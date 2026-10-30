//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The recovery of a database dpkg left unfinished (handoff N-14, S7-4;
// PRIVILEGED §6, "Recovering an unfinished database"), in the broad unit:
// priv_pkg_recover_preview reports the unfinished packages from dpkg's
// state (the status file with its journal folded in) and hashes them with
// the privileged policy; priv_pkg_recover takes the package operation
// record, waits for the dpkg lock as the other package operations do,
// reads the state again and refuses any change from the preview, runs
// dpkg --force-confold --configure --pending with the package environment
// through the stop points (an early answer at a hang-up or the deadline,
// no SIGINT, the process group killed only at limits.max_timeout_s), and
// decides its result from dpkg's state alone.

type recoverEntry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	State          string   `json:"state"`
	Flag           string   `json:"flag"`
	MissingDepends []string `json:"missing_depends"`
}

type recoverPreviewData struct {
	Op string `json:"op"`
	// Unfinished are the packages a recovery configures (with any
	// dependency no package provides), NeedsReinstall those it leaves.
	Unfinished     []recoverEntry `json:"unfinished"`
	NeedsReinstall []recoverEntry `json:"needs_reinstall"`
	JournalEntries int            `json:"journal_entries"`
	Argv           []string       `json:"argv"`
	PolicySHA256   string         `json:"policy_sha256"`
	PreviewSHA256  string         `json:"preview_sha256"`
}

type recoverConfigured struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	FromState string `json:"from_state"`
}

type recoverData struct {
	Op string `json:"op"`
	// Ran is false when there was nothing to recover.
	Ran             bool                `json:"ran"`
	Configured      []recoverConfigured `json:"configured"`
	ExitCode        *int                `json:"exit_code"`
	Signal          *string             `json:"signal"`
	TimedOut        bool                `json:"timed_out"`
	Stdout          string              `json:"stdout"`
	Stderr          string              `json:"stderr"`
	StdoutTruncated bool                `json:"stdout_truncated"`
	StderrTruncated bool                `json:"stderr_truncated"`
	Attempts        int                 `json:"attempts"`
	LockWaitMS      int64               `json:"lock_wait_ms"`
	DurationMS      int64               `json:"duration_ms"`
}

// recoverable splits the unfinished packages: what a recovery configures
// (RecoverConfigure, and RecoverDependency, which dpkg tries and leaves),
// and what it cannot touch (RecoverReinstall).
func recoverable(u []pkg.UnfinishedPackage) (configure, reinstall []recoverEntry) {
	configure, reinstall = []recoverEntry{}, []recoverEntry{}
	for _, p := range u {
		e := recoverEntry{Name: p.Name, Version: p.Version, State: p.State, Flag: p.Flag, MissingDepends: []string{}}
		e.MissingDepends = append(e.MissingDepends, p.Missing...)
		if p.Recovery == pkg.RecoverReinstall {
			reinstall = append(reinstall, e)
		} else {
			configure = append(configure, e)
		}
	}
	return configure, reinstall
}

// nothingToConfigure refuses a state where configuring would change
// nothing, with no journal to fold in: only packages that need a
// reinstall (configuring leaves them, measured in S7-4) or whose
// dependency nothing provides (dpkg exits 1 and leaves them, measured in
// S7-7, F1), and none to configure.
func nothingToConfigure(st *pkg.State, u []pkg.UnfinishedPackage) error {
	if len(u) == 0 || len(st.Journal) > 0 || slices.ContainsFunc(u, func(p pkg.UnfinishedPackage) bool { return p.Recovery == pkg.RecoverConfigure }) {
		return nil
	}
	return errf(protocol.CodeExecFailed, "dpkg left only %s, so a recovery would change nothing; nothing was requested", describeUnfinished(u, 0))
}

func (s *server) readState() (pkg.State, error) {
	st, err := pkg.ReadState(s.o.DpkgDir)
	if err != nil {
		return pkg.State{}, stateErr(err, "nothing was changed")
	}
	return st, nil
}

// pkgRecoverPreview is priv_pkg_recover_preview.
func (s *server) pkgRecoverPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	if err := decode(raw, &noArgs{}); err != nil {
		return nil, nil, err
	}
	if err := s.pkgAllowed(pkg.OpRecover, nil); err != nil {
		return nil, nil, err
	}
	if err := s.notInProgress(); err != nil {
		return nil, nil, err
	}
	if err := s.lockFree(); err != nil {
		return nil, nil, err
	}
	st, err := s.readState()
	if err != nil {
		return nil, nil, err
	}
	u := st.UnfinishedPackages()
	configure, reinstall := recoverable(u)
	if rerr := nothingToConfigure(&st, u); rerr != nil {
		return nil, nil, rerr
	}
	argv := pkg.RecoverArgs()
	return recoverPreviewData{Op: string(pkg.OpRecover), Unfinished: configure, NeedsReinstall: reinstall, JournalEntries: len(st.Journal), Argv: argv,
		PolicySHA256: s.p.SHA256, PreviewSHA256: pkg.RecoverPreviewHash(s.p.SHA256, argv, u, st.Journal)}, nil, nil
}

// pkgRecover is priv_pkg_recover.
func (s *server) pkgRecover(raw jsontext.Value) (data any, warns []string, failure error) {
	var a boundArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	switch w := a.ExpectedPreviewSHA256; {
	case w == nil:
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 is required: the preview_sha256 that priv_pkg_recover_preview returned")
	case !fsx.ValidPreviewSHA256(*w):
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that priv_pkg_recover_preview returned")
	}
	if err := s.pkgAllowed(pkg.OpRecover, nil); err != nil {
		return nil, nil, err
	}
	s.program = "dpkg"
	st := s.stages()
	rec, err := s.holdRecord(st.killAt)
	if err != nil {
		return nil, nil, err
	}
	defer rec.release()
	lockBudget := time.Now().Add(min(maxLockWait, s.timeout()/2))
	waited, err := s.waitLock(lockBudget, st.deadline)
	if err != nil {
		return nil, nil, err
	}
	before, err := s.readState()
	if err != nil {
		return nil, nil, err
	}
	u := before.UnfinishedPackages()
	if rerr := nothingToConfigure(&before, u); rerr != nil {
		return nil, nil, rerr
	}
	argv := pkg.RecoverArgs()
	if pkg.RecoverPreviewHash(s.p.SHA256, argv, u, before.Journal) != *a.ExpectedPreviewSHA256 {
		return nil, nil, errf(protocol.CodeExists, "dpkg's unfinished packages or its journal changed since the preview (or the privileged policy did); nothing was run; preview again")
	}
	if len(u) == 0 && len(before.Journal) == 0 {
		return recoverData{Op: string(pkg.OpRecover), Configured: []recoverConfigured{}, LockWaitMS: waited.Milliseconds()}, nil, nil
	}
	res, attempts, err := s.runLocked(s.o.Dpkg, argv, st, lockBudget, false)
	if err != nil {
		return nil, nil, err
	}
	after, err := pkg.ReadState(s.o.DpkgDir)
	if err != nil {
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "dpkg ran, but its state could not be read afterwards (%s); check the host", err.Error())
	}
	r := pkg.Settle(before.Status, after.Status)
	s.recordApplied(r.Other)
	for _, c := range r.Configured {
		if len(s.configured) < maxAuditChanged {
			s.configured = append(s.configured, auditText(c.Name))
		}
	}
	for _, p := range r.Still {
		if len(s.unfinished) < maxAuditChanged {
			s.unfinished = append(s.unfinished, p.Name)
		}
	}
	if s.reapErr != "" {
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "the helper could not confirm that every process dpkg started has ended (see its journal on the host); configured so far %s",
			configuredSummary(r.Configured))
	}
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	how := ""
	if stopped == "killed" {
		how = "dpkg was killed at the helper's limit; "
	}
	switch {
	case before.Same(after):
		code := "none"
		if res.ExitCode != nil {
			code = fmt.Sprint(*res.ExitCode)
		}
		return nil, nil, errf(protocol.CodeExecFailed, "%sdpkg changed nothing (exit code %s)%s; still %s; nothing was changed", how, code, dpkgErrors(res.Stderr, s),
			describeUnfinished(r.Still, len(after.Journal)))
	case len(r.Still) > 0 || len(after.Journal) > 0 || !r.Other.Empty():
		other := ""
		if !r.Other.Empty() {
			other = "; other changes, which a recovery never makes: " + txSummary(r.Other)
		}
		return nil, nil, errf(protocol.CodeVerifyFailed, "%sthe recovery did not finish: configured %s; still %s%s; it cannot be undone; preview again",
			how, configuredSummary(r.Configured), describeUnfinished(r.Still, len(after.Journal)), other)
	}
	d, w := s.pkgResult(pkg.OpRecover, nil, &res, attempts, waited)
	out := recoverData{Op: string(pkg.OpRecover), Ran: true, Configured: []recoverConfigured{}, ExitCode: d.ExitCode, Signal: d.Signal, TimedOut: d.TimedOut,
		Stdout: d.Stdout, Stderr: d.Stderr, StdoutTruncated: d.StdoutTruncated, StderrTruncated: d.StderrTruncated, Attempts: d.Attempts,
		LockWaitMS: d.LockWaitMS, DurationMS: d.DurationMS}
	for _, c := range r.Configured {
		out.Configured = append(out.Configured, recoverConfigured{Name: c.Name, Version: c.Version, FromState: c.From})
	}
	if stopped != "" {
		w = append(w, "dpkg was stopped at the helper's limit after every package had been configured")
	}
	return out, w, nil
}

// configuredSummary is a recovery's configured packages in a message.
func configuredSummary(c []pkg.Configured) string {
	if len(c) == 0 {
		return "none"
	}
	l := make([]string, 0, len(c))
	for _, p := range c {
		l = append(l, p.Name+" "+p.Version)
	}
	return fmt.Sprintf("%d (%s)", len(c), firstNames(l))
}

// dpkgErrors quotes at most five of dpkg's "dpkg: " error lines (each at
// most 200 bytes, redacted) for a message; never into the journal.
func dpkgErrors(stderr []byte, s *server) string {
	var lines []string
	for _, l := range strings.Split(string(stderr), "\n") {
		if strings.HasPrefix(l, "dpkg: ") && len(lines) < 5 {
			b, _ := s.red.Truncate([]byte(l), 200)
			lines = append(lines, strings.ToValidUTF8(string(b), "?"))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "; dpkg said: " + strings.Join(lines, " | ")
}
