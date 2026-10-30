//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The reinstall of the packages dpkg left needing one (handoff N-36,
// S7-7; PRIVILEGED §6, "What the recovery leaves"), in the broad unit:
// half-installed or flagged reinstreq, which configuring does not finish
// and dpkg refuses to remove. priv_pkg_reinstall_preview simulates
// apt-get install --reinstall with every requested name pinned to the
// version dpkg's status names, and hashes the transaction with the
// unfinished state and the privileged policy; priv_pkg_reinstall takes
// the package operation record, waits for the dpkg lock, reads the state
// again, simulates the same argv and refuses any change, runs it through
// the install's stop points (an early answer, SIGINT to apt-get alone at
// the stop point, the process group killed at limits.max_timeout_s), and
// decides its result from dpkg's state alone. It runs only while the
// requested names are exactly the unfinished packages and dpkg's journal
// is empty: apt refuses to run with entries in it, and configures every
// other unfinished package in the same run (both measured).

type reinstallPreviewData struct {
	Op              string         `json:"op"`
	Packages        []string       `json:"packages"`
	Reinstall       []recoverEntry `json:"reinstall"`
	Argv            []string       `json:"argv"`
	ExitCode        *int           `json:"exit_code"`
	Signal          *string        `json:"signal"`
	Stderr          string         `json:"stderr"`
	StderrTruncated bool           `json:"stderr_truncated"`
	DurationMS      int64          `json:"duration_ms"`
	PolicySHA256    string         `json:"policy_sha256"`
	PreviewSHA256   string         `json:"preview_sha256"`
}

type reinstallData struct {
	Op              string              `json:"op"`
	Packages        []string            `json:"packages"`
	Reinstalled     []recoverConfigured `json:"reinstalled"`
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

// reinstallPins checks the state for a reinstall of names and returns
// each name pinned to the version dpkg's status names: the journal empty,
// every unfinished package one that needs a reinstall, and the names
// exactly them. Anything else is refused, naming what each package needs.
func reinstallPins(st *pkg.State, names []string) ([]pkg.Version, error) {
	u := st.UnfinishedPackages()
	if len(u) == 0 && len(st.Journal) == 0 {
		return nil, errf(protocol.CodeExecFailed, "nothing needs a reinstall: dpkg left nothing unfinished; nothing was requested")
	}
	if len(st.Journal) > 0 {
		return nil, unfinishedErr(*st, "nothing was changed")
	}
	var re []string
	for _, p := range u {
		if p.Recovery != pkg.RecoverReinstall {
			return nil, errf(protocol.CodeExecFailed, "dpkg was interrupted and left %s; a reinstall runs only while every unfinished package is one it reinstalls, "+
				"since apt-get would also configure the others in the same run: finish or remove them first; nothing was changed", describeUnfinished(u, 0))
		}
		re = append(re, p.Name)
	}
	req := slices.Clone(names)
	slices.Sort(req)
	if !slices.Equal(req, re) {
		return nil, errf(protocol.CodeExecFailed, "dpkg was interrupted and left %s; a reinstall must name exactly the packages that need one (%s); nothing was changed",
			describeUnfinished(u, 0), firstNames(re))
	}
	pins := make([]pkg.Version, 0, len(names))
	for _, n := range names {
		pins = append(pins, pkg.Version{Name: n, Version: st.Packages[n].Version})
	}
	return pins, nil
}

// reinstallSim simulates the pinned reinstall and checks that its
// transaction is exactly the reinstall; it returns the argv, the
// simulation and the preview's hash.
func (s *server) reinstallSim(st *pkg.State, names []string, pins []pkg.Version, deadline time.Time) (argv []string, sim *simulation, hash string, err error) {
	argv, err = pkg.ReinstallArgs(true, pins)
	if err != nil {
		return nil, nil, "", errf(protocol.CodeExecFailed, "the reinstall cannot be pinned to the versions dpkg's status names (%s); nothing was requested", err.Error())
	}
	sim, err = s.simulate(argv, deadline)
	if err != nil {
		return nil, nil, "", err
	}
	if rerr := pkg.IsReinstall(sim.tx, pins); rerr != nil {
		return nil, nil, "", errf(protocol.CodePolicyDenied, "this reinstall would change more than the packages it reinstalls (%s); a reinstall never installs, upgrades or removes anything else; nothing was requested",
			txSummary(sim.tx))
	}
	return argv, sim, pkg.ReinstallPreviewHash(s.p.SHA256, names, sim.tx, argv, st.UnfinishedPackages(), st.Journal), nil
}

// pkgReinstallPreview is priv_pkg_reinstall_preview.
func (s *server) pkgReinstallPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	names, _, err := pkgNames(raw, pkg.OpReinstall, false)
	if err != nil {
		return nil, nil, err
	}
	if aerr := s.pkgAllowed(pkg.OpReinstall, names); aerr != nil {
		return nil, nil, aerr
	}
	if perr := s.notInProgress(); perr != nil {
		return nil, nil, perr
	}
	if lerr := s.lockFree(); lerr != nil {
		return nil, nil, lerr
	}
	st, err := s.readState()
	if err != nil {
		return nil, nil, err
	}
	pins, err := reinstallPins(&st, names)
	if err != nil {
		return nil, nil, err
	}
	argv, sim, hash, err := s.reinstallSim(&st, names, pins, s.start.Add(s.timeout()))
	if err != nil {
		return nil, nil, err
	}
	stderr, cut := s.red.Truncate(sim.res.Stderr, s.p.Limits.MaxOutputBytes)
	return reinstallPreviewData{Op: string(pkg.OpReinstall), Packages: names, Reinstall: unfinishedEntries(st.UnfinishedPackages()), Argv: argv,
		ExitCode: sim.res.ExitCode, Stderr: string(stderr), StderrTruncated: sim.res.StderrTruncated || cut, DurationMS: sim.res.Duration.Milliseconds(),
		PolicySHA256: s.p.SHA256, PreviewSHA256: hash}, nil, nil
}

// pkgReinstall is priv_pkg_reinstall.
func (s *server) pkgReinstall(raw jsontext.Value) (data any, warns []string, failure error) {
	names, want, err := pkgNames(raw, pkg.OpReinstall, true)
	if err != nil {
		return nil, nil, err
	}
	if aerr := s.pkgAllowed(pkg.OpReinstall, names); aerr != nil {
		return nil, nil, aerr
	}
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
	pins, err := reinstallPins(&before, names)
	if err != nil {
		return nil, nil, err
	}
	_, _, hash, err := s.reinstallSim(&before, names, pins, st.deadline)
	if err != nil {
		return nil, nil, err
	}
	if hash != want {
		return nil, nil, errf(protocol.CodeExists, "the reinstall differs from its preview (the packages dpkg left unfinished, the version the package index offers, "+
			"or the privileged policy changed); nothing was run; preview again")
	}
	if pkgHook != nil {
		pkgHook(s, "before-run")
	}
	argv, _ := pkg.ReinstallArgs(false, pins)
	res, attempts, err := s.runLocked(s.o.AptGet, argv, st, lockBudget, true)
	if err != nil {
		return nil, nil, err
	}
	after, err := pkg.ReadState(s.o.DpkgDir)
	if err != nil {
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "apt-get ran, but dpkg's state could not be read afterwards (%s); check the host", err.Error())
	}
	r := pkg.Settle(before.Status, after.Status)
	s.recordApplied(r.Other)
	for _, c := range r.Configured {
		if len(s.reinstalled) < maxAuditChanged {
			s.reinstalled = append(s.reinstalled, auditText(c.Name))
		}
	}
	for _, p := range r.Still {
		if len(s.unfinished) < maxAuditChanged {
			s.unfinished = append(s.unfinished, p.Name)
		}
	}
	if s.reapErr != "" {
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "the helper could not confirm that every process apt-get started has ended (see its journal on the host); reinstalled so far %s",
			configuredSummary(r.Configured))
	}
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	how := ""
	switch stopped {
	case "sigint":
		how = "apt-get was asked to stop at the helper's limit and stopped at a safe point; "
	case "killed":
		how = "apt-get was killed at the helper's limit; "
	}
	switch {
	case before.Same(after):
		code := "none"
		if res.ExitCode != nil {
			code = fmt.Sprint(*res.ExitCode)
		}
		return nil, nil, errf(protocol.CodeExecFailed, "%sapt-get changed nothing (exit code %s)%s; still %s; nothing was changed", how, code, aptErrors(res.Stderr, s),
			describeUnfinished(r.Still, len(after.Journal)))
	case len(r.Still) > 0 || len(after.Journal) > 0 || !r.Other.Empty() || len(r.Configured) != len(pins):
		other := ""
		if !r.Other.Empty() {
			other = "; other changes, which a reinstall never makes: " + txSummary(r.Other)
		}
		return nil, nil, errf(protocol.CodeVerifyFailed, "%sthe reinstall did not finish: reinstalled %s; still %s%s; it cannot be undone; preview again",
			how, configuredSummary(r.Configured), describeUnfinished(r.Still, len(after.Journal)), other)
	}
	d, w := s.pkgResult(pkg.OpReinstall, names, &res, attempts, waited)
	out := reinstallData{Op: string(pkg.OpReinstall), Packages: names, Reinstalled: []recoverConfigured{}, ExitCode: d.ExitCode, Signal: d.Signal, TimedOut: d.TimedOut,
		Stdout: d.Stdout, Stderr: d.Stderr, StdoutTruncated: d.StdoutTruncated, StderrTruncated: d.StderrTruncated, Attempts: d.Attempts,
		LockWaitMS: d.LockWaitMS, DurationMS: d.DurationMS}
	for _, c := range r.Configured {
		out.Reinstalled = append(out.Reinstalled, recoverConfigured{Name: c.Name, Version: c.Version, FromState: c.From})
	}
	if stopped != "" {
		w = append(w, "apt-get was stopped at the helper's limit after every package had been reinstalled")
	}
	return out, w, nil
}
