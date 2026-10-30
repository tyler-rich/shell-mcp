//go:build linux

package ops

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The package operations (PRIVILEGED §6, "Package operations"; handoff D5,
// S4c-7), run by the broad unit's instance only: priv_pkg_update_index,
// priv_pkg_install, priv_pkg_upgrade, priv_pkg_remove, and their read-tier
// previews. A preview simulates the transaction (apt-get -s) and hashes it
// with the privileged policy; the operation simulates it again, then the
// exact pinned argv it runs, refuses anything but the approved transaction,
// runs it, and decides its result from dpkg's status alone.
//
// Install, upgrade and remove are the one exception to "stopped when the
// gate goes away" (the maintainer's decision, 2026-10-21): killing apt-get
// or dpkg part-way leaves dpkg's database unfinished, so at a hang-up or
// the request's deadline the helper answers outcome_unknown at once and lets
// apt-get go on, sends SIGINT to apt-get alone at the stop point, and kills
// its process group only at limits.max_timeout_s.

// Production paths of the package operations.
const (
	// DefaultDpkgDir is dpkg's administrative directory.
	DefaultDpkgDir = "/var/lib/dpkg"
	// DefaultPkgRecord is the package operation record (PRIVILEGED §6).
	DefaultPkgRecord = "/run/shell-mcp-privd-pkg"
)

// maxLockWait bounds the wait for a held dpkg or lists lock; it is also at
// most half of the request's timeout.
const maxLockWait = 60 * time.Second

// maxStopAllowance bounds the stop allowance: SIGINT goes to apt-get this
// long (at most a quarter of limits.max_timeout_s) before the limit, so
// that the dpkg run in progress can finish (PRIVILEGED §6).
const maxStopAllowance = 60 * time.Second

// pkgHook, set only in the e2e test build (bypass_e2e.go), runs at the
// named stages of an install, upgrade or remove; nil in a release build.
var pkgHook func(s *server, stage string)

type pkgArgs struct {
	Packages []string `json:"packages"`
}

type noArgs struct{}

type pkgBoundArgs struct {
	Packages              []string `json:"packages"`
	ExpectedPreviewSHA256 *string  `json:"expected_preview_sha256"`
}

type boundArgs struct {
	ExpectedPreviewSHA256 *string `json:"expected_preview_sha256"`
}

type pkgVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type pkgUpgrade struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

type pkgRemoval struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purge   bool   `json:"purge"`
}

// appliedData is a transaction on the wire: a preview's lists, and the
// results' applied (handoff P-6).
type appliedData struct {
	Install []pkgVersion `json:"install"`
	Upgrade []pkgUpgrade `json:"upgrade"`
	Remove  []pkgRemoval `json:"remove"`
}

func wireTx(t pkg.Transaction) appliedData {
	d := appliedData{Install: []pkgVersion{}, Upgrade: []pkgUpgrade{}, Remove: []pkgRemoval{}}
	for _, v := range t.Install {
		d.Install = append(d.Install, pkgVersion{Name: v.Name, Version: v.Version})
	}
	for _, u := range t.Upgrade {
		d.Upgrade = append(d.Upgrade, pkgUpgrade{Name: u.Name, From: u.From, To: u.To})
	}
	for _, r := range t.Remove {
		d.Remove = append(d.Remove, pkgRemoval{Name: r.Name, Version: r.Version, Purge: r.Purge})
	}
	return d
}

type pkgData struct {
	Op       string   `json:"op"`
	Packages []string `json:"packages"`
	// Applied is what dpkg's status shows the operation changed (install,
	// upgrade, remove; not the index update).
	Applied         *appliedData `json:"applied,omitempty"`
	ExitCode        *int         `json:"exit_code"`
	Signal          *string      `json:"signal"`
	TimedOut        bool         `json:"timed_out"`
	Stdout          string       `json:"stdout"`
	Stderr          string       `json:"stderr"`
	StdoutTruncated bool         `json:"stdout_truncated"`
	StderrTruncated bool         `json:"stderr_truncated"`
	Attempts        int          `json:"attempts"`
	LockWaitMS      int64        `json:"lock_wait_ms"`
	DurationMS      int64        `json:"duration_ms"`
}

type previewData struct {
	Op       string       `json:"op"`
	Packages []string     `json:"packages"`
	Install  []pkgVersion `json:"install"`
	Upgrade  []pkgUpgrade `json:"upgrade"`
	Remove   []pkgRemoval `json:"remove"`
	// Unfinished are the packages dpkg left unfinished, each with its
	// version and state, for a removal of exactly them (handoff N-36);
	// empty for a clean database, which every other preview requires.
	Unfinished []recoverEntry `json:"unfinished"`
	// Complete is always true: an incomplete simulation is refused, so no
	// approval is requested for it (handoff D5 §1).
	Complete        bool     `json:"complete"`
	Argv            []string `json:"argv"`
	ExitCode        *int     `json:"exit_code"`
	Signal          *string  `json:"signal"`
	Stderr          string   `json:"stderr"`
	StderrTruncated bool     `json:"stderr_truncated"`
	DurationMS      int64    `json:"duration_ms"`
	PolicySHA256    string   `json:"policy_sha256"`
	PreviewSHA256   string   `json:"preview_sha256"`
}

type updatePreviewData struct {
	Argv          []string `json:"argv"`
	PolicySHA256  string   `json:"policy_sha256"`
	PreviewSHA256 string   `json:"preview_sha256"`
}

func (s *server) pkgUpdateIndex(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgUpdate(raw)
}

func (s *server) pkgUpdateIndexPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	if err := decode(raw, &noArgs{}); err != nil {
		return nil, nil, err
	}
	if err := s.pkgAllowed(pkg.OpUpdate, nil); err != nil {
		return nil, nil, err
	}
	argv, _ := pkg.Args(pkg.OpUpdate, false, nil)
	return updatePreviewData{Argv: argv, PolicySHA256: s.p.SHA256, PreviewSHA256: pkg.UpdatePreviewHash(s.p.SHA256, argv)}, nil, nil
}

func (s *server) pkgInstall(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgChange(raw, pkg.OpInstall)
}

func (s *server) pkgInstallPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgPreview(raw, pkg.OpInstall)
}

func (s *server) pkgUpgrade(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgChange(raw, pkg.OpUpgrade)
}

func (s *server) pkgUpgradePreview(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgPreview(raw, pkg.OpUpgrade)
}

func (s *server) pkgRemove(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgChange(raw, pkg.OpRemove)
}

func (s *server) pkgRemovePreview(raw jsontext.Value) (data any, warns []string, failure error) {
	return s.pkgPreview(raw, pkg.OpRemove)
}

// pkgNames decodes a request's names: install and remove take packages (the
// Debian name grammar, at most MaxNames, checked by pkg.Args), upgrade and
// the index update none. bound decodes expected_preview_sha256 too, which
// is then required and well formed.
func pkgNames(raw jsontext.Value, op pkg.Op, bound bool) (names []string, want string, err error) {
	var a pkgBoundArgs
	takesNames := op == pkg.OpInstall || op == pkg.OpRemove || op == pkg.OpReinstall
	switch {
	case takesNames && bound:
		err = decode(raw, &a)
	case takesNames:
		var p pkgArgs
		err = decode(raw, &p)
		a.Packages = p.Packages
	case bound:
		var b boundArgs
		err = decode(raw, &b)
		a.ExpectedPreviewSHA256 = b.ExpectedPreviewSHA256
	default:
		err = decode(raw, &noArgs{})
	}
	if err != nil {
		return nil, "", err
	}
	if takesNames && a.Packages == nil {
		return nil, "", errf(protocol.CodeBadRequest, "packages is required")
	}
	check := func() error { _, e := pkg.Args(op, false, a.Packages); return e }
	if op == pkg.OpReinstall {
		check = func() error { return pkg.CheckNames(op, a.Packages) }
	}
	if aerr := check(); aerr != nil {
		return nil, "", errf(protocol.CodeBadRequest, "packages: %s", aerr.Error())
	}
	if bound {
		switch w := a.ExpectedPreviewSHA256; {
		case w == nil:
			return nil, "", errf(protocol.CodeBadRequest, "expected_preview_sha256 is required: the preview_sha256 that priv_pkg_%s_preview returned for the same arguments", opName(op))
		case !fsx.ValidPreviewSHA256(*w):
			return nil, "", errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that priv_pkg_%s_preview returned", opName(op))
		default:
			want = *w
		}
	}
	if a.Packages == nil {
		a.Packages = []string{}
	}
	return a.Packages, want, nil
}

func opName(op pkg.Op) string {
	if op == pkg.OpUpdate {
		return "update_index"
	}
	return string(op)
}

// pkgAllowed checks the request against the packages section.
func (s *server) pkgAllowed(op pkg.Op, names []string) error {
	pp := &s.p.Packages
	if !pp.Enabled {
		return errf(protocol.CodePolicyDenied, "package operations are not enabled in the privileged policy")
	}
	switch op {
	case pkg.OpUpdate:
		if !pp.AllowUpdateIndex {
			return errf(protocol.CodePolicyDenied, "packages.allow_update_index is not set")
		}
	case pkg.OpUpgrade:
		if !pp.AllowUpgrade {
			return errf(protocol.CodePolicyDenied, "packages.allow_upgrade is not set")
		}
	case pkg.OpRecover:
		if !pp.AllowRecover {
			return errf(protocol.CodePolicyDenied, "packages.allow_recover is not set")
		}
	case pkg.OpInstall, pkg.OpRemove, pkg.OpReinstall:
		// A reinstall installs an archive again: packages.install.
		allowed, list := pp.Install, "packages.install"
		if op == pkg.OpRemove {
			allowed, list = pp.Remove, "packages.remove"
		}
		for _, n := range names {
			if !slices.Contains(allowed, n) {
				return errf(protocol.CodePolicyDenied, "package %s is not in %s", n, list)
			}
		}
	}
	return nil
}

func (s *server) aptEnv() []string { return pkg.Env(execHome) }

// pkgUpdate is priv_pkg_update_index: bound to its preview (the argv and
// the policy), run with the lock wait, and stopped like a command when the
// gate goes away (apt-get update never touches dpkg's database).
func (s *server) pkgUpdate(raw jsontext.Value) (data any, warns []string, failure error) {
	_, want, err := pkgNames(raw, pkg.OpUpdate, true)
	if err != nil {
		return nil, nil, err
	}
	if aerr := s.pkgAllowed(pkg.OpUpdate, nil); aerr != nil {
		return nil, nil, aerr
	}
	argv, _ := pkg.Args(pkg.OpUpdate, false, nil)
	if pkg.UpdatePreviewHash(s.p.SHA256, argv) != want {
		return nil, nil, errf(protocol.CodeExists, "the index update differs from its preview (the privileged policy changed); nothing was run")
	}
	timeout := s.timeout()
	r := pkg.Runner{
		AptGet: s.o.AptGet, Trampoline: s.o.Executable, Env: s.aptEnv(), MaxOutput: s.p.Limits.MaxOutputBytes,
		MaxMemoryMB: s.p.Limits.MaxMemoryMB, LockWait: min(maxLockWait, timeout/2), Retry: s.o.PkgLockRetry,
		Exec: func(_ context.Context, sp *execx.Spec) (execx.Result, error) { return s.runCommand(sp, true) },
	}
	res, err := r.Run(context.Background(), timeout, argv)
	if errors.Is(err, pkg.ErrLockHeld) {
		return nil, nil, errf(protocol.CodeExecFailed, "the package lists are locked by %s (waited %d s); nothing was changed; try again later",
			holderOf(res.Stderr), res.LockWait.Milliseconds()/1000)
	}
	if err != nil {
		return nil, nil, err
	}
	d, w := s.pkgResult(pkg.OpUpdate, []string{}, &res.Result, res.Attempts, res.LockWait)
	return d, w, nil
}

// holderOf names the lock holder apt reported, or "another process".
func holderOf(stderr []byte) string {
	if h, ok := pkg.HolderFromStderr(stderr); ok {
		return h.String()
	}
	return "another process"
}

// pkgResult shapes apt-get's last run as the result.
func (s *server) pkgResult(op pkg.Op, names []string, res *execx.Result, attempts int, lockWait time.Duration) (out pkgData, warns []string) {
	maxOut := s.p.Limits.MaxOutputBytes
	stdout, cutOut := s.red.Truncate(res.Stdout, maxOut)
	stderr, cutErr := s.red.Truncate(res.Stderr, maxOut)
	d := pkgData{
		Op: string(op), Packages: names, ExitCode: res.ExitCode, TimedOut: res.TimedOut,
		Stdout: string(stdout), Stderr: string(stderr),
		StdoutTruncated: res.StdoutTruncated || cutOut, StderrTruncated: res.StderrTruncated || cutErr,
		Attempts: attempts, LockWaitMS: lockWait.Milliseconds(), DurationMS: res.Duration.Milliseconds(),
	}
	if res.Signal != "" {
		sig := res.Signal
		d.Signal = &sig
	}
	var warnings []string
	if res.OutputCeilingHit {
		warnings = append(warnings, "output exceeded the hard ceiling; the process group was killed")
	}
	return d, warnings
}

// simulation is one apt-get -s run, parsed.
type simulation struct {
	argv []string
	res  execx.Result
	tx   pkg.Transaction
}

// simulate runs argv (a simulation) for at most the request's remaining
// time; a hang-up stops it, and nothing is changed either way. An
// incomplete simulation (a failure, its output cut, a line that did not
// parse, a timeout) is exec_failed.
func (s *server) simulate(argv []string, deadline time.Time) (*simulation, error) {
	left := time.Until(deadline)
	if left <= 0 {
		return nil, errf(protocol.CodeTimeout, "the request's time ran out before apt-get changed anything; nothing was changed")
	}
	res, err := s.runCommand(&execx.Spec{Trampoline: s.o.Executable, Path: s.o.AptGet, Args: argv, Env: s.aptEnv(), Dir: "/", Timeout: left,
		MaxOutput: s.p.Limits.MaxOutputBytes, MaxMemoryMB: s.p.Limits.MaxMemoryMB}, false)
	if s.hungUp {
		return nil, errf(protocol.CodeTimeout, "the gate stopped waiting before apt-get changed anything; nothing was changed")
	}
	if err != nil {
		return nil, err
	}
	sim := pkg.ParseSimulation(res.Stdout)
	if res.ExitCode == nil || *res.ExitCode != 0 || res.StdoutTruncated || res.TimedOut || sim.Unparsed > 0 {
		code := "none"
		if res.ExitCode != nil {
			code = fmt.Sprint(*res.ExitCode)
		}
		return nil, errf(protocol.CodeExecFailed, "the simulation was incomplete (exit code %s, %d line(s) not understood%s); nothing was requested",
			code, sim.Unparsed, aptErrors(res.Stderr, s))
	}
	return &simulation{argv: argv, res: res, tx: sim.Transaction()}, nil
}

// aptErrors quotes at most five of apt's "E:" lines (each at most 200
// bytes, redacted) for a message; never into the journal.
func aptErrors(stderr []byte, s *server) string {
	var lines []string
	for _, l := range strings.Split(string(stderr), "\n") {
		if strings.HasPrefix(l, "E: ") && len(lines) < 5 {
			b, _ := s.red.Truncate([]byte(l), 200)
			lines = append(lines, strings.ToValidUTF8(string(b), "?"))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "; apt-get said: " + strings.Join(lines, " | ")
}

// pkgState is the check a preview and its operation share on dpkg's
// state, before anything is simulated: nothing dpkg left unfinished, or,
// for a removal, the unfinished mode (removalMode). It returns the state
// and whether the request is a removal in the unfinished mode.
func pkgState(st *pkg.State, op pkg.Op, names []string) (unfinished bool, err error) {
	if len(st.UnfinishedPackages()) == 0 && len(st.Journal) == 0 {
		return false, nil
	}
	if op != pkg.OpRemove {
		return false, unfinishedErr(*st, "nothing was changed")
	}
	return true, removalMode(st, names)
}

// removalMode is the unfinished mode of a removal (handoff N-36, S7-7):
// with dpkg's journal empty (apt refuses to run otherwise, measured), the
// request must name exactly the unfinished packages that do not need a
// reinstall. Those that need one are left as they are: dpkg refuses to
// remove them, and apt leaves them alone (M1, measured). Anything else is
// refused before anything runs, naming what each package needs.
func removalMode(st *pkg.State, names []string) error {
	u := st.UnfinishedPackages()
	if len(st.Journal) > 0 {
		return unfinishedErr(*st, "nothing was changed")
	}
	set := removable(u)
	req := slices.Clone(names)
	slices.Sort(req)
	if slices.Equal(req, set) {
		return nil
	}
	which := "none: every unfinished package needs a reinstall"
	if len(set) > 0 {
		which = firstNames(set)
	}
	return errf(protocol.CodeExecFailed, "dpkg was interrupted and left %s; in this state a removal must name exactly the unfinished packages that do not need a reinstall (%s); nothing was changed",
		describeUnfinished(u, 0), which)
}

// removable are the unfinished packages a removal in the unfinished mode
// removes: every one that does not need a reinstall, sorted.
func removable(u []pkg.UnfinishedPackage) []string {
	out := []string{}
	for _, p := range u {
		if p.Recovery != pkg.RecoverReinstall {
			out = append(out, p.Name)
		}
	}
	slices.Sort(out)
	return out
}

// removesExactly checks a removal's transaction in the unfinished mode:
// it removes exactly the unfinished packages named, each at the version
// dpkg's state names, and installs or changes nothing.
func removesExactly(st *pkg.State, tx pkg.Transaction) error {
	want := []pkg.Removal{}
	for _, p := range st.UnfinishedPackages() {
		if p.Recovery != pkg.RecoverReinstall {
			want = append(want, pkg.Removal{Name: p.Name, Version: p.Version})
		}
	}
	got := tx.Remove
	if got == nil {
		got = []pkg.Removal{}
	}
	if len(tx.Install)+len(tx.Upgrade) == 0 && slices.Equal(got, want) {
		return nil
	}
	return errf(protocol.CodeExecFailed, "the removal would change more than the unfinished packages (%s); in this state a removal removes exactly them; nothing was requested",
		txSummary(tx))
}

// unfinishedEntries are the unfinished packages on the wire: each with
// its version, state, flag and missing dependencies.
func unfinishedEntries(u []pkg.UnfinishedPackage) []recoverEntry {
	out := []recoverEntry{}
	for _, p := range u {
		out = append(out, recoverEntry{Name: p.Name, Version: p.Version, State: p.State, Flag: p.Flag, MissingDepends: append([]string{}, p.Missing...)})
	}
	return out
}

// stateErr refuses when dpkg's state could not be read: as an interrupted
// dpkg when its journal holds an entry that could not be read.
func stateErr(err error, tail string) error {
	if errors.Is(err, pkg.ErrJournal) {
		return errf(protocol.CodeExecFailed, "dpkg was interrupted and left an entry in its journal /var/lib/dpkg/updates that could not be read (%s), "+
			"which dpkg --configure -a folds in; %s", err.Error(), tail)
	}
	return errf(protocol.CodeExecFailed, "dpkg's state could not be read (%s); %s", err.Error(), tail)
}

// unfinishedErr refuses a database dpkg left part-way, naming what each
// unfinished package needs (S7-4): configuring, a missing dependency, or
// a reinstall, and dpkg's journal; nil when there is nothing.
func unfinishedErr(st pkg.State, tail string) error {
	u := st.UnfinishedPackages()
	if len(u) == 0 && len(st.Journal) == 0 {
		return nil
	}
	return errf(protocol.CodeExecFailed, "dpkg was interrupted and left %s; %s", describeUnfinished(u, len(st.Journal)), tail)
}

// describeUnfinished says what unfinished packages need, by recovery, and
// what dpkg's journal holds: for a refusal, and for a recovery's result.
func describeUnfinished(u []pkg.UnfinishedPackage, journal int) string {
	var conf, dep, re []string
	for _, p := range u {
		n := p.Name + " (" + p.State + ")"
		switch p.Recovery {
		case pkg.RecoverReinstall:
			re = append(re, n)
		case pkg.RecoverDependency:
			dep = append(dep, n+" needs "+strings.Join(p.Missing, ", "))
		default:
			conf = append(conf, n)
		}
	}
	// Each part names the route that fits its state (S7-7): the
	// recovery, a removal of exactly the unfinished packages, or the
	// reinstall; with entries in the journal the recovery comes first,
	// since apt refuses to run until they are folded in (measured).
	var parts []string
	if len(conf) > 0 {
		parts = append(parts, fmt.Sprintf("%d package(s) to configure (%s): dpkg --configure -a finishes them "+
			"(the helper's recovery, priv_pkg_recover, where packages.allow_recover is set, or an administrator on the host)", len(conf), firstNames(conf)))
	}
	if len(dep) > 0 {
		parts = append(parts, fmt.Sprintf("%d package(s) with a missing dependency (%s): configuring leaves them unfinished; "+
			"a removal naming exactly the unfinished packages that do not need a reinstall removes them (priv_pkg_remove, where packages.remove lists them), "+
			"or an administrator installs the dependency on the host", len(dep), firstNames(dep)))
	}
	if len(re) > 0 {
		parts = append(parts, fmt.Sprintf("%d package(s) to reinstall (%s): dpkg --configure -a does not fix them and they cannot be removed (dpkg refuses); "+
			"a reinstall at the same version naming exactly them repairs them (priv_pkg_reinstall, where packages.install lists them and the package index has that version), "+
			"or an administrator reinstalls them on the host", len(re), firstNames(re)))
	}
	if journal > 0 {
		parts = append(parts, fmt.Sprintf("%d entr(ies) in its journal /var/lib/dpkg/updates, which dpkg --configure -a folds in "+
			"(priv_pkg_recover first, where packages.allow_recover is set: apt refuses to run until it is folded in)", journal))
	}
	if len(parts) == 0 {
		return "nothing unfinished"
	}
	return strings.Join(parts, "; ")
}

func firstNames(l []string) string {
	if len(l) <= 10 {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:10], ", ") + fmt.Sprintf(" and %d more", len(l)-10)
}

// lockFree refuses while another process holds the dpkg frontend lock: a
// simulation during its transaction shows a state about to change.
func (s *server) lockFree() error {
	h, held, err := pkg.LockHolder(s.dpkgLock())
	if err != nil {
		return errf(protocol.CodeExecFailed, "%s; nothing was requested", err.Error())
	}
	if held {
		return errf(protocol.CodeExecFailed, "the package database is locked by %s, which is changing packages; preview again after it ends", h.String())
	}
	return nil
}

func (s *server) dpkgLock() string { return s.o.DpkgDir + "/lock-frontend" }

// pkgPreview is priv_pkg_{install,upgrade,remove}_preview: the transaction
// simulated with the preview's argv, refused as the operation would refuse
// it, and hashed with the privileged policy (handoff P-5).
func (s *server) pkgPreview(raw jsontext.Value, op pkg.Op) (data any, warns []string, failure error) {
	names, _, err := pkgNames(raw, op, false)
	if err != nil {
		return nil, nil, err
	}
	if aerr := s.pkgAllowed(op, names); aerr != nil {
		return nil, nil, aerr
	}
	if err := s.notInProgress(); err != nil {
		return nil, nil, err
	}
	st, err := s.readState()
	if err != nil {
		return nil, nil, err
	}
	unfinished, err := pkgState(&st, op, names)
	if err != nil {
		return nil, nil, err
	}
	if lerr := s.lockFree(); lerr != nil {
		return nil, nil, lerr
	}
	argv, _ := pkg.Args(op, true, names)
	sim, err := s.simulate(argv, s.start.Add(s.timeout()))
	if err != nil {
		return nil, nil, err
	}
	if rerr := neverRemoves(op, sim.tx); rerr != nil {
		return nil, nil, rerr
	}
	entries := []recoverEntry{}
	if unfinished {
		if rerr := removesExactly(&st, sim.tx); rerr != nil {
			return nil, nil, rerr
		}
		entries = unfinishedEntries(st.UnfinishedPackages())
	}
	w := wireTx(sim.tx)
	stderr, cut := s.red.Truncate(sim.res.Stderr, s.p.Limits.MaxOutputBytes)
	d := previewData{
		Op: string(op), Packages: names, Install: w.Install, Upgrade: w.Upgrade, Remove: w.Remove, Unfinished: entries, Complete: true, Argv: argv,
		ExitCode: sim.res.ExitCode, Stderr: string(stderr), StderrTruncated: sim.res.StderrTruncated || cut, DurationMS: sim.res.Duration.Milliseconds(),
		PolicySHA256: s.p.SHA256, PreviewSHA256: previewHash(s.p.SHA256, op, names, sim.tx, argv, &st, unfinished),
	}
	return d, nil, nil
}

// previewHash is an install's, upgrade's or removal's preview_sha256; a
// removal in the unfinished mode binds dpkg's unfinished state too, in a
// domain of its own (handoff N-36).
func previewHash(policySHA string, op pkg.Op, names []string, tx pkg.Transaction, argv []string, st *pkg.State, unfinished bool) string {
	h := pkg.PreviewHash(policySHA, op, names, tx, argv)
	if unfinished {
		h = pkg.UnfinishedPreviewHash(h, st.UnfinishedPackages(), st.Journal)
	}
	return h
}

// neverRemoves refuses an install or upgrade whose transaction removes a
// package: the run carries --no-remove (PRIVILEGED §6).
func neverRemoves(op pkg.Op, tx pkg.Transaction) error {
	if op == pkg.OpRemove || len(tx.Remove) == 0 {
		return nil
	}
	names := make([]string, 0, len(tx.Remove))
	for _, r := range tx.Remove {
		names = append(names, r.Name)
	}
	return errf(protocol.CodePolicyDenied, "this %s would remove %d package(s) (%s); package installs and upgrades never remove packages; nothing was requested",
		op, len(names), firstNames(names))
}

// pkgStages are an install's, upgrade's or remove's points in time: the
// request's deadline, the stop point (SIGINT to apt-get alone) and the
// instance's limit (the process group killed), the last two from the
// instance's start and limits.max_timeout_s.
type pkgStages struct {
	deadline, stopAt, killAt time.Time
}

func (s *server) stages() pkgStages {
	limit := time.Duration(s.p.Limits.MaxTimeoutS) * time.Second
	allowance := min(maxStopAllowance, limit/4)
	return pkgStages{deadline: s.start.Add(s.timeout()), stopAt: s.start.Add(limit - allowance), killAt: s.start.Add(limit)}
}

// pkgChange is priv_pkg_install, priv_pkg_upgrade and priv_pkg_remove.
func (s *server) pkgChange(raw jsontext.Value, op pkg.Op) (data any, warns []string, failure error) {
	names, want, err := pkgNames(raw, op, true)
	if err != nil {
		return nil, nil, err
	}
	if aerr := s.pkgAllowed(op, names); aerr != nil {
		return nil, nil, aerr
	}
	st := s.stages()
	rec, err := s.holdRecord(st.killAt)
	if err != nil {
		return nil, nil, err
	}
	defer rec.release()
	timeout := s.timeout()
	lockBudget := time.Now().Add(min(maxLockWait, timeout/2))
	waited, err := s.waitLock(lockBudget, st.deadline)
	if err != nil {
		return nil, nil, err
	}
	before, err := s.readState()
	if err != nil {
		return nil, nil, err
	}
	unfinished, err := pkgState(&before, op, names)
	if err != nil {
		return nil, nil, err
	}
	// (1) The preview, recomputed with its own argv (and, for a removal in
	// the unfinished mode, dpkg's unfinished state).
	argv, _ := pkg.Args(op, true, names)
	sim, err := s.simulate(argv, st.deadline)
	if err != nil {
		return nil, nil, err
	}
	if rerr := neverRemoves(op, sim.tx); rerr != nil {
		return nil, nil, rerr
	}
	if previewHash(s.p.SHA256, op, names, sim.tx, argv, &before, unfinished) != want {
		return nil, nil, errf(protocol.CodeExists, "the transaction differs from its preview (a new candidate version, dependency or removal, "+
			"a change to the packages dpkg left unfinished, or the privileged policy changed); nothing was run; preview again")
	}
	if unfinished {
		if rerr := removesExactly(&before, sim.tx); rerr != nil {
			return nil, nil, rerr
		}
	}
	tx := sim.tx
	if pkgHook != nil {
		pkgHook(s, "before-pinned-sim")
	}
	// (2) The exact argv about to run, simulated: its transaction must be
	// the approved one.
	pinnedSim, err := pkg.PinnedArgs(op, true, names, tx)
	if err != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "the approved transaction cannot be pinned (%s); nothing was run", err.Error())
	}
	pinned, _ := pkg.PinnedArgs(op, false, names, tx)
	if pinned == nil && !tx.Empty() {
		return nil, nil, errf(protocol.CodeExecFailed, "the approved transaction (%s) cannot be run pinned to the request; nothing was run", txSummary(tx))
	}
	if pinned == nil {
		// Nothing to change: approved, and nothing runs.
		s.recordApplied(pkg.Transaction{})
		return pkgData{Op: string(op), Packages: names, Applied: ptr(wireTx(pkg.Transaction{})), LockWaitMS: waited.Milliseconds()}, nil, nil
	}
	ps, err := s.simulate(pinnedSim, st.deadline)
	if err != nil {
		var oe *opError
		if errors.As(err, &oe) && oe.code == protocol.CodeExecFailed {
			return nil, nil, errf(protocol.CodeExists, "the pinned transaction can no longer be resolved (%s); nothing was run; preview again", oe.msg)
		}
		return nil, nil, err
	}
	if !ps.tx.Equal(tx) {
		return nil, nil, errf(protocol.CodeExists, "the pinned transaction differs from the approved one (%s, approved %s); nothing was run; preview again",
			txSummary(ps.tx), txSummary(tx))
	}
	if pkgHook != nil {
		pkgHook(s, "before-run")
	}
	// (3) The run, then dpkg's status decides.
	res, attempts, err := s.runPinned(pinned, st, lockBudget)
	if err != nil {
		return nil, nil, err
	}
	return s.pkgOutcome(op, names, &before, tx, &res, attempts, waited)
}

func ptr[T any](v T) *T { return &v }

// txSummary is a transaction in a message: counts and the first names.
func txSummary(t pkg.Transaction) string {
	var in, up, rm []string
	for _, v := range t.Install {
		in = append(in, v.Name+" "+v.Version)
	}
	for _, u := range t.Upgrade {
		up = append(up, u.Name+" "+u.From+"→"+u.To)
	}
	for _, r := range t.Remove {
		rm = append(rm, r.Name+" "+r.Version)
	}
	part := func(verb string, l []string) string {
		if len(l) == 0 {
			return verb + " 0"
		}
		return fmt.Sprintf("%s %d (%s)", verb, len(l), firstNames(l))
	}
	return part("install", in) + ", " + part("upgrade", up) + ", " + part("remove", rm)
}

// waitLock waits while another process holds the dpkg frontend lock, until
// budget; a hang-up or the request's deadline ends the wait with nothing
// changed. It returns how long it waited.
func (s *server) waitLock(budget, deadline time.Time) (time.Duration, error) {
	start := time.Now()
	retry := s.o.PkgLockRetry
	if retry <= 0 {
		retry = pkg.DefaultRetry
	}
	for {
		h, held, err := pkg.LockHolder(s.dpkgLock())
		if err != nil {
			return 0, errf(protocol.CodeExecFailed, "%s; nothing was changed", err.Error())
		}
		if !held {
			return time.Since(start), nil
		}
		if time.Now().Add(retry).After(budget) {
			return 0, errf(protocol.CodeExecFailed, "the package database is locked by %s (waited %d s); nothing was changed; try again later",
				h.String(), time.Since(start).Milliseconds()/1000)
		}
		if err := s.pause(retry, deadline); err != nil {
			return 0, err
		}
	}
}

// pause waits d, ended early, with nothing changed, by a hang-up or the
// request's deadline.
func (s *server) pause(d time.Duration, deadline time.Time) error {
	t := time.NewTimer(min(d, max(time.Until(deadline), 0)))
	defer t.Stop()
	select {
	case <-s.hangup():
		s.hungUp = true
		return errf(protocol.CodeTimeout, "the gate stopped waiting before apt-get changed anything; nothing was changed")
	case <-t.C:
	}
	if !time.Now().Before(deadline) {
		return errf(protocol.CodeTimeout, "the request's time ran out before apt-get changed anything; nothing was changed")
	}
	return nil
}

// runPinned runs the pinned argv through the stop points, again after
// apt's own refusal of a held lock while the lock budget lasts, unless the
// request was already answered.
func (s *server) runPinned(argv []string, st pkgStages, lockBudget time.Time) (execx.Result, int, error) {
	return s.runLocked(s.o.AptGet, argv, st, lockBudget, true)
}

// runLocked runs path with argv through the stop points, again after the
// program's own refusal of a held lock while the lock budget lasts,
// unless the request was already answered. sigint says whether the stop
// point sends SIGINT (apt-get's graceful stop; dpkg has none).
func (s *server) runLocked(path string, argv []string, st pkgStages, lockBudget time.Time, sigint bool) (execx.Result, int, error) {
	retry := s.o.PkgLockRetry
	if retry <= 0 {
		retry = pkg.DefaultRetry
	}
	attempts := 0
	for {
		res, err := s.runApt(path, argv, st, sigint)
		attempts++
		if err != nil {
			return res, attempts, err
		}
		if res.ExitCode == nil || *res.ExitCode == 0 || !pkg.LockHeld(res.Stderr) {
			return res, attempts, nil
		}
		// apt refused before changing anything: another process took the
		// lock after the wait.
		if s.answered || time.Now().Add(retry).After(lockBudget) {
			return res, attempts, errf(protocol.CodeExecFailed, "the package database is locked by %s; nothing was changed; try again later", holderOf(res.Stderr))
		}
		if err := s.pause(retry, st.deadline); err != nil {
			return res, attempts, err
		}
	}
}

// runApt runs path (apt-get, or dpkg for the recovery) once through the
// stop points (PRIVILEGED §6): no signal at a hang-up or the request's
// deadline, but an early outcome_unknown answer; SIGINT to apt-get alone
// at the stop point when sigint is set (never for dpkg, which ignores
// SIGINT only while it waits for a maintainer script and otherwise dies
// of it: dpkg 1.22.22, lib/dpkg/subproc.c and src/main/script.c); the
// process group killed at the instance's limit; then every child left
// killed and reaped.
func (s *server) runApt(path string, argv []string, st pkgStages, sigint bool) (execx.Result, error) {
	if s.answered {
		return execx.Result{}, errf(protocol.CodeExecFailed, "the request was answered before apt-get started; nothing was changed")
	}
	if s.o.ReapOrphans && s.o.ReapHooks == nil {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			s.reapErr = "PR_SET_CHILD_SUBREAPER: " + err.Error()
			return execx.Result{}, errf(protocol.CodeExecFailed, "the helper could not make itself a child subreaper, so it could not account for what apt-get would start; nothing was changed")
		}
	}
	var mu sync.Mutex
	var proc *os.Process
	spec := &execx.Spec{
		Trampoline: s.o.Executable, Path: path, Args: argv, Env: s.aptEnv(), Dir: "/",
		Timeout: time.Until(st.killAt), MaxOutput: s.p.Limits.MaxOutputBytes, MaxMemoryMB: s.p.Limits.MaxMemoryMB,
		Started: func(p *os.Process) { mu.Lock(); proc = p; mu.Unlock() },
	}
	done := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		hang := s.hangup()
		dl := time.NewTimer(time.Until(st.deadline))
		stop := time.NewTimer(time.Until(st.stopAt))
		defer dl.Stop()
		defer stop.Stop()
		if !sigint {
			stop.Stop()
		}
		for {
			select {
			case <-done:
				return
			case <-hang:
				// A gate that closes once it has the early answer did not
				// hang up on the operation.
				hang = nil
				s.mu.Lock()
				answered := s.answered
				s.mu.Unlock()
				if !answered {
					s.hungUp = true
				}
				s.answerEarly("after the gate stopped waiting")
			case <-dl.C:
				s.answerEarly("at the request's timeout")
			case <-stop.C:
				mu.Lock()
				p := proc
				mu.Unlock()
				if p == nil {
					// Not started yet: try again shortly.
					stop.Reset(50 * time.Millisecond)
					continue
				}
				// apt's own graceful stop: the dpkg run in progress
				// finishes, nothing after it is unpacked or removed.
				// Never the process group: dpkg and maintainer scripts
				// would get it too.
				if p.Signal(unix.SIGINT) == nil {
					s.setStopped("sigint")
				}
			}
		}
	}()
	res, err := execx.Run(context.Background(), spec)
	close(done)
	watcher.Wait()
	if res.TimedOut {
		s.setStopped("killed")
	}
	if s.o.ReapOrphans {
		if rerr := s.reap(); rerr != nil {
			s.reapErr = rerr.Error()
		}
	}
	return res, err
}

func (s *server) setStopped(how string) {
	s.mu.Lock()
	s.stopped = how
	s.mu.Unlock()
}

// answerEarly answers the request, once, with outcome_unknown while apt-get
// runs (a hang-up or the request's deadline): the operation goes on, and
// its journal line, written when it ends, has its result.
func (s *server) answerEarly(when string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.answered {
		return
	}
	s.answered = true
	until := s.stages().killAt.UTC().Format(time.RFC3339)
	program, stop, logFile := "apt-get", "stopped gracefully before then, killed only then", "/var/log/apt/history.log"
	if s.program == "dpkg" {
		program, stop, logFile = "dpkg", "killed only then", "/var/log/dpkg.log"
	}
	resp := failure(protocol.CodeOutcomeUnknown, fmt.Sprintf("%s is still running %s (request id %s): it is left to finish, because stopping dpkg part-way "+
		"would leave its database unfinished, and may run until %s (%s); what it changed will be in "+
		"the helper's journal under request id %s and in %s on the host; preview again after that time; the approval was used",
		program, when, s.req.ID, until, stop, s.req.ID, logFile))
	resp.ID = s.req.ID
	s.earlyCode = s.respond(s.conn, resp)
}

// pkgOutcome decides the result from dpkg's status alone (the maintainer's
// condition 2): the transaction applied exactly and nothing unfinished is
// a success; nothing changed is exec_failed; anything else verify_failed.
// apt's exit code decides nothing.
func (s *server) pkgOutcome(op pkg.Op, names []string, before *pkg.State, tx pkg.Transaction, res *execx.Result, attempts int, waited time.Duration) (data any, warns []string, failure error) {
	after, err := pkg.ReadState(s.o.DpkgDir)
	if err != nil {
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "apt-get ran, but dpkg's state could not be read afterwards (%s); check the host", err.Error())
	}
	diff := pkg.Diff(before.Status, after.Status)
	s.recordApplied(diff)
	s.unfinished = after.Unfinished()
	if len(s.unfinished) > maxAuditChanged {
		s.unfinished = s.unfinished[:maxAuditChanged]
	}
	if s.reapErr != "" {
		// Fail closed, as for a command (S4c-6): something apt-get or a
		// maintainer script started may still run as root.
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "the helper could not confirm that every process apt-get started has ended (see its journal on the host); "+
			"applied so far %s, approved %s", txSummary(diff), txSummary(tx))
	}
	stopped := ""
	s.mu.Lock()
	stopped = s.stopped
	s.mu.Unlock()
	how := ""
	switch stopped {
	case "sigint":
		how = "apt-get was asked to stop at the helper's limit and stopped at a safe point; "
	case "killed":
		how = "apt-get was killed at the helper's limit; "
	}
	if before.Same(after) {
		// Nothing changed, a removal in the unfinished mode included,
		// whose unfinished packages are still as they were.
		code := "none"
		if res.ExitCode != nil {
			code = fmt.Sprint(*res.ExitCode)
		}
		return nil, nil, errf(protocol.CodeExecFailed, "%sapt-get changed nothing (exit code %s)%s; nothing was changed", how, code, aptErrors(res.Stderr, s))
	}
	if left := stillUnfinished(before, &after); len(left) > 0 || len(after.Journal) > 0 {
		return nil, nil, errf(protocol.CodeVerifyFailed, "%sdpkg was interrupted and left %s; the transaction cannot be undone; applied %s, approved %s",
			how, describeUnfinished(left, len(after.Journal)), txSummary(diff), txSummary(tx))
	}
	switch {
	case diff.Equal(tx):
		d, w := s.pkgResult(op, names, res, attempts, waited)
		d.Applied = ptr(wireTx(diff))
		if stopped != "" {
			w = append(w, "apt-get was stopped at the helper's limit after the whole transaction had been applied")
		}
		return d, w, nil
	case diff.Empty():
		code := "none"
		if res.ExitCode != nil {
			code = fmt.Sprint(*res.ExitCode)
		}
		return nil, nil, errf(protocol.CodeExecFailed, "%sapt-get changed nothing (exit code %s)%s; nothing was changed", how, code, aptErrors(res.Stderr, s))
	}
	return nil, nil, errf(protocol.CodeVerifyFailed, "%sthe transaction differed from the approved one: applied %s, approved %s; it cannot be undone; preview again",
		how, txSummary(diff), txSummary(tx))
}

// stillUnfinished are the packages dpkg left unfinished after an
// operation, less those that needed a reinstall before it and are exactly
// as they were: a removal in the unfinished mode leaves them alone (M1,
// handoff N-36), which is not a failure. A clean database before (every
// other operation) tolerates nothing.
func stillUnfinished(before, after *pkg.State) []pkg.UnfinishedPackage {
	var out []pkg.UnfinishedPackage
	for _, p := range after.UnfinishedPackages() {
		b, ok := before.Packages[p.Name]
		if ok && p.Recovery == pkg.RecoverReinstall && b == after.Packages[p.Name] {
			continue
		}
		out = append(out, p)
	}
	return out
}
