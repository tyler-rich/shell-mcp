//go:build linux

package ops

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
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
	switch {
	case (op == pkg.OpInstall || op == pkg.OpRemove) && bound:
		err = decode(raw, &a)
	case op == pkg.OpInstall || op == pkg.OpRemove:
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
	if (op == pkg.OpInstall || op == pkg.OpRemove) && a.Packages == nil {
		return nil, "", errf(protocol.CodeBadRequest, "packages is required")
	}
	if _, aerr := pkg.Args(op, false, a.Packages); aerr != nil {
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
	case pkg.OpInstall, pkg.OpRemove:
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
	if err := s.pkgAllowed(pkg.OpUpdate, nil); err != nil {
		return nil, nil, err
	}
	argv, _ := pkg.Args(pkg.OpUpdate, false, nil)
	if pkg.UpdatePreviewHash(s.p.SHA256, argv) != want {
		return nil, nil, errf(protocol.CodeExists, "the index update differs from its preview (the privileged policy changed); nothing was run")
	}
	timeout := s.timeout()
	r := pkg.Runner{
		AptGet: s.o.AptGet, Trampoline: s.o.Executable, Env: s.aptEnv(), MaxOutput: s.p.Limits.MaxOutputBytes,
		LockWait: min(maxLockWait, timeout/2), Retry: s.o.PkgLockRetry,
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
	d, w := s.pkgResult(pkg.OpUpdate, []string{}, res.Result, res.Attempts, res.LockWait)
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
func (s *server) pkgResult(op pkg.Op, names []string, res execx.Result, attempts int, lockWait time.Duration) (pkgData, []string) {
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
		MaxOutput: s.p.Limits.MaxOutputBytes}, false)
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

// pkgChecks are the checks a preview and its operation share, before
// anything is simulated: no package operation of this helper in progress
// (its record), the dpkg frontend lock free (previews only: an operation
// waits for it), and nothing dpkg left unfinished.
func (s *server) pkgChecks() error {
	if err := s.notInProgress(); err != nil {
		return err
	}
	return s.notUnfinished()
}

// notUnfinished refuses a database dpkg left part-way: unfinished
// packages, or entries in its journal (PRIVILEGED §6).
func (s *server) notUnfinished() error {
	st, err := pkg.ReadStatus(s.o.DpkgDir)
	if err != nil {
		return errf(protocol.CodeExecFailed, "dpkg's status could not be read (%s); nothing was changed", err.Error())
	}
	return unfinishedErr(st, s.o.DpkgDir, "nothing was changed")
}

func unfinishedErr(st pkg.Status, dir, tail string) error {
	unf := st.Unfinished()
	upd, err := pkg.PendingUpdates(dir)
	if err != nil {
		return errf(protocol.CodeExecFailed, "dpkg's journal could not be read (%s); %s", err.Error(), tail)
	}
	if len(unf) == 0 && len(upd) == 0 {
		return nil
	}
	what := []string{}
	if len(unf) > 0 {
		what = append(what, fmt.Sprintf("%d package(s) unfinished (%s)", len(unf), firstNames(unf)))
	}
	if len(upd) > 0 {
		what = append(what, fmt.Sprintf("%d entr(ies) in its journal /var/lib/dpkg/updates", len(upd)))
	}
	return errf(protocol.CodeExecFailed, "dpkg was interrupted and left %s: an administrator must run dpkg --configure -a on the host; %s", strings.Join(what, " and "), tail)
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
	if err := s.pkgAllowed(op, names); err != nil {
		return nil, nil, err
	}
	if err := s.pkgChecks(); err != nil {
		return nil, nil, err
	}
	if err := s.lockFree(); err != nil {
		return nil, nil, err
	}
	argv, _ := pkg.Args(op, true, names)
	sim, err := s.simulate(argv, s.start.Add(s.timeout()))
	if err != nil {
		return nil, nil, err
	}
	if err := neverRemoves(op, sim.tx); err != nil {
		return nil, nil, err
	}
	w := wireTx(sim.tx)
	stderr, cut := s.red.Truncate(sim.res.Stderr, s.p.Limits.MaxOutputBytes)
	d := previewData{
		Op: string(op), Packages: names, Install: w.Install, Upgrade: w.Upgrade, Remove: w.Remove, Complete: true, Argv: argv,
		ExitCode: sim.res.ExitCode, Stderr: string(stderr), StderrTruncated: sim.res.StderrTruncated || cut, DurationMS: sim.res.Duration.Milliseconds(),
		PolicySHA256: s.p.SHA256, PreviewSHA256: pkg.PreviewHash(s.p.SHA256, op, names, sim.tx, argv),
	}
	return d, nil, nil
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
	if err := s.pkgAllowed(op, names); err != nil {
		return nil, nil, err
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
	before, err := pkg.ReadStatus(s.o.DpkgDir)
	if err != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "dpkg's status could not be read (%s); nothing was changed", err.Error())
	}
	if err := unfinishedErr(before, s.o.DpkgDir, "nothing was changed"); err != nil {
		return nil, nil, err
	}
	// (1) The preview, recomputed with its own argv.
	argv, _ := pkg.Args(op, true, names)
	sim, err := s.simulate(argv, st.deadline)
	if err != nil {
		return nil, nil, err
	}
	if err := neverRemoves(op, sim.tx); err != nil {
		return nil, nil, err
	}
	if pkg.PreviewHash(s.p.SHA256, op, names, sim.tx, argv) != want {
		return nil, nil, errf(protocol.CodeExists, "the transaction differs from its preview (a new candidate version, dependency or removal, or the privileged policy changed); nothing was run; preview again")
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
	if pinned == nil {
		// Nothing to change: approved, and nothing runs.
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
	return s.pkgOutcome(op, names, before, tx, res, attempts, waited)
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
	retry := s.o.PkgLockRetry
	if retry <= 0 {
		retry = pkg.DefaultRetry
	}
	attempts := 0
	for {
		res, err := s.runApt(argv, st)
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

// runApt runs apt-get once through the stop points (PRIVILEGED §6): no
// signal at a hang-up or the request's deadline, but an early
// outcome_unknown answer; SIGINT to apt-get alone at the stop point; the
// process group killed at the instance's limit; then every child left
// killed and reaped.
func (s *server) runApt(argv []string, st pkgStages) (execx.Result, error) {
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
	pid := 0
	spec := &execx.Spec{
		Trampoline: s.o.Executable, Path: s.o.AptGet, Args: argv, Env: s.aptEnv(), Dir: "/",
		Timeout: time.Until(st.killAt), MaxOutput: s.p.Limits.MaxOutputBytes,
		Started: func(p int) { mu.Lock(); pid = p; mu.Unlock() },
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
				p := pid
				mu.Unlock()
				if p == 0 {
					// Not started yet: try again shortly.
					stop.Reset(50 * time.Millisecond)
					continue
				}
				// apt's own graceful stop: the dpkg run in progress
				// finishes, nothing after it is unpacked or removed.
				// Never the process group: dpkg and maintainer scripts
				// would get it too.
				_ = unix.Kill(p, unix.SIGINT)
				s.setStopped("sigint")
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
	resp := failure(protocol.CodeOutcomeUnknown, fmt.Sprintf("apt-get is still running %s (request id %s): it is left to finish, because stopping dpkg part-way "+
		"would leave its database unfinished, and may run until %s (stopped gracefully before then, killed only then); what it changed will be in "+
		"the helper's journal under request id %s and in /var/log/apt/history.log on the host; preview again after that time; the approval was used",
		when, s.req.ID, until, s.req.ID))
	resp.ID = s.req.ID
	s.earlyCode = s.respond(s.conn, resp)
}

// pkgOutcome decides the result from dpkg's status alone (the maintainer's
// condition 2): the transaction applied exactly and nothing unfinished is
// a success; nothing changed is exec_failed; anything else verify_failed.
// apt's exit code decides nothing.
func (s *server) pkgOutcome(op pkg.Op, names []string, before pkg.Status, tx pkg.Transaction, res execx.Result, attempts int, waited time.Duration) (any, []string, error) {
	after, err := pkg.ReadStatus(s.o.DpkgDir)
	if err != nil {
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "apt-get ran, but dpkg's status could not be read afterwards (%s); check the host", err.Error())
	}
	diff := pkg.Diff(before, after)
	s.recordApplied(diff)
	s.unfinished = after.Unfinished()
	if len(s.unfinished) > maxAuditChanged {
		s.unfinished = s.unfinished[:maxAuditChanged]
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
	if err := unfinishedErr(after, s.o.DpkgDir, "the transaction cannot be undone"); err != nil {
		var oe *opError
		errors.As(err, &oe)
		return nil, nil, errf(protocol.CodeVerifyFailed, "%s%s; applied %s, approved %s", how, oe.msg, txSummary(diff), txSummary(tx))
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
