//go:build linux

// Package ops is the privileged helper's serve pipeline (docs/PRIVILEGED.md
// §3, §6, §7, §8; ARCHITECTURE §3 step 5): peer credentials against the
// unit → self-checks and policy → Landlock → read one request → tier → op
// against the privileged policy → backup → execute → verify → respond →
// audit.
//
// Nothing is ever written to a peer that has not passed the SO_PEERCRED
// check, which uses only the connection and the unit's environment: a
// refusal there closes the connection without a byte. A self-check that
// fails after it is answered with its own code before the request is read.
// Either way the journal gets one WARN line naming the check.
package ops

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/peercred"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/selfcheck"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// Deadlines on the connection.
const (
	readDeadline  = 10 * time.Second // the gate writes its request right after connecting
	writeDeadline = 10 * time.Second
)

// Options configures one helper run. ProductionOptions fills it from the
// running process; nothing in it comes from the connection.
type Options struct {
	Version    string
	PolicyPath string
	// Executable is the helper binary's resolved path.
	Executable string
	// ExpectedSHA256 is SHELL_MCP_PRIVD_POLICY_SHA256 from the unit.
	ExpectedSHA256 string
	// UnitClientUID is SHELL_MCP_PRIVD_CLIENT_UID from the unit.
	UnitClientUID string
	// Unit is SHELL_MCP_PRIVD_UNIT from the unit: core or broad.
	Unit string
	// AptGet is the apt-get binary (production: /usr/bin/apt-get).
	AptGet string
	// DpkgDir is dpkg's administrative directory (production:
	// /var/lib/dpkg): its status file, updates/ journal and frontend lock.
	DpkgDir string
	// PkgRecord is the package operation record (production:
	// /run/shell-mcp-privd-pkg), locked while an install, upgrade or remove
	// runs (PRIVILEGED §6, "Package operations").
	PkgRecord string
	// ResolveExecutable, when set, resolves Executable after the peer check
	// (production: the running binary, so nothing touches the filesystem
	// before the peer is authenticated).
	ResolveExecutable func() (string, error)
	// BuiltWithCGO reports a binary built with cgo, which the helper refuses
	// to run (no_new_privs and Landlock need CGO_ENABLED=0).
	BuiltWithCGO bool
	Trust        gpolicy.Trust
	// Lookups fills the policy loader's user and group lookups
	// (production: policy.ProductionLookups).
	Lookups func(*policy.LoadOptions)
	// SystemBinDirs are the identity check's directories (nil: defaults).
	SystemBinDirs []string
	// ReadStatus returns /proc/self/status.
	ReadStatus func() ([]byte, error)
	// Conn is the accepted connection (stdin under the unit).
	Conn *os.File
	// BackupDir is the backup store (production: units.BackupDir).
	BackupDir string
	// ApplySandbox applies Landlock (production: ApplyLandlock).
	ApplySandbox func(*policy.Policy, string) (sandbox.Report, error)
	// Audit receives one line per connection (production: stderr, which
	// the unit sends to the journal).
	Audit io.Writer
	// SystemBus is the system bus socket priv_power talks to (production:
	// dbus.SystemBus).
	SystemBus string
	// PowerDecision is the power decision file (production:
	// /run/shell-mcp-privd-power; PRIVILEGED §6, "Power").
	PowerDecision string
	// PowerDelay replaces priv_power's 60 s delay; tests only.
	PowerDelay time.Duration
	// PowerConfirmWait replaces the 10 s the gate has to read priv_power's
	// answer in; tests only.
	PowerConfirmWait time.Duration
	// HoldTermWhileRequesting ignores SIGTERM from just before priv_power's
	// logind call until its journal line is written (production: true).
	HoldTermWhileRequesting bool
	// PkgLockRetry is the pause between attempts while the dpkg or lists lock
	// is held (0 means 2 s); tests only.
	PkgLockRetry time.Duration
	// InjectReadBackFault is passed to fsx; tests only.
	InjectReadBackFault func([]byte) []byte
	// InjectBeforeCommit and InjectNoReplaceFault are passed to fsx; tests
	// only.
	InjectBeforeCommit   func()
	InjectNoReplaceFault func() error
	// InjectMetadataReadBackFault is passed to fsx; tests only.
	InjectMetadataReadBackFault func(fsx.Meta) fsx.Meta
	// InjectBeforeBackup and InjectExchangeFault are passed to fsx; tests
	// only.
	InjectBeforeBackup  func()
	InjectExchangeFault func() error
	// InjectDeleteStep is passed to fsx (DeleteExactBound's steps); tests
	// only.
	InjectDeleteStep func(fsx.DeleteStep, string)
	// InjectStopAfterSetAside is passed to fsx; tests only.
	InjectStopAfterSetAside func(string) error
	// InjectAfterStage is passed to fsx (a move's staging); tests only.
	InjectAfterStage func(string) error
	// DisableCommitReport leaves fsx's OnCommit unset, as a mutating site
	// that never reports would; tests only.
	DisableCommitReport bool
	// Now is the clock (backup ids and times).
	Now func() time.Time
	// ReapOrphans makes the helper a child subreaper while it runs a
	// command, and kill and reap every child it still has once the command
	// has ended (production: true). Tests leave it off: in a test binary,
	// other tests' processes would be its children too.
	ReapOrphans bool
	// ReapHooks replace the child listing and the wait of ReapOrphans, and
	// skip PR_SET_CHILD_SUBREAPER; tests only.
	ReapHooks *ReapHooks
}

// ProductionOptions describes the running process: the unit's client uid
// and policy hash, its own executable (resolved after the peer check),
// root-only trust, the local user and group databases, /proc/self/status,
// stdin as the connection, the fixed backup store, the helper's Landlock
// ruleset and stderr for the audit.
func ProductionOptions(version, policyPath string) Options {
	return Options{
		Version: version, PolicyPath: policyPath,
		ResolveExecutable: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(exe)
		},
		UnitClientUID:           os.Getenv(units.ClientUIDEnv),
		Unit:                    os.Getenv(units.UnitEnv),
		AptGet:                  policy.DefaultAptGet,
		DpkgDir:                 DefaultDpkgDir,
		PkgRecord:               DefaultPkgRecord,
		SystemBus:               dbus.SystemBus,
		ExpectedSHA256:          os.Getenv(units.HashEnv),
		Trust:                   gpolicy.RootTrust(),
		Lookups:                 policy.ProductionLookups,
		ReadStatus:              func() ([]byte, error) { return os.ReadFile("/proc/self/status") },
		Conn:                    os.Stdin,
		BackupDir:               units.BackupDir,
		ApplySandbox:            ApplyLandlock,
		Audit:                   os.Stderr,
		Now:                     time.Now,
		ReapOrphans:             true,
		PowerDecision:           DefaultPowerDecision,
		HoldTermWhileRequesting: true,
	}
}

// server holds one connection's state.
type server struct {
	o     *Options
	start time.Time
	p     *policy.Policy
	cred  peercred.Cred
	// unitUID is the unit's client uid, which the peer matched.
	unitUID uint32
	// unit is the unit this instance runs in (SHELL_MCP_PRIVD_UNIT).
	unit      policy.Unit
	fs        *fsx.FS
	restoreFS *fsx.FS
	red       *redact.Redactor
	store     *store
	req       *protocol.Request
	// backupIDs are the backups written for this request.
	backupIDs []string
	// precondition is the content hash the request's precondition named
	// (expected_sha256, expected_destination_sha256), for its backups.
	precondition string
	// boundPreview is a delete's expected_preview_sha256, which its backup
	// records (it is not a content hash, so nothing is compared with it).
	boundPreview string
	// committed reports that the request changed the filesystem (fsx's
	// OnCommit): a failed request that did not keeps no backup.
	committed bool
	// discarded are the backups removed again because the request failed
	// provably unchanged (the audit line records them).
	discarded []string
	// changed are the entries chmod or chown changed, with their old
	// values, for the audit line (bounded: recordChanges); changedTotal
	// counts every one, changedBytes the list's encoded size.
	changed          []auditChange
	changedTotal     int
	changedBytes     int
	changedTruncated bool
	// removed are the entries a delete removed, for the audit line
	// (bounded: recordRemoved); removedTotal counts every one.
	removed          []string
	removedTotal     int
	removedBytes     int
	removedTruncated bool
	// setAside is the entry a delete left set aside (fsx.Error.SetAside).
	setAside string
	// conn is the connection the request was read from; priv_exec watches it
	// for the gate's hang-up while the command runs.
	conn net.Conn
	// hungUp reports that the gate hung up while priv_exec ran its command,
	// or before it started (the audit line records it).
	hungUp bool
	// reapErr is why the helper could not confirm that every process a
	// command started has ended (the audit line records it).
	reapErr string
	// hangOnce starts the one watcher of the connection (hangup), whose
	// channel hangCh is closed when the gate hangs up.
	hangOnce sync.Once
	hangCh   <-chan struct{}
	// mu guards what a package operation's stop-point watcher sets while
	// apt-get runs: answered (the request was answered early,
	// outcome_unknown, and earlyCode is respond's result) and stopped
	// ("sigint" or "killed").
	mu        sync.Mutex
	answered  bool
	earlyCode int
	stopped   string
	// applied is what dpkg's status shows a package operation changed, and
	// unfinished the packages dpkg left part-way, for the audit line.
	applied    *auditApplied
	unfinished []string
	// powerState is what became of priv_power's action ("not_delivered",
	// "cancelled", "refused", "unconfirmed", "requested"), powerAt its
	// scheduled time and powerDetail why it was refused, for the audit line.
	powerState, powerAt, powerDetail string
}

// Serve handles one connection and returns the process exit code: 0 when a
// request was read and answered, 1 otherwise — including every refused
// connection, whether it was closed without a byte (the peer check) or
// answered with a self-check code.
//
// The order is PRIVILEGED §7: (1) authenticate the peer from the
// connection and the unit's environment alone; (2) every other self-check,
// the policy load among them, answered to the authenticated peer; (3)
// Landlock, answered as helper_sandbox_unavailable; (4) only then read the
// request. Nothing reads from the
// connection before (4).
func Serve(o *Options) int {
	s := &server{o: o, start: time.Now()}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := s.authenticate(); err != nil {
		s.auditRefusal(err, "")
		return 1
	}
	// A duplicate of the connection with deadlines (it needs no filesystem
	// access and reads nothing).
	nc, err := net.FileConn(o.Conn)
	if err != nil {
		s.auditRefusal(&selfcheck.Error{Check: selfcheck.CheckStdin, Detail: "connection cannot be used: " + err.Error()}, "")
		return 1
	}
	defer func() { _ = nc.Close() }()

	if err := s.checks(); err != nil {
		code, msg := selfCheckFailure(err)
		s.respond(nc, failure(code, msg))
		s.auditRefusal(err, code)
		return 1
	}
	if err := s.sandbox(); err != nil {
		s.respond(nc, failure(protocol.CodeHelperSandboxUnavailable, "the privileged helper's Landlock sandbox could not be applied under sandbox.landlock: required; see the helper's journal and run shell-mcp-privd check-policy on the host"))
		s.auditRefusal(err, protocol.CodeHelperSandboxUnavailable)
		return 1
	}
	resp := s.run(nc)
	if s.req != nil {
		resp.ID = s.req.ID
	}
	// A package operation answered early (outcome_unknown, while apt-get
	// ran) is not answered again; its journal line has its own result.
	code := s.earlyCode
	if !s.answered {
		code = s.respond(nc, resp)
	}
	s.auditRequest(resp)
	return code
}

// respond writes resp with the helper's own block (its version, policy
// hash, max_tier and unit), which the gate passes to the server as the
// response's `helper` block; it returns 0 if the response was written.
func (s *server) respond(nc net.Conn, resp *protocol.Response) int {
	resp.V = protocol.Version
	resp.Gate = &protocol.GateInfo{Version: s.o.Version, Principal: "shell-mcp-privd", Unit: string(s.unit), DurationMS: time.Since(s.start).Milliseconds()}
	if s.p != nil {
		resp.Gate.PolicySHA256, resp.Gate.MaxTier = s.p.SHA256, s.p.MaxTier.String()
	}
	_ = nc.SetWriteDeadline(time.Now().Add(writeDeadline))
	return writeResponse(nc, resp)
}

// authenticate is PRIVILEGED §7 step 1. It uses only the connection (fstat,
// getsockopt, getpeername, SO_PEERCRED — never a read) and the unit's
// SHELL_MCP_PRIVD_CLIENT_UID; nothing is read from disk. A failure here
// is never answered.
func (s *server) authenticate() error {
	o := s.o
	if o.Conn == nil {
		return &selfcheck.Error{Check: selfcheck.CheckStdin, Detail: "no connection"}
	}
	fd := int(o.Conn.Fd())
	if e := selfcheck.Stdin(fd); e != nil {
		return e
	}
	want, err := selfcheck.UnitClientUID(o.UnitClientUID)
	if err != nil {
		return err
	}
	cred, err := peercred.Authenticate(fd, want)
	s.cred = cred
	switch {
	case errors.Is(err, peercred.ErrWrongPeer):
		return &selfcheck.Error{Check: selfcheck.CheckPeer, Detail: fmt.Sprintf("peer uid %d is not the unit's client uid %d", cred.UID, want)}
	case err != nil:
		return &selfcheck.Error{Check: selfcheck.CheckPeer, Detail: err.Error()}
	}
	s.unitUID = want
	return nil
}

// checks is PRIVILEGED §7 step 2, for an authenticated peer: the process,
// the binary, the policy, the policy's hash and client_uid against the
// unit's, and the bounding set. Each failure is a *selfcheck.Error.
func (s *server) checks() error {
	o := s.o
	raw, err := o.ReadStatus()
	if err != nil {
		return &selfcheck.Error{Check: selfcheck.CheckUID, Detail: "cannot read /proc/self/status: " + err.Error()}
	}
	st, err := selfcheck.ParseStatus(raw)
	if err != nil {
		return &selfcheck.Error{Check: selfcheck.CheckUID, Detail: "cannot parse /proc/self/status: " + err.Error()}
	}
	if e := selfcheck.Process(&st); e != nil {
		return e
	}
	if o.BuiltWithCGO {
		return &selfcheck.Error{Check: selfcheck.CheckBinary, Detail: "the helper was built with cgo; rebuild with CGO_ENABLED=0"}
	}
	if o.ResolveExecutable != nil {
		exe, rerr := o.ResolveExecutable()
		if rerr != nil {
			return &selfcheck.Error{Check: selfcheck.CheckBinary, Detail: "cannot resolve own path: " + rerr.Error()}
		}
		o.Executable = exe
	}
	if e := selfcheck.Binary(o.Trust, o.Executable); e != nil {
		return e
	}
	lo := &policy.LoadOptions{Trust: o.Trust, HelperExecutable: o.Executable, SystemBinDirs: o.SystemBinDirs, AptGet: o.AptGet}
	o.Lookups(lo)
	p, err := policy.Load(o.PolicyPath, lo)
	if err != nil {
		var oe *gpolicy.OwnershipError
		if errors.As(err, &oe) {
			return &policyError{&selfcheck.Error{Check: selfcheck.CheckPolicyFile, Detail: err.Error()}, err}
		}
		return &policyError{&selfcheck.Error{Check: selfcheck.CheckPolicy, Detail: err.Error()}, err}
	}
	if e := selfcheck.Hash(p.SHA256, o.ExpectedSHA256); e != nil {
		return e
	}
	if e := selfcheck.ClientUID(p.ClientUID, s.unitUID); e != nil {
		return e
	}
	// Which unit this instance runs in: core, or broad for a policy that uses
	// the broad unit (a broad instance for any other policy is a stale unit).
	u, err := selfcheck.Unit(o.Unit)
	if err != nil {
		return err
	}
	if u == policy.UnitBroad && !p.UsesBroad() {
		return &selfcheck.Error{Check: selfcheck.CheckUnit, Detail: "this is the broad unit, but the policy uses no broad unit (no packages, unit: broad command or power); remove the broad units"}
	}
	if u == policy.UnitCore {
		err = selfcheck.Capabilities(&st, p.Capabilities)
	} else {
		err = selfcheck.BroadCapabilities(&st, p.BroadProtectClock())
	}
	if err != nil {
		return err
	}
	s.unit = u
	s.p = p
	return nil
}

// policyError is a failed policy load; err is the loader's error, from
// which the wire message takes only field names.
type policyError struct {
	check *selfcheck.Error
	err   error
}

func (e *policyError) Error() string   { return e.check.Error() }
func (e *policyError) Unwrap() []error { return []error{e.check, e.err} }

// fieldRE is a policy field path as the validator names it
// ("paths.write[0]", "commands[2].path"): schema keys and indexes only,
// never a value from the policy.
var fieldRE = regexp.MustCompile(`^[a-z_]{1,32}(\[[0-9]{1,4}\])?(\.[a-z_]{1,32}(\[[0-9]{1,4}\])?){0,3}$`)

// selfCheckFailure maps a failed self-check to its code and a one-line
// message for the authenticated gate. Messages are fixed text: they name
// the failed check and at most schema field names of the policy, never a
// local path, a value from the root-only policy, or a parser's message
// (which could quote the file). The journal line has the full detail.
func selfCheckFailure(err error) (code, msg string) {
	const hint = "; see the helper's journal and run shell-mcp-privd check-policy on the host"
	check := "internal"
	var se *selfcheck.Error
	if errors.As(err, &se) {
		check = se.Check
	}
	switch check {
	case selfcheck.CheckUID:
		return protocol.CodeHelperInstallInsecure, "the privileged helper is not running as root under its generated unit" + hint
	case selfcheck.CheckNoNewPrivs:
		return protocol.CodeHelperInstallInsecure, "the privileged helper is running without NoNewPrivs, outside its generated unit" + hint
	case selfcheck.CheckBinary:
		return protocol.CodeHelperInstallInsecure, "the privileged helper's binary is not a root-owned, not group/other-writable CGO_ENABLED=0 build" + hint
	case selfcheck.CheckPolicyFile:
		return protocol.CodeHelperInstallInsecure, "the privileged policy is missing, unreadable, or not root-owned and private" + hint
	case selfcheck.CheckPolicy:
		return protocol.CodeHelperPolicyInvalid, policyInvalidMessage(err) + hint
	case selfcheck.CheckPolicyHash:
		return protocol.CodeHelperPolicyMismatch, "the privileged policy changed after the units were generated; regenerate and reinstall them (shell-mcp-privd units)"
	case selfcheck.CheckClientUID:
		return protocol.CodeHelperClientUIDMismatch, "the unit's client uid is not the privileged policy's client_uid; regenerate and reinstall the units (shell-mcp-privd units)"
	case selfcheck.CheckUnit:
		return protocol.CodeHelperInstallInsecure, "the unit does not say which sandbox it is (SHELL_MCP_PRIVD_UNIT), or is a broad unit for a policy that uses none; regenerate and reinstall the units (shell-mcp-privd units)"
	case selfcheck.CheckCapabilities:
		return protocol.CodeHelperCapabilitiesBroad, "the privileged helper's capability bounding set is broader than its unit declares; reinstall the generated units"
	}
	return protocol.CodeInternal, "the privileged helper failed a self-check" + hint
}

// policyInvalidMessage names where a policy failed validation: the first
// failing field and how many problems there are, or that it did not parse.
func policyInvalidMessage(err error) string {
	var fields []string
	var walk func(error)
	walk = func(e error) {
		switch x := e.(type) { //nolint:errorlint // walking the loader's joined errors one level at a time
		case *policy.Error:
			fields = append(fields, x.Field)
		case interface{ Unwrap() []error }:
			for _, c := range x.Unwrap() {
				walk(c)
			}
		}
	}
	var pe *policyError
	if errors.As(err, &pe) {
		walk(pe.err)
	}
	switch {
	case len(fields) == 0 || fields[0] == "":
		return "the privileged policy cannot be parsed (YAML syntax, an unknown or duplicate key, or its size)"
	case !fieldRE.MatchString(fields[0]):
		return fmt.Sprintf("the privileged policy fails validation (%d problem(s))", len(fields))
	case len(fields) == 1:
		return "the privileged policy fails validation at " + fields[0]
	}
	return fmt.Sprintf("the privileged policy fails validation at %s and %d more", fields[0], len(fields)-1)
}

// sandbox is PRIVILEGED §7 step 3 (D-019 for the helper): Landlock is in
// place before any byte of the request is read. A failure is a
// *selfcheck.Error for the "landlock" check.
func (s *server) sandbox() error {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	if s.unit != policy.UnitCore {
		// The broad unit has no Landlock sandbox: package managers write
		// anywhere and broad commands need the network (PRIVILEGED §5.2, §7).
		return nil
	}
	if _, err := s.o.ApplySandbox(s.p, s.o.BackupDir); err != nil {
		return &selfcheck.Error{Check: selfcheck.CheckLandlock, Detail: err.Error()}
	}
	return nil
}

// run reads one request and dispatches it. Every outcome from here on is a
// response carrying the request's id: the peer is authenticated and the
// sandbox applied.
func (s *server) run(nc net.Conn) *protocol.Response {
	o, p := s.o, s.p
	s.red = redact.New(nil)
	s.store = &store{dir: o.BackupDir, trust: o.Trust, keep: p.BackupsKeep, max: p.BackupsMaxStoreBytes, now: o.Now}
	modesMax := p.ModesMax
	cfg := &fsx.Config{
		ReadRoots:  p.Paths.Read,
		WriteRoots: p.Paths.WriteRoots(),
		Deny:       p.Paths.Deny,
		// The policy's deny matcher starts with the built-in list (parse.go).
		BuiltinDeny: len(gpolicy.BuiltinDeny()),
		Protected:   p.Paths.Protected,
		Limits: fsx.Limits{
			MaxReadBytes:     p.Limits.MaxReadBytes,
			MaxWriteBytes:    p.Limits.MaxWriteBytes,
			MaxFindResults:   1000,
			MaxFindDepth:     8,
			MaxDeleteEntries: p.Limits.MaxDeleteEntries,
		},
		// Every new inode within modes.max, and chmod and chown read back
		// (PRIVILEGED §4, §6).
		ModesMax:       &modesMax,
		VerifyMetadata: true,
		// Every replace is an exchange checked afterwards, so a destination
		// changed after it was checked is never lost (S4c-2).
		VerifyReplaced: true,
		// chmod and chown change an entry only when no account but root
		// could have put it there (handoff N-1, PRIVILEGED §6).
		TrustedDirOwner: o.Trust.Owns,
		// A file another account could have moved in is read, and
		// overwritten keeping its owner, only when that account could have
		// read or written it itself (handoff N-6, N-7, PRIVILEGED §6).
		GuardMovedIn: true,
		// Every new inode gets both ids set, so a setgid parent never
		// chooses its group (handoff N-8, PRIVILEGED §6).
		ExplicitOwner: true,
		// A root command is given a path (a placeholder, its cwd) only when
		// no account but root can change what it names before the command
		// looks it up itself (handoff N-10, PRIVILEGED §6).
		GuardExecPaths:              true,
		InjectBeforeBackup:          o.InjectBeforeBackup,
		InjectExchangeFault:         o.InjectExchangeFault,
		InjectReadBackFault:         o.InjectReadBackFault,
		InjectBeforeCommit:          o.InjectBeforeCommit,
		InjectNoReplaceFault:        o.InjectNoReplaceFault,
		InjectMetadataReadBackFault: o.InjectMetadataReadBackFault,
		InjectDeleteStep:            o.InjectDeleteStep,
		InjectStopAfterSetAside:     o.InjectStopAfterSetAside,
	}
	if p.BackupsKeep > 0 {
		cfg.Backup = s.backup
	}
	if !o.DisableCommitReport {
		cfg.OnCommit = func() { s.committed = true }
	}
	s.fs = fsx.New(cfg)
	rc := *cfg
	rc.Limits.MaxWriteBytes = maxBackupBytes // a restore writes what was backed up
	s.restoreFS = fsx.New(&rc)

	_ = nc.SetReadDeadline(time.Now().Add(readDeadline))
	req, err := protocol.DecodeRequest(nc)
	if err != nil {
		var de *protocol.DecodeError
		if errors.As(err, &de) {
			return failure(de.Code, de.Msg)
		}
		return failure(protocol.CodeBadRequest, "request could not be decoded")
	}
	s.req, s.conn = req, nc
	return s.dispatch()
}

// timeout is the request's timeout, defaulted and clamped by the policy.
func (s *server) timeout() time.Duration {
	d := time.Duration(s.req.TimeoutMS) * time.Millisecond
	if d <= 0 {
		d = time.Duration(s.p.Limits.DefaultTimeoutS) * time.Second
	}
	if maxD := time.Duration(s.p.Limits.MaxTimeoutS) * time.Second; d > maxD {
		d = maxD
	}
	return d
}

func failure(code, msg string) *protocol.Response {
	return &protocol.Response{V: protocol.Version, Error: &protocol.Error{Code: code, Message: msg}}
}

// writeResponse writes resp; one over 4 MiB is replaced by too_large. It
// returns 0 if a response was written, 1 otherwise.
func writeResponse(w io.Writer, resp *protocol.Response) int {
	err := protocol.EncodeResponse(w, resp)
	if errors.Is(err, protocol.ErrResponseTooLarge) {
		small := &protocol.Response{V: protocol.Version, ID: resp.ID, Gate: resp.Gate,
			Error: &protocol.Error{Code: protocol.CodeTooLarge, Message: "response exceeds 4 MiB; request less data"}}
		err = protocol.EncodeResponse(w, small)
	}
	if err != nil {
		return 1
	}
	return 0
}
