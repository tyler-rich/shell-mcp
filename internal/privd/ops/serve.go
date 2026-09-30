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
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
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
	// InjectReadBackFault is passed to fsx; tests only.
	InjectReadBackFault func([]byte) []byte
	// Now is the clock (backup ids and times).
	Now func() time.Time
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
		UnitClientUID:  os.Getenv(units.ClientUIDEnv),
		Unit:           os.Getenv(units.UnitEnv),
		AptGet:         policy.DefaultAptGet,
		ExpectedSHA256: os.Getenv(units.HashEnv),
		Trust:          gpolicy.RootTrust(),
		Lookups:        policy.ProductionLookups,
		ReadStatus:     func() ([]byte, error) { return os.ReadFile("/proc/self/status") },
		Conn:           os.Stdin,
		BackupDir:      units.BackupDir,
		ApplySandbox:   ApplyLandlock,
		Audit:          os.Stderr,
		Now:            time.Now,
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
	code := s.respond(nc, resp)
	s.auditRequest(resp)
	return code
}

// respond writes resp with the helper's gate block; it returns 0 if the
// response was written.
func (s *server) respond(nc net.Conn, resp *protocol.Response) int {
	resp.V = protocol.Version
	resp.Gate = &protocol.GateInfo{Version: s.o.Version, Principal: "shell-mcp-privd", DurationMS: time.Since(s.start).Milliseconds()}
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
	s.store = &store{dir: o.BackupDir, trust: o.Trust, keep: p.BackupsKeep, now: o.Now}
	cfg := &fsx.Config{
		ReadRoots:  p.Paths.Read,
		WriteRoots: p.Paths.WriteRoots(),
		Deny:       p.Paths.Deny,
		Protected:  p.Paths.Protected,
		Limits: fsx.Limits{
			MaxReadBytes:     p.Limits.MaxReadBytes,
			MaxWriteBytes:    p.Limits.MaxWriteBytes,
			MaxFindResults:   1000,
			MaxFindDepth:     8,
			MaxDeleteEntries: p.Limits.MaxDeleteEntries,
		},
		InjectReadBackFault: o.InjectReadBackFault,
	}
	if p.BackupsKeep > 0 {
		cfg.Backup = s.backup
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
	s.req = req
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
