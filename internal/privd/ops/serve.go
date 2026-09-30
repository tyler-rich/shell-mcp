//go:build linux

// Package ops is the privileged helper's serve pipeline (docs/PRIVILEGED.md
// §3, §6, §7, §8; ARCHITECTURE §3 step 5): self-checks → policy → peer
// credentials → Landlock → read one request → tier → op against the
// privileged policy → backup → execute → verify → respond → audit.
//
// Nothing is ever written to a peer that has not passed every self-check
// and the SO_PEERCRED check: a refusal closes the connection without a
// byte and leaves one WARN line in the journal.
package ops

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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
	Trust          gpolicy.Trust
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

// ProductionOptions describes the running process: its resolved
// executable, the unit's policy hash, root-only trust, the local user and
// group databases, /proc/self/status, stdin as the connection, the fixed
// backup store, the helper's Landlock ruleset and stderr for the audit.
func ProductionOptions(version, policyPath string) (Options, error) {
	exe, err := os.Executable()
	if err != nil {
		return Options{}, fmt.Errorf("executable: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return Options{}, fmt.Errorf("executable: %w", err)
	}
	return Options{
		Version: version, PolicyPath: policyPath, Executable: exe,
		ExpectedSHA256: os.Getenv(units.HashEnv),
		Trust:          gpolicy.RootTrust(),
		Lookups:        policy.ProductionLookups,
		ReadStatus:     func() ([]byte, error) { return os.ReadFile("/proc/self/status") },
		Conn:           os.Stdin,
		BackupDir:      units.BackupDir,
		ApplySandbox:   ApplyLandlock,
		Audit:          os.Stderr,
		Now:            time.Now,
	}, nil
}

// server holds one connection's state.
type server struct {
	o         *Options
	start     time.Time
	p         *policy.Policy
	cred      peercred.Cred
	fs        *fsx.FS
	restoreFS *fsx.FS
	red       *redact.Redactor
	store     *store
	req       *protocol.Request
	// backupIDs are the backups written for this request.
	backupIDs []string
}

// Serve handles one connection and returns the process exit code: 0 when a
// response was written, 1 otherwise (including every refusal, which closes
// the connection without a response).
func Serve(o *Options) int {
	s := &server{o: o, start: time.Now()}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := s.checks(); err != nil {
		s.auditRefusal(err)
		return 1
	}
	// A duplicate of the connection with deadlines, made before the
	// sandbox (it needs no filesystem access, but nothing else should
	// happen after it).
	nc, err := net.FileConn(o.Conn)
	if err != nil {
		s.auditRefusal(&selfcheck.Error{Check: selfcheck.CheckStdin, Detail: "connection cannot be used: " + err.Error()})
		return 1
	}
	defer func() { _ = nc.Close() }()

	resp := s.run(nc)
	resp.V = protocol.Version
	if s.req != nil {
		resp.ID = s.req.ID
	}
	resp.Gate = &protocol.GateInfo{Version: o.Version, Principal: "shell-mcp-privd", PolicySHA256: s.p.SHA256,
		MaxTier: s.p.MaxTier.String(), DurationMS: time.Since(s.start).Milliseconds()}
	_ = nc.SetWriteDeadline(time.Now().Add(writeDeadline))
	code := writeResponse(nc, resp)
	s.auditRequest(resp)
	return code
}

// checks runs PRIVILEGED §7 in order; each failure is a *selfcheck.Error.
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
	if o.Conn == nil {
		return &selfcheck.Error{Check: selfcheck.CheckStdin, Detail: "no connection"}
	}
	fd := int(o.Conn.Fd())
	if e := selfcheck.Stdin(fd); e != nil {
		return e
	}
	if e := selfcheck.Binary(o.Trust, o.Executable); e != nil {
		return e
	}
	lo := &policy.LoadOptions{Trust: o.Trust, HelperExecutable: o.Executable, SystemBinDirs: o.SystemBinDirs}
	o.Lookups(lo)
	p, err := policy.Load(o.PolicyPath, lo)
	if err != nil {
		return &selfcheck.Error{Check: selfcheck.CheckPolicy, Detail: err.Error()}
	}
	if e := selfcheck.Hash(p.SHA256, o.ExpectedSHA256); e != nil {
		return e
	}
	if e := selfcheck.Capabilities(&st, p.Capabilities); e != nil {
		return e
	}
	cred, err := peercred.Authenticate(fd, p.ClientUID)
	s.cred = cred
	switch {
	case errors.Is(err, peercred.ErrWrongPeer):
		return &selfcheck.Error{Check: selfcheck.CheckPeer, Detail: fmt.Sprintf("peer uid %d is not client_uid %d", cred.UID, p.ClientUID)}
	case err != nil:
		return &selfcheck.Error{Check: selfcheck.CheckPeer, Detail: err.Error()}
	}
	s.p = p
	return nil
}

// run applies the sandbox, reads one request and dispatches it. Every
// outcome from here on is a response: the peer is authenticated.
func (s *server) run(nc net.Conn) *protocol.Response {
	o, p := s.o, s.p
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	// D-019 for the helper: Landlock is in place before any byte of the
	// request is read.
	if _, err := o.ApplySandbox(p, o.BackupDir); err != nil {
		return failure(protocol.CodeSandboxUnavailable, "the privileged helper's Landlock sandbox could not be applied under sandbox.landlock: required; run shell-mcp-privd check-policy on the host")
	}
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
