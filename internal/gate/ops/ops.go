//go:build linux

// Package ops is the gate's serve pipeline and dispatcher (docs/ARCHITECTURE.md
// §3 step 4, §4): install checks → policy load → sandbox → read one request
// → tier check → op-specific validation → run → redact → respond.
package ops

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// Options configures one gate run. ProductionOptions fills it from the
// running process; nothing in it comes from the request or the forced
// command line except PolicyPath and Principal.
type Options struct {
	Version    string
	PolicyPath string
	Principal  string

	Identity           install.Identity
	Trust              policy.Trust
	Executable         string
	SSHOriginalCommand *string
	ServiceHome        string

	// ApplySandbox applies the sandbox (production: sandbox.Apply).
	ApplySandbox func(*policy.Policy) (sandbox.Report, error)
	// InjectReadBackFault is passed to fsx; tests only.
	InjectReadBackFault func([]byte) []byte
}

// ProductionOptions describes the running process: its real identity, its
// resolved executable, SSH_ORIGINAL_COMMAND, the service account's home,
// root-only trust and the real sandbox.
func ProductionOptions(version, policyPath, principal string) (Options, error) {
	id, err := install.Current()
	if err != nil {
		return Options{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return Options{}, fmt.Errorf("executable: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return Options{}, fmt.Errorf("executable: %w", err)
	}
	o := Options{
		Version: version, PolicyPath: policyPath, Principal: principal,
		Identity: id, Trust: policy.RootTrust(), Executable: exe,
		ServiceHome: ServiceHome(), ApplySandbox: sandbox.Apply,
	}
	if v, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		o.SSHOriginalCommand = &v
	}
	return o, nil
}

// ServiceHome returns the running user's home directory from the user
// database, or "" if it is unknown or not an absolute clean path.
func ServiceHome() string {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || pathx.CheckClean(u.HomeDir) != nil {
		return ""
	}
	return u.HomeDir
}

// principalRE is the --principal label format.
var principalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

// ValidPrincipal reports whether a --principal label is well formed.
func ValidPrincipal(s string) bool { return principalRE.MatchString(s) }

// server holds one request's state.
type server struct {
	o      Options
	gate   *protocol.GateInfo
	p      *policy.Policy
	fs     *fsx.FS
	red    *redact.Redactor
	report sandbox.Report
	req    *protocol.Request
}

// Serve runs the gate for one request: install checks, policy load,
// sandbox, then (only then) read one request, dispatch, and write one
// response. It returns the process exit code: 0 whenever a response was
// written, 1 if it could not be.
func Serve(o *Options, stdin io.Reader, stdout io.Writer) int {
	start := time.Now()
	s := &server{o: *o, gate: &protocol.GateInfo{Version: o.Version, Principal: o.Principal}}
	resp := s.run(stdin)
	resp.V = protocol.Version
	s.gate.DurationMS = time.Since(start).Milliseconds()
	resp.Gate = s.gate
	return WriteResponse(stdout, resp)
}

// WriteResponse writes resp; a response over 4 MiB is replaced by a
// too_large error. It returns 0 if a response was written, 1 otherwise.
func WriteResponse(w io.Writer, resp *protocol.Response) int {
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

// Failure builds an error response.
func Failure(id, code, msg string) *protocol.Response {
	return &protocol.Response{V: protocol.Version, ID: id, Error: &protocol.Error{Code: code, Message: msg}}
}

func (s *server) run(stdin io.Reader) *protocol.Response {
	o := s.o
	if !ValidPrincipal(o.Principal) {
		s.gate.Principal = ""
		return Failure("", protocol.CodeInstallInsecure, "gate --principal label is malformed")
	}
	if err := install.Check(&install.Env{Identity: o.Identity, Trust: o.Trust, Executable: o.Executable, SSHOriginalCommand: o.SSHOriginalCommand}); err != nil {
		msg := "gate installation is insecure"
		var ie *install.Error
		if errors.As(err, &ie) {
			msg = ie.Wire
		}
		return Failure("", protocol.CodeInstallInsecure, msg)
	}
	p, err := policy.Load(o.PolicyPath, policy.LoadOptions{Trust: o.Trust, GateExecutable: o.Executable, ServiceHome: o.ServiceHome})
	if err != nil {
		return Failure("", protocol.CodeInstallInsecure, "gate policy is missing, insecure or invalid (run shell-mcp-gate check-policy on the host)")
	}
	s.p = p
	s.gate.PolicySHA256 = p.SHA256
	s.gate.MaxTier = p.MaxTier.String()

	// The gate itself never dumps core; children get their own limits.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})

	// D-019: the sandbox is in place before any untrusted byte is read.
	rep, err := o.ApplySandbox(p)
	if err != nil {
		return Failure("", protocol.CodeSandboxUnavailable, fmt.Sprintf(
			"Landlock sandbox could not be applied (kernel ABI %d; this policy needs %d with landlock: required); run shell-mcp-gate check-policy on the host",
			rep.KernelABI, sandbox.RequiredMinABI))
	}
	s.report = rep
	s.fs = fsx.New(&fsx.Config{
		ReadRoots:  p.Paths.Read,
		WriteRoots: p.Paths.Write,
		Deny:       p.Paths.Deny,
		Protected:  p.Paths.Protected,
		Limits: fsx.Limits{
			MaxReadBytes:     p.Limits.MaxReadBytes,
			MaxWriteBytes:    p.Limits.MaxWriteBytes,
			MaxFindResults:   p.Limits.MaxFindResults,
			MaxFindDepth:     p.Limits.MaxFindDepth,
			MaxDeleteEntries: p.Limits.MaxDeleteEntries,
		},
		InjectReadBackFault: o.InjectReadBackFault,
	})
	s.red = redact.New(p.Redact)

	req, err := protocol.DecodeRequest(stdin)
	if err != nil {
		var de *protocol.DecodeError
		if errors.As(err, &de) {
			return Failure("", de.Code, de.Msg)
		}
		return Failure("", protocol.CodeBadRequest, "request could not be decoded")
	}
	s.req = req
	resp := s.dispatch()
	resp.ID = req.ID
	return resp
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
