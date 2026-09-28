//go:build linux

// Command shell-mcp-gate is the SSH forced command on each target. It enforces
// the host's root-owned gate policy: install checks, strict policy, a
// Landlock + no_new_privs sandbox applied before the request is read, then
// one request and one response.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/polkit"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Set with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "dev"
)

const usage = `usage: shell-mcp-gate <command> [flags]

commands:
  serve --policy <file> [--principal <label>]
                serve one request (the SSH forced command)
  check-policy --policy <file>
                check the install, the policy and the sandbox on this host
  polkit --policy <file> --user <name>
                print the polkit rule for the policy's services.control
  version       print version information
`

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWith(args, stdin, stdout, stderr, ops.ProductionOptions)
}

// optionsFunc builds the gate's options; production uses
// ops.ProductionOptions. There is no flag or environment variable that
// changes trust or identity.
type optionsFunc func(version, policyPath, principal string) (ops.Options, error)

func runWith(args []string, stdin io.Reader, stdout, stderr io.Writer, mk optionsFunc) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stdin, stdout, mk)
	case "check-policy":
		return checkPolicy(args[1:], stdout, stderr)
	case "polkit":
		return polkitWith(args[1:], stdout, stderr, policy.RootTrust())
	case "version":
		_, _ = fmt.Fprintf(stdout, "shell-mcp-gate %s (commit %s, %s)\n", version, commit, runtime.Version())
		return 0
	case "-h", "--help", "help":
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "shell-mcp-gate: unknown command %q\n%s", args[0], usage)
	return 2
}

// builtWithCGO reports whether this binary was built with cgo. The gate
// must be CGO_ENABLED=0: psx then applies no_new_privs and Landlock through
// syscall.AllThreadsSyscall, and no C code runs in the gate.
func builtWithCGO() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return true // unknown: fail closed
	}
	for _, s := range bi.Settings {
		if s.Key == "CGO_ENABLED" {
			return s.Value != "0"
		}
	}
	return true
}

// serve is the forced command. Every outcome is one JSON response on
// stdout; stderr stays empty. It exits non-zero only if no response could
// be written.
func serve(args []string, stdin io.Reader, stdout io.Writer, mk optionsFunc) int {
	fail := func(msg string) int {
		r := ops.Failure("", protocol.CodeInstallInsecure, msg)
		r.Gate = &protocol.GateInfo{Version: version}
		return ops.WriteResponse(stdout, r)
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	principal := fs.String("principal", "default", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || fs.NArg() != 0 {
		return fail("gate forced command is malformed (want: serve --policy <file> [--principal <label>])")
	}
	if builtWithCGO() {
		return fail("gate binary was built with cgo; rebuild with CGO_ENABLED=0")
	}
	o, err := mk(version, *policyPath, *principal)
	if err != nil {
		return fail("gate cannot determine its own identity")
	}
	return ops.Serve(&o, stdin, stdout)
}

// checkPolicy runs the install checks and the policy validation as the
// forced command would, and reports what the sandbox would enforce on this
// kernel without applying it. Findings go to stdout; the exit code is 1 if
// anything would make serve refuse.
func checkPolicy(args []string, stdout, stderr io.Writer) int {
	return checkPolicyWith(args, stdout, stderr, policy.RootTrust(), ops.ServiceHome())
}

// polkitWith prints the polkit rule (POLICY §4b) for the policy's
// services.control units and verbs, for the service account --user. The
// policy is loaded and validated exactly as serve would, with the account's
// home directory in the protected set. Only tests pass a trust set other
// than policy.RootTrust().
func polkitWith(args []string, stdout, stderr io.Writer, trust policy.Trust) int {
	fs := flag.NewFlagSet("polkit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	userName := fs.String("user", "", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || *userName == "" || fs.NArg() != 0 {
		_, _ = io.WriteString(stderr, "usage: shell-mcp-gate polkit --policy <file> --user <name>\n")
		return 2
	}
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "shell-mcp-gate polkit: "+format+"\n", a...)
		return 1
	}
	u, err := user.Lookup(*userName)
	if err != nil {
		return fail("user %q is not in the user database; create the service account first", *userName)
	}
	if u.Uid == "0" {
		return fail("user %q is root; the rule is for the gate's service account", *userName)
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fail("cannot resolve own path: %v", err)
	}
	p, err := policy.Load(*policyPath, policy.LoadOptions{Trust: trust, GateExecutable: exe, ServiceHome: u.HomeDir})
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			_, _ = fmt.Fprintf(stderr, "shell-mcp-gate polkit: %s\n", line)
		}
		return 1
	}
	rule, err := polkit.Rule(polkit.Spec{User: *userName, Units: p.Services.ControlUnits, Verbs: p.Services.ControlVerbs, PolicySHA256: p.SHA256})
	if err != nil {
		return fail("%v", err)
	}
	_, _ = io.WriteString(stdout, rule)
	return 0
}

// checkPolicyWith is checkPolicy with the trust set and the service home as
// parameters; only tests pass anything but policy.RootTrust() and
// ops.ServiceHome().
func checkPolicyWith(args []string, stdout, stderr io.Writer, trust policy.Trust, home string) int {
	fs := flag.NewFlagSet("check-policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || fs.NArg() != 0 {
		_, _ = io.WriteString(stderr, "usage: shell-mcp-gate check-policy --policy <file>\n")
		return 2
	}
	pr := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	failures := 0
	failf := func(format string, a ...any) {
		failures++
		pr("FAIL "+format, a...)
	}

	pr("shell-mcp-gate %s check-policy %s", version, *policyPath)
	if builtWithCGO() {
		failf("binary: built with cgo; serve refuses (rebuild with CGO_ENABLED=0)")
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		failf("binary: cannot resolve own path: %v", err)
	}
	id, err := install.Current()
	switch {
	case err != nil:
		failf("install: cannot read own identity: %v", err)
	case id.UID == 0:
		pr("NOTE install: running as root, so the uid and group checks describe root, not the service account;")
		pr("     run check-policy as the service account to check its identity and home directory")
		if _, err = policy.CheckChain(policy.RootTrust(), exe); err != nil {
			failf("install: gate binary: %v", err)
		}
	default:
		if err = install.Check(&install.Env{Identity: id, Trust: policy.RootTrust(), Executable: exe}); err != nil {
			failf("install: %v", err)
		} else {
			pr("ok   install: uid, groups and gate binary")
		}
	}
	pr("     service home used for the protected set: %q", home)

	p, err := policy.Load(*policyPath, policy.LoadOptions{Trust: trust, GateExecutable: exe, ServiceHome: home})
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			failf("%s", line)
		}
		var oe *policy.OwnershipError
		if errors.As(err, &oe) {
			pr("     the policy, its directories, the gate binary and command binaries must be owned by root and not group/other-writable")
		}
	} else {
		pr("ok   policy: sha256 %s, max_tier %s, %d commands", p.SHA256, p.MaxTier, len(p.Commands))
		for _, w := range p.Warnings {
			pr("WARN %s", w)
		}
	}

	abi := sandbox.KernelABI()
	if p != nil {
		rep, perr := sandbox.Plan(p, abi)
		pr("     sandbox: mode %s, kernel Landlock ABI %d (effective %d), required needs %d", rep.Mode, abi, rep.EffectiveABI, rep.RequiredMinABI)
		pr("     sandbox: enforced fs=%v net=%v unix_socket=%v scope=%v; unix sockets: %s",
			rep.Enforced.FS, rep.Enforced.Net, rep.Enforced.UnixSocket, rep.Enforced.Scope, rep.UnixSocketControl)
		pr("     sandbox: MPTCP %s (Landlock does not govern MPTCP sockets)", rep.MPTCP)
		if perr != nil {
			failf("sandbox: %v", perr)
		} else if len(rep.NotEnforced) > 0 {
			pr("WARN sandbox: not enforced on this kernel: %s", strings.Join(rep.NotEnforced, ", "))
		}
		if b, err := protocol.Marshal(ops.PolicySummary(p)); err == nil {
			pr("effective policy: %s", b)
		}
	} else {
		pr("     sandbox: kernel Landlock ABI %d; required needs %d", abi, sandbox.RequiredMinABI)
	}
	if failures > 0 {
		pr("%d problem(s): serve would refuse with install_insecure or sandbox_unavailable", failures)
		return 1
	}
	pr("ok: serve would accept this install and policy")
	return 0
}
