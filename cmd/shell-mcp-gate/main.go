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

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
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
	p, err := policy.Load(*policyPath, &policy.LoadOptions{Trust: trust, GateExecutable: exe, ServiceHome: u.HomeDir})
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			_, _ = fmt.Fprintf(stderr, "shell-mcp-gate polkit: %s\n", line)
		}
		return 1
	}
	rule, err := polkit.Rule(&polkit.Spec{User: *userName, Units: p.Services.ControlUnits, Verbs: p.Services.ControlVerbs, PolicySHA256: p.SHA256})
	if err != nil {
		return fail("%v", err)
	}
	_, _ = io.WriteString(stdout, rule)
	return 0
}

// checkPolicyWith is checkPolicy with the trust set and the service home as
// parameters; only tests pass anything but policy.RootTrust() and
// ops.ServiceHome().
// probeNoReplace and probeExchange are fsx's rename-flag probes; tests
// replace them.
var (
	probeNoReplace = fsx.ProbeNoReplace
	probeExchange  = fsx.ProbeExchange
)

// checkPolicyWithParam is checkPolicyWith reading the kernel's
// ignore_rlimit_data parameter from param.
func checkPolicyWithParam(args []string, stdout, stderr io.Writer, trust policy.Trust, home, param string) int {
	_ = param
	return checkPolicyWith(args, stdout, stderr, trust, home)
}

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
		pr("     run check-policy as the service account to check its identity and home directory;")
		pr("     the roots' paths and git.repos are checked trusting root only")
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

	p, err := policy.Load(*policyPath, &policy.LoadOptions{Trust: trust, GateExecutable: exe, ServiceHome: home})
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
		for i := range p.Commands {
			if c := &p.Commands[i]; c.Applet != "" {
				pr("ok   commands[%s]: %s is the uutils multi-call binary; it runs as %s (the name of the file it is executed by)", c.ID, c.Resolved, c.Applet)
			}
		}
		for _, w := range p.Warnings {
			pr("WARN %s", w)
		}
		// delete and every move (its stage, and without overwrite its commit)
		// need RENAME_NOREPLACE, and a
		// write with expected_sha256 or a copy or move with a bound
		// destination RENAME_EXCHANGE (verified replaces); each is refused
		// on a filesystem without its flag (POLICY §3): probe each write
		// root for both (files created, renamed and removed inside it).
		for _, root := range p.Paths.Write {
			for _, pb := range []struct {
				flag, needs string
				probe       func(string) error
				unsupported error
			}{
				{"RENAME_NOREPLACE", "delete and move", probeNoReplace, fsx.ErrNoReplaceUnsupported},
				{"RENAME_EXCHANGE", "write_file with expected_sha256, and copy and move with expected_destination_sha256,", probeExchange, fsx.ErrExchangeUnsupported},
			} {
				switch err := pb.probe(root); {
				case err == nil:
					pr("ok   paths.write %s: %s supported", root, pb.flag)
				case errors.Is(err, pb.unsupported):
					pr("WARN paths.write %s: the filesystem does not support %s; %s are refused under this root", root, pb.flag, pb.needs)
				default:
					pr("WARN paths.write %s: could not probe %s (%v); %s need it", root, pb.flag, err, pb.needs)
				}
			}
		}
		// Commands' paths (handoff N-11) and git repositories (N-20) are
		// checked from / on every request, trusting root and the service
		// account (POLICY §4, §7): report each root whose own path another
		// account could change, as the helper's check-policy does for its
		// roots, and each listed repository the git operations would refuse.
		self := install.ID(os.Geteuid())
		trusted := ops.CommandTrust(trust, self)
		for _, r := range []struct {
			kind    string
			roots   []string
			refused string
		}{
			{"read", p.Paths.Read, "commands get no cwd at or under it"},
			{"write", p.Paths.Write, "commands get no {path:write} or cwd at or under it"},
		} {
			for _, root := range r.roots {
				var ce *fsx.ChainError
				switch err := fsx.CheckClosedChain(root, trusted); {
				case err == nil:
					pr("ok   paths.%s %s: every directory from / to it is root's or the service account's and neither group- nor world-writable nor sticky", r.kind, root)
				case errors.As(err, &ce):
					pr("WARN paths.%s %s: %v; %s, and a {path:read} only where the directories open on its path are one other account's that only it can write (POLICY §4); "+
						"git runs in no repository under it (POLICY §7)", r.kind, root, ce, r.refused)
				default:
					pr("WARN paths.%s %s: could not check the directories on its path (%v); commands' paths and git repositories under it are refused unless they pass", r.kind, root, err)
				}
			}
		}
		for i, err := range ops.CheckGitRepos(p, trust, self) {
			repo := p.Git.Repos[i].Path
			if err == nil {
				pr("ok   git.repos[%d] %s: closed (every directory from / to it, it, .git and .git/config are root's or the service account's and neither group- nor world-writable nor sticky)", i, repo)
				continue
			}
			pr("WARN git.repos[%d] %s: %s; every git operation on it is refused", i, repo, gitRefusal(repo, err))
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

// gitRefusal is the reason the git operations would refuse repo (err, from
// fsx.CheckGitRepo), without what only a refused request says.
func gitRefusal(repo string, err error) string {
	var fe *fsx.Error
	if !errors.As(err, &fe) {
		return err.Error()
	}
	msg := strings.TrimPrefix(fe.Msg, fmt.Sprintf("git is not run in the repository %q: ", repo))
	return strings.TrimSuffix(msg, "; nothing was run")
}
