//go:build linux

// Command shell-mcp-privd is the socket-activated privileged helper on each
// target (docs/PRIVILEGED.md). systemd starts one instance per connection
// (Accept=yes) inside the generated core unit; it authenticates the gate by
// SO_PEERCRED, validates one request against its own root-owned policy,
// backs up what it changes, answers and exits. It also generates its units
// and checks its policy for the host administrator.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// Set with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "dev"
)

const usage = `usage: shell-mcp-privd <command> [flags]

commands:
  serve --policy <file>
                serve one request (started by systemd only, in its generated unit)
  check-policy --policy <file>
                validate a privileged policy and report everything that needs review
  units --policy <file> [--out <dir>]
                write shell-mcp-privd.socket and shell-mcp-privd@.service for the policy
  version       print version information
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// loadEnv is what loading a policy needs from this host. Production uses
// root-only trust, the running binary and the local user and group
// databases; only tests pass anything else.
type loadEnv struct {
	trust         gpolicy.Trust
	executable    string
	systemBinDirs []string
	lookups       func(*policy.LoadOptions)
}

func productionEnv() (*loadEnv, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve own path: %w", err)
	}
	return &loadEnv{trust: gpolicy.RootTrust(), executable: exe, lookups: policy.ProductionLookups}, nil
}

func (e *loadEnv) load(file string) (*policy.Policy, error) {
	lo := &policy.LoadOptions{Trust: e.trust, HelperExecutable: e.executable, SystemBinDirs: e.systemBinDirs}
	e.lookups(lo)
	return policy.Load(file, lo)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr)
	case "check-policy", "units":
		env, err := productionEnv()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "shell-mcp-privd %s: %v\n", args[0], err)
			return 1
		}
		if args[0] == "units" {
			return unitsWith(args[1:], stdout, stderr, env)
		}
		return checkPolicyWith(args[1:], stdout, stderr, env)
	case "version":
		_, _ = fmt.Fprintf(stdout, "shell-mcp-privd %s (commit %s, %s)\n", version, commit, runtime.Version())
		return 0
	case "-h", "--help", "help":
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "shell-mcp-privd: unknown command %q\n%s", args[0], usage)
	return 2
}

// builtWithCGO reports whether this binary was built with cgo. The helper,
// like the gate, must be CGO_ENABLED=0: psx then applies no_new_privs and
// Landlock through syscall.AllThreadsSyscall.
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

// refuse writes one WARN journal line (stderr) and nothing to stdout,
// which under the unit is the connection.
func refuse(stderr io.Writer, check, detail string) int {
	_, _ = fmt.Fprintf(stderr, "<4>{\"outcome\":\"refused\",\"check\":%q,\"detail\":%q}\n", check, detail)
	return 1
}

// serve is the unit's ExecStart. Stdout is the connection: nothing but the
// response is ever written to it, and a refusal writes nothing at all.
func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || fs.NArg() != 0 {
		return refuse(stderr, "arguments", "ExecStart is malformed (want: serve --policy <file>)")
	}
	if builtWithCGO() {
		return refuse(stderr, "binary", "the helper was built with cgo; rebuild with CGO_ENABLED=0")
	}
	o, err := ops.ProductionOptions(version, *policyPath)
	if err != nil {
		return refuse(stderr, "binary", err.Error())
	}
	o.Audit = stderr
	return ops.Serve(&o)
}

// unitsWith writes the core unit pair for the policy into --out (default
// "."). The policy is loaded and validated exactly as serve would load it.
func unitsWith(args []string, stdout, stderr io.Writer, env *loadEnv) int {
	fs := flag.NewFlagSet("units", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	out := fs.String("out", ".", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || fs.NArg() != 0 {
		_, _ = io.WriteString(stderr, "usage: shell-mcp-privd units --policy <file> [--out <dir>]\n")
		return 2
	}
	p, err := env.load(*policyPath)
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %s\n", line)
		}
		return 1
	}
	f, err := units.Core(p)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %v\n", err)
		return 1
	}
	for _, u := range []struct{ name, content string }{{units.SocketUnit, f.Socket}, {units.ServiceUnit, f.Service}} {
		dst := filepath.Join(*out, u.name)
		if err := os.WriteFile(dst, []byte(u.content), 0o644); err != nil { //nolint:gosec // G306: unit files are root:root 0644 (PRIVILEGED §2)
			_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %v\n", err)
			return 1
		}
		if err := os.Chmod(dst, 0o644); err != nil { //nolint:gosec // G302: unit files are root:root 0644 (PRIVILEGED §2)
			_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s\n", dst)
	}
	pr := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	pr("policy sha256: %s (the helper refuses to serve if the policy changes; regenerate the units after every edit)", p.SHA256)
	if env.executable != units.HelperPath {
		pr("NOTE the units run %s; install this binary there (root:root 0755)", units.HelperPath)
	}
	pr("next, as root: install both files in /etc/systemd/system (root:root 0644); create %s (root:root 0700);", units.BackupDir)
	pr("  systemctl daemon-reload; systemd-analyze verify /etc/systemd/system/%s /etc/systemd/system/%s;", units.SocketUnit, units.ServiceUnit)
	pr("  systemd-analyze security %s; systemctl enable --now %s", units.ServiceUnit, units.SocketUnit)
	return 0
}

// checkPolicyWith validates the policy as serve would and reports every
// item that needs review: list B binaries, persistence roots, capabilities
// added to the core unit, root-equivalent commands, and warnings. The exit
// code is 1 if serve would refuse the policy.
func checkPolicyWith(args []string, stdout, stderr io.Writer, env *loadEnv) int {
	fs := flag.NewFlagSet("check-policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || fs.NArg() != 0 {
		_, _ = io.WriteString(stderr, "usage: shell-mcp-privd check-policy --policy <file>\n")
		return 2
	}
	pr := func(format string, a ...any) { _, _ = fmt.Fprintf(stdout, format+"\n", a...) }
	pr("shell-mcp-privd %s check-policy %s", version, *policyPath)
	failures := 0
	if builtWithCGO() {
		failures++
		pr("FAIL binary: built with cgo; serve refuses (rebuild with CGO_ENABLED=0)")
	}
	p, err := env.load(*policyPath)
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			pr("FAIL %s", line)
		}
		var oe *gpolicy.OwnershipError
		if errors.As(err, &oe) {
			pr("     the policy, its directories and command binaries must be owned by root and not group/other-writable")
		}
		pr("serve would refuse this policy")
		return 1
	}
	if fi, err := os.Stat(*policyPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
		pr("WARN the policy file is mode %04o; make it root:root 0600 (only root reads it, PRIVILEGED §2)", fi.Mode().Perm())
	}
	pr("policy sha256: %s", p.SHA256)
	pr("client_uid: %d   socket_group: %s (gid %d)   max_tier: %s", p.ClientUID, p.SocketGroup, p.SocketGID, p.MaxTier)
	pr("limits: read %d, write %d, output %d bytes; timeout default %ds, max %ds; delete entries %d",
		p.Limits.MaxReadBytes, p.Limits.MaxWriteBytes, p.Limits.MaxOutputBytes, p.Limits.DefaultTimeoutS, p.Limits.MaxTimeoutS, p.Limits.MaxDeleteEntries)
	pr("read roots: %s", strings.Join(p.Paths.Read, " "))
	pr("write roots: %s", strings.Join(p.Paths.Write, " "))
	for _, e := range p.Paths.Persistence {
		pr("persistence root: %s (acknowledge: %q)", e.Path, e.Acknowledge)
	}
	var owners []string
	for _, u := range p.Owners.Users {
		owners = append(owners, fmt.Sprintf("%s(%d)", u.Name, u.ID))
	}
	var groups []string
	for _, g := range p.Owners.Groups {
		groups = append(groups, fmt.Sprintf("%s(%d)", g.Name, g.ID))
	}
	pr("owners: users %s; groups %s", strings.Join(owners, " "), strings.Join(groups, " "))
	pr("modes.max: %04o   backups.keep: %d", uint32(p.ModesMax), p.BackupsKeep)
	pr("core unit capability bounding set: %s", strings.Join(p.Capabilities, " "))
	for i := range p.Commands {
		c := &p.Commands[i]
		extra := ""
		if c.ListB > 0 {
			extra += fmt.Sprintf(" [list B group %d: %q]", c.ListB, c.Acknowledge)
		}
		if len(c.Capabilities) > 0 {
			extra += " [capabilities " + strings.Join(c.Capabilities, " ") + "]"
		}
		if c.RootEquivalent {
			extra += " [root_equivalent]"
		}
		pr("command %s: tier %s, unit %s, %s%s", c.ID, c.Tier, c.Unit, c.Resolved, extra)
	}
	for _, fd := range p.Acknowledged {
		pr("REVIEW %s %s: %s", fd.Kind, fd.Item, fd.Detail)
	}
	for _, w := range p.Warnings {
		pr("WARN %s", w)
	}
	rules := ops.Rules(p, units.BackupDir)
	abi := sandbox.KernelABI()
	rep, perr := sandbox.PlanRules(p.Landlock, &rules, abi)
	pr("sandbox: landlock %s, kernel Landlock ABI %d (effective %d), required needs %d; enforced fs=%v net=%v; network: none granted",
		rep.Mode, abi, rep.EffectiveABI, rep.RequiredMinABI, rep.Enforced.FS, rep.Enforced.Net)
	if perr != nil {
		failures++
		pr("FAIL sandbox: %v", perr)
	}
	if failures > 0 {
		pr("%d problem(s): serve would refuse", failures)
		return 1
	}
	pr("OK: the helper would serve this policy once its units are generated from it (shell-mcp-privd units --policy %s)", *policyPath)
	return 0
}
