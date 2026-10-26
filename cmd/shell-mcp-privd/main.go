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

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
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
                write shell-mcp-privd.socket and shell-mcp-privd@.service for the policy,
                and the broad unit pair when the policy uses it
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
	// varRun is the path that must resolve to /run (production: /var/run).
	varRun  string
	lookups func(*policy.LoadOptions)
	// ignoreRLimitData is the kernel's ignore_rlimit_data parameter
	// (production: execx.IgnoreRLimitDataPath).
	ignoreRLimitData string
}

func productionEnv() (*loadEnv, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve own path: %w", err)
	}
	return &loadEnv{trust: gpolicy.RootTrust(), executable: exe, lookups: policy.ProductionLookups, varRun: "/var/run",
		ignoreRLimitData: execx.IgnoreRLimitDataPath}, nil
}

// checkVarRun requires e.varRun (/var/run) to resolve to /run. The core unit
// hides /run behind an empty read-only tmpfs (TemporaryFileSystem=/run:ro);
// where /var/run is the usual symlink to /run that hides it too. Anything
// else would leave the sockets under /var/run reachable from the core unit.
func (e *loadEnv) checkVarRun() error {
	if r, err := filepath.EvalSymlinks(e.varRun); err != nil || r != "/run" {
		return fmt.Errorf("/var/run is not a symlink to /run on this host; the core unit hides only /run, so it would leave /var/run's sockets reachable (make /var/run a symlink to /run)")
	}
	return nil
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
		if ops.BypassBuild {
			_, _ = io.WriteString(stdout, "WARNING: end-to-end test build with the helper's own checks bypassed; never deploy it\n")
		}
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
// response is ever written to it, and nothing at all to a peer that fails
// the peer check (PRIVILEGED §7).
func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyPath := fs.String("policy", "", "")
	if err := fs.Parse(args); err != nil || *policyPath == "" || fs.NArg() != 0 {
		return refuse(stderr, "arguments", "ExecStart is malformed (want: serve --policy <file>)")
	}
	// Everything else, the cgo build check and the binary's own path among
	// them, is checked by Serve after the peer is authenticated.
	o := ops.ProductionOptions(version, *policyPath)
	o.BuiltWithCGO = builtWithCGO()
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
	if verr := env.checkVarRun(); verr != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %v\n", verr)
		return 1
	}
	f, err := units.Core(p)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %v\n", err)
		return 1
	}
	files := []struct{ name, content string }{{units.SocketUnit, f.Socket}, {units.ServiceUnit, f.Service}}
	if p.UsesBroad() {
		b, err := units.Broad(p)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "shell-mcp-privd units: %v\n", err)
			return 1
		}
		files = append(files, struct{ name, content string }{units.BroadSocketUnit, b.Socket}, struct{ name, content string }{units.BroadServiceUnit, b.Service})
	}
	for _, u := range files {
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
	if p.UsesBroad() {
		pr("NOTE the broad unit (%s, %s) is root-equivalent by design: network and full root capabilities, for %s", units.BroadSocketUnit, units.BroadServiceUnit, strings.Join(broadUsers(p), ", "))
	} else {
		pr("no broad unit: the policy uses no packages, unit: broad command or power (remove %s and %s if installed)", units.BroadSocketUnit, units.BroadServiceUnit)
	}
	pr("next, as root: install the files in /etc/systemd/system (root:root 0644); create %s (root:root 0700);", units.BackupDir)
	pr("  systemctl daemon-reload; systemd-analyze verify /etc/systemd/system/%s /etc/systemd/system/%s;", units.SocketUnit, units.ServiceUnit)
	pr("  systemd-analyze security %s; systemctl enable --now %s", units.ServiceUnit, units.SocketUnit)
	if p.UsesBroad() {
		pr("  systemd-analyze verify /etc/systemd/system/%s /etc/systemd/system/%s; systemctl enable --now %s", units.BroadSocketUnit, units.BroadServiceUnit, units.BroadSocketUnit)
	}
	return 0
}

// broadUsers names what makes the policy use the broad unit.
func broadUsers(p *policy.Policy) []string {
	var out []string
	if p.Packages.Enabled {
		out = append(out, "packages")
	}
	for i := range p.Commands {
		if p.Commands[i].Unit == policy.UnitBroad {
			out = append(out, "command "+p.Commands[i].ID)
		}
	}
	if len(p.Power.Allowed) > 0 {
		out = append(out, "power ("+strings.Join(p.Power.Allowed, ", ")+")")
	}
	return out
}

// checkPolicyWith validates the policy as serve would and reports every
// item that needs review: list B binaries, persistence roots, capabilities
// added to the core unit, root-equivalent commands, and warnings. The exit
// code is 1 if serve would refuse the policy.
// probeNoReplace and probeExchange are fsx's rename-flag probes,
// checkRootChain its chain rule for a write root, and checkClosedChain the
// rule for root commands' paths, under which a sticky directory is open too;
// tests may replace them.
var (
	probeNoReplace   = fsx.ProbeNoReplace
	probeExchange    = fsx.ProbeExchange
	checkRootChain   = fsx.CheckRootChain
	checkClosedChain = fsx.CheckClosedChain
)

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
	if ops.BypassBuild {
		failures++
		pr("FAIL binary: this is the end-to-end test build, with the helper's own checks bypassed; never deploy it")
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
	if err := env.checkVarRun(); err != nil {
		failures++
		pr("FAIL host: %v", err)
	}
	if fi, err := os.Stat(*policyPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
		pr("WARN the policy file is mode %04o; make it root:root 0600 (only root reads it, PRIVILEGED §2)", fi.Mode().Perm())
	}
	pr("policy sha256: %s", p.SHA256)
	pr("client_uid: %d   socket_group: %s (gid %d)   max_tier: %s", p.ClientUID, p.SocketGroup, p.SocketGID, p.MaxTier)
	pr("limits: read %d, write %d, output %d bytes; timeout default %ds, max %ds; delete entries %d",
		p.Limits.MaxReadBytes, p.Limits.MaxWriteBytes, p.Limits.MaxOutputBytes, p.Limits.DefaultTimeoutS, p.Limits.MaxTimeoutS, p.Limits.MaxDeleteEntries)
	// The child memory limit and the units' second layer (handoff N-30).
	mem := "core unit MemoryMax=" + units.MemoryMax(p)
	if p.UsesBroad() {
		mem += ", broad unit MemoryMax=" + units.MemoryMax(p)
	}
	pr("memory: limits.max_memory_mb %d MiB, the memory limit (RLIMIT_DATA, soft and hard) of every command and apt-get; %s (MemorySwapMax=0, OOMPolicy=continue)", p.Limits.MaxMemoryMB, mem)
	if set, err := execx.IgnoreRLimitData(env.ignoreRLimitData); err != nil {
		pr("WARN kernel: could not read ignore_rlimit_data (%v); if the boot option is set, limits.max_memory_mb binds brk(2) only, not mmap(2)", err)
	} else if set {
		pr("WARN kernel: ignore_rlimit_data is set (boot option); mmap(2) past limits.max_memory_mb only logs a warning, so the limit binds brk(2) only; remove the boot option")
	}
	pr("read roots: %s", strings.Join(p.Paths.Read, " "))
	pr("write roots: %s", strings.Join(p.Paths.Write, " "))
	for _, e := range p.Paths.Persistence {
		pr("persistence root: %s (acknowledge: %q)", e.Path, e.Acknowledge)
	}
	// Moves without overwrite need RENAME_NOREPLACE, and every replace as
	// root RENAME_EXCHANGE (PRIVILEGED §6): probe each privileged write root
	// for both (two files created, renamed and removed inside it, as the
	// gate's check-policy does).
	for _, root := range p.Paths.WriteRoots() {
		for _, pb := range []struct {
			flag, needs string
			probe       func(string) error
			unsupported error
		}{
			{"RENAME_NOREPLACE", "moves without overwrite are refused under this root", probeNoReplace, fsx.ErrNoReplaceUnsupported},
			{"RENAME_EXCHANGE", "writes, copies and moves that replace a file are refused under this root", probeExchange, fsx.ErrExchangeUnsupported},
		} {
			switch err := pb.probe(root); {
			case err == nil:
				pr("ok   privileged write root %s: %s supported", root, pb.flag)
			case errors.Is(err, pb.unsupported):
				pr("WARN privileged write root %s: the filesystem does not support %s; %s", root, pb.flag, pb.needs)
			default:
				pr("WARN privileged write root %s: could not probe %s (%v); %s without it", root, pb.flag, err, pb.needs)
			}
		}
	}
	// chmod and chown change an entry only when no account but root could
	// have put it there (PRIVILEGED §6, handoff N-1): every directory from /
	// to it root's and neither group- nor world-writable. Check each write
	// root's own path the same way, by descriptor.
	// The moved-in rule for reads and overwrites (handoff N-6, N-7) checks
	// the directories from each root down: an open directory above a root
	// lets another account replace the root itself, which it cannot see, so
	// read roots are reported too.
	movedIn := func(root string, ce *fsx.ChainError) string {
		if rp, err := filepath.EvalSymlinks(root); err == nil && ce.Dir == rp {
			return "files under it are read as root only when another account could read them itself, and overwritten keeping their owner only when it could have written them"
		}
		return "another account could replace the root itself, which the per-request moved-in check does not see"
	}
	// Root commands' path placeholders and cwd (handoff N-10) are checked from
	// /, and a directory given to one must be closed itself, so an open
	// directory at or above a root refuses the root and everything under it.
	const execNote = "root commands are given no path (placeholder or cwd) at or under it"
	// A root whose path passes the chain rule can still hold a sticky
	// directory, which root commands' paths count as open, writable or not
	// (handoff N-24); chmod and chown ignore the sticky bit.
	closed := func(kind, root string) {
		var ce *fsx.ChainError
		switch err := checkClosedChain(root, env.trust.Owns); {
		case err == nil:
			pr("ok   privileged %s root %s: every directory from / to it is root's and not group- or world-writable, nor sticky", kind, root)
		case errors.As(err, &ce):
			pr("WARN privileged %s root %s: %v; %s (chmod, chown and the moved-in checks do not look at the sticky bit)", kind, root, ce, execNote)
		default:
			pr("WARN privileged %s root %s: could not check the directories on its path for a sticky bit (%v); root commands' paths are refused under it unless they pass", kind, root, err)
		}
	}
	for _, root := range p.Paths.WriteRoots() {
		var ce *fsx.ChainError
		switch err := checkRootChain(root, env.trust.Owns); {
		case err == nil:
			closed("write", root)
		case errors.As(err, &ce):
			pr("WARN privileged write root %s: %v; chmod and chown are refused under it (another account could move files in and out again); %s; %s", root, ce, movedIn(root, ce), execNote)
		default:
			pr("WARN privileged write root %s: could not check the directories on its path (%v); chmod and chown, and root commands' paths, are refused under it unless they pass", root, err)
		}
	}
	for _, root := range p.Paths.Read {
		var ce *fsx.ChainError
		switch err := checkRootChain(root, env.trust.Owns); {
		case err == nil:
			closed("read", root)
		case errors.As(err, &ce):
			pr("WARN privileged read root %s: %v; %s; %s", root, ce, movedIn(root, ce), execNote)
		default:
			pr("WARN privileged read root %s: could not check the directories on its path (%v); root commands' paths are refused under it unless they pass", root, err)
		}
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
	if p.BackupsKeep > 0 {
		use := "its current use could not be read"
		if n, err := ops.StoreUsage(units.BackupDir, env.trust); err == nil {
			use = fmt.Sprintf("%d bytes used now", n)
		}
		pr("backups.max_store_bytes: %d (the backup store, %s: %s)", p.BackupsMaxStoreBytes, units.BackupDir, use)
	}
	pr("core unit capability bounding set: %s", strings.Join(p.Capabilities, " "))
	if p.UsesBroad() {
		pr("broad unit: yes, ROOT-EQUIVALENT (network, full root capabilities%s) for %s", map[bool]string{true: "", false: ", no ProtectClock="}[p.BroadProtectClock()], strings.Join(broadUsers(p), ", "))
	} else {
		pr("broad unit: none")
	}
	if len(p.Power.Allowed) > 0 {
		pr("power: %s (broad unit, logind 60 s after the answer, respecting inhibitor locks; acknowledge: %q)", strings.Join(p.Power.Allowed, " "), p.Power.Acknowledge)
	}
	if p.Packages.Enabled {
		pr("packages: apt (%s); install %s; remove %s; update index %v; upgrade %v", p.Packages.AptGet, strings.Join(p.Packages.Install, " "), strings.Join(p.Packages.Remove, " "), p.Packages.AllowUpdateIndex, p.Packages.AllowUpgrade)
	}
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
		if c.Applet != "" {
			extra += " [uutils applet " + c.Applet + "]"
		}
		if c.Interpreter != "" {
			extra += " [#! script run by " + c.Interpreter + "]"
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
