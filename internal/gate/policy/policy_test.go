//go:build linux

package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// fixture is an invented layout under a secure temp dir; nothing here
// describes a real host.
type fixture struct {
	dir, read, write, bin, home, gate, etc string
	opts                                   policy.LoadOptions
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := gatetest.SecureDir(t)
	f := &fixture{
		dir:   d,
		read:  filepath.Join(d, "srv", "app"),
		write: filepath.Join(d, "srv", "app", "config"),
		bin:   filepath.Join(d, "bin"),
		home:  filepath.Join(d, "home", "svc-shell"),
		gate:  filepath.Join(d, "gate", "shell-mcp-gate"),
		etc:   filepath.Join(d, "etc", "shell-mcp"),
	}
	for _, p := range []string{f.write, f.bin, f.home, f.etc} {
		gatetest.Mkdir(t, p, 0o755)
	}
	gatetest.WriteFile(t, f.gate, "invented gate binary", 0o755)
	f.exe(t, "example-tool")
	f.opts = policy.LoadOptions{Trust: gatetest.Trust(), GateExecutable: f.gate, ServiceHome: f.home}
	return f
}

// exe creates an executable fixture named name in f.bin (never executed).
func (f *fixture) exe(t *testing.T, name string) {
	t.Helper()
	gatetest.WriteFile(t, filepath.Join(f.bin, name), "invented binary\n", 0o755)
}

// chmod sets a fixture mode, including the deliberately insecure ones under test.
func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) expand(y string) string {
	return strings.NewReplacer("{R}", f.read, "{W}", f.write, "{BIN}", f.bin, "{HOME}", f.home,
		"{GATEDIR}", filepath.Dir(f.gate), "{ETC}", f.etc, "{D}", f.dir).Replace(y)
}

// put stores the policy under f.etc and returns its path.
func (f *fixture) put(t *testing.T, y string) string {
	t.Helper()
	p := filepath.Join(f.etc, "policy.yaml")
	gatetest.WriteFile(t, p, f.expand(y), 0o644)
	return p
}

func (f *fixture) load(t *testing.T, y string) (*policy.Policy, error) {
	t.Helper()
	return policy.Load(f.put(t, y), f.opts)
}

func (f *fixture) mustLoad(t *testing.T, y string) *policy.Policy {
	t.Helper()
	p, err := f.load(t, y)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, f.expand(y))
	}
	return p
}

func (f *fixture) mustFail(t *testing.T, y, want string) {
	t.Helper()
	_, err := f.load(t, y)
	if err == nil {
		t.Fatalf("policy accepted, want error containing %q:\n%s", want, f.expand(y))
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

const minimal = "version: 1\nmax_tier: read\n"

const full = `version: 1
max_tier: destructive
sandbox:
  landlock: best-effort
  system_read_exec: [{BIN}]
  tcp_connect_ports: [443, 22]
limits:
  default_timeout_s: 10
  max_timeout_s: 60
  max_output_bytes: 65536
paths:
  read: [{R}]
  write: [{W}]
  deny: ["{R}/secrets/**", "**/*.key"]
services:
  status: ["example-app.service", "example-*.service"]
  control:
    units: ["example-app.service"]
    verbs: [restart, reload]
journal:
  units: ["*"]
  max_lines: 500
git:
  repos:
    - path: {R}/deploy
      remote: https://git.example.test/org/deploy.git
privileged:
  enabled: true
  socket: /run/shell-mcp/privd.sock
  broad_socket: /run/shell-mcp/privd-broad.sock
  max_tier: operator
redact:
  patterns: ['(?i)token\s*[:=]\s*\S+']
commands:
  - id: example-status
    path: {BIN}/example-tool
    tier: read
    description: "Example status"
    templates:
      - ["status"]
      - ["show", "{path:read}"]
      - ["unit", "{unit}"]
`

func TestLoadFull(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, full)
	if p.MaxTier != policy.TierDestructive || p.Sandbox.Landlock != policy.LandlockBestEffort {
		t.Fatalf("tier/sandbox: %+v", p)
	}
	if len(p.Sandbox.TCPConnectPorts) != 2 || p.Sandbox.TCPConnectPorts[0] != 443 {
		t.Fatalf("ports %v", p.Sandbox.TCPConnectPorts)
	}
	l := p.Limits
	if l.DefaultTimeoutS != 10 || l.MaxTimeoutS != 60 || l.MaxOutputBytes != 65536 || l.MaxReadBytes != 1<<20 || l.MaxFindDepth != 8 || l.MaxDeleteEntries != 1000 || l.MaxProcesses != 2000 {
		t.Fatalf("limits %+v", l)
	}
	if !p.Privileged.Enabled || p.Privileged.MaxTier != policy.TierOperator {
		t.Fatalf("privileged %+v", p.Privileged)
	}
	if p.Journal.MaxLines != 500 || len(p.Redact) != 1 || len(p.Git.Repos) != 1 {
		t.Fatalf("journal/redact/git %+v %d %+v", p.Journal, len(p.Redact), p.Git)
	}
	c, ok := p.Command("example-status")
	if !ok || c.Resolved != filepath.Join(f.bin, "example-tool") || len(c.Templates) != 3 || c.Tier != policy.TierRead {
		t.Fatalf("command %+v", c)
	}
	data, _ := os.ReadFile(filepath.Join(f.etc, "policy.yaml"))
	sum := sha256.Sum256(data)
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha %s", p.SHA256)
	}
	// Built-in deny list plus policy patterns.
	for _, d := range []string{"/etc/shadow", "/root/x", "/home/u/.ssh/id", "/x/.git-credentials", f.read + "/secrets/a", f.read + "/tls.key", "/var/lib/shell-mcp/x"} {
		if !p.Paths.Deny.Covers(d) {
			t.Errorf("deny does not cover %s", d)
		}
	}
	if p.Paths.Deny.Covers(f.read + "/config.yaml") {
		t.Error("deny covers an ordinary file")
	}
	for _, d := range []string{"/etc/ssh/sshd_config", "/usr/local/bin/x", f.gate, f.home + "/.profile", filepath.Join(f.etc, "policy.yaml"), "/etc/crontab", "/srv/x/.ssh"} {
		if !p.Paths.Protected.Covers(d) {
			t.Errorf("protected does not cover %s", d)
		}
	}
}

func TestDefaults(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, minimal)
	if p.Sandbox.Landlock != policy.LandlockRequired {
		t.Fatalf("default landlock %q", p.Sandbox.Landlock)
	}
	want := policy.Limits{DefaultTimeoutS: 30, MaxTimeoutS: 300, MaxOutputBytes: 1 << 20, MaxStdinBytes: 1 << 20, MaxReadBytes: 1 << 20,
		MaxWriteBytes: 1 << 20, MaxFindResults: 1000, MaxFindDepth: 8, MaxDeleteEntries: 1000, MaxProcesses: 2000}
	if p.Limits != want {
		t.Fatalf("limits %+v", p.Limits)
	}
	if p.Privileged.Enabled || len(p.Commands) != 0 || len(p.Paths.Read) != 0 {
		t.Fatalf("omitted sections must allow nothing: %+v", p)
	}
	if p.ServiceHome != f.home {
		t.Fatalf("home %q", p.ServiceHome)
	}
}

func TestStrictParsing(t *testing.T) {
	f := newFixture(t)
	cases := map[string]string{
		"unknown top-level key": minimal + "extra: 1\n",
		"sudo key":              minimal + "sudo: true\n",
		"sudo in a command":     minimal + "commands:\n  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    sudo: true\n    templates: [[x]]\n",
		"unknown nested key":    minimal + "paths:\n  read: [{R}]\n  exec: [{R}]\n",
		"duplicate key":         "version: 1\nmax_tier: read\nmax_tier: destructive\n",
		"duplicate nested key":  minimal + "limits:\n  max_timeout_s: 10\n  max_timeout_s: 600\n",
		"wrong type":            "version: 1\nmax_tier: [read]\n",
		"wrong int type":        minimal + "limits:\n  max_timeout_s: ten\n",
		"two documents":         minimal + "---\nversion: 1\nmax_tier: destructive\n",
		"empty":                 "",
		"version 2":             "version: 2\nmax_tier: read\n",
		"no version":            "max_tier: read\n",
		"no max_tier":           "version: 1\n",
		"bad max_tier":          "version: 1\nmax_tier: admin\n",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.load(t, y); err == nil {
				t.Fatalf("accepted:\n%s", f.expand(y))
			}
		})
	}
}

func TestSandboxAndLimits(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, minimal+"sandbox:\n  landlock: off\n", "landlock")
	f.mustFail(t, minimal+"sandbox:\n  system_read_exec: [opt/bin]\n", "system_read_exec")
	f.mustFail(t, minimal+"sandbox:\n  system_read_exec: [/opt/bin/]\n", "system_read_exec")
	f.mustFail(t, minimal+"sandbox:\n  system_read_exec: [/]\n", "system_read_exec")
	f.mustFail(t, minimal+"sandbox:\n  tcp_connect_ports: [0]\n", "tcp_connect_ports")
	f.mustFail(t, minimal+"sandbox:\n  tcp_connect_ports: [65536]\n", "tcp_connect_ports")
	f.mustFail(t, minimal+"sandbox:\n  tcp_connect_ports: [443, 443]\n", "tcp_connect_ports")
	for _, l := range []string{
		"max_timeout_s: 601", "max_timeout_s: 0", "default_timeout_s: 400", "max_output_bytes: 4194305", "max_stdin_bytes: 1048577",
		"max_read_bytes: 4194305", "max_write_bytes: 1048577", "max_find_results: 10001", "max_find_depth: 33",
		"max_delete_entries: 10001", "max_find_results: 0", "max_output_bytes: -1",
	} {
		f.mustFail(t, minimal+"limits:\n  "+l+"\n", "limits")
	}
	p := f.mustLoad(t, minimal+"limits:\n  max_timeout_s: 600\n  max_output_bytes: 4194304\n  max_read_bytes: 4194304\n  max_stdin_bytes: 0\n")
	if p.Limits.MaxTimeoutS != 600 || p.Limits.MaxStdinBytes != 0 {
		t.Fatalf("ceilings: %+v", p.Limits)
	}
}

func TestRoots(t *testing.T) {
	f := newFixture(t)
	bad := map[string]string{
		"relative":         "paths:\n  read: [srv/app]\n",
		"trailing slash":   "paths:\n  read: [{R}/]\n",
		"dot-dot":          "paths:\n  read: [{R}/../app]\n",
		"root":             "paths:\n  read: [/]\n",
		"proc":             "paths:\n  read: [/proc]\n",
		"inside proc":      "paths:\n  read: [/proc/1]\n",
		"sys":              "paths:\n  read: [/sys/kernel]\n",
		"dev":              "paths:\n  read: [/dev]\n",
		"run":              "paths:\n  write: [/run/example]\n",
		"duplicate":        "paths:\n  read: [{R}, {R}]\n",
		"write etc/ssh":    "paths:\n  write: [/etc/ssh]\n",
		"write in etc/ssh": "paths:\n  write: [/etc/ssh/sshd_config.d]\n",
		"write contains":   "paths:\n  write: [/etc]\n",
		"write usr local":  "paths:\n  write: [/usr/local/bin]\n",
		"write cron.d":     "paths:\n  write: [/etc/cron.d]\n",
		"write systemd":    "paths:\n  write: [/etc/systemd/system]\n",
		"write gate dir":   "paths:\n  write: [{GATEDIR}]\n",
		"write home":       "paths:\n  write: [{HOME}]\n",
		"write in home":    "paths:\n  write: [{HOME}/data]\n",
		"write above home": "paths:\n  write: [{D}/home]\n",
		"write policy dir": "paths:\n  write: [{ETC}]\n",
		"write in .ssh":    "paths:\n  write: [{R}/.ssh]\n",
		"write under .ssh": "paths:\n  write: [{R}/.ssh/keys]\n",
		"write boot":       "paths:\n  write: [/boot/efi]\n",
		"bad deny glob":    "paths:\n  deny: [\"relative/**\"]\n",
		"bad deny glob [":  "paths:\n  deny: [\"/srv/[ab]\"]\n",
	}
	for name, y := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := f.load(t, minimal+y); err == nil {
				t.Fatalf("accepted:\n%s", f.expand(minimal+y))
			}
		})
	}
	// A read root may contain protected paths; only writes are restricted.
	f.mustLoad(t, minimal+"paths:\n  read: [/etc, {R}]\n  write: [{W}]\n")
}

func TestServicesJournalGit(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, minimal+"services:\n  status: [\"a/b.service\"]\n", "services.status")
	f.mustFail(t, minimal+"services:\n  status: [\"[\"]\n", "services.status")
	f.mustFail(t, minimal+"services:\n  control:\n    units: [\"example-*.service\"]\n    verbs: [restart]\n", "services.control.units")
	f.mustFail(t, minimal+"services:\n  control:\n    units: [\"example-?.service\"]\n    verbs: [restart]\n", "services.control.units")
	f.mustFail(t, minimal+"services:\n  control:\n    units: [\"example-app.service\"]\n    verbs: [enable]\n", "services.control.verbs")
	f.mustFail(t, minimal+"services:\n  control:\n    units: [\"example-app.service\"]\n", "services.control")
	f.mustFail(t, minimal+"services:\n  control:\n    units: [\"-x.service\"]\n    verbs: [restart]\n", "services.control.units")
	f.mustFail(t, minimal+"journal:\n  units: [\"*\"]\n  max_lines: 10001\n", "journal.max_lines")
	f.mustFail(t, minimal+"journal:\n  units: [\"a/b\"]\n", "journal.units")
	f.mustFail(t, minimal+"paths:\n  read: [{R}]\ngit:\n  repos:\n    - path: {D}/elsewhere\n      remote: https://git.example.test/r.git\n", "git.repos")
	f.mustFail(t, minimal+"paths:\n  read: [{R}]\ngit:\n  repos:\n    - path: {R}/r\n      remote: \"--upload-pack=x\"\n", "git.repos")
	f.mustFail(t, minimal+"paths:\n  read: [{R}]\ngit:\n  repos:\n    - path: {R}/r\n", "git.repos")
	p := f.mustLoad(t, minimal+"journal:\n  units: [\"*\"]\n")
	if p.Journal.MaxLines != 1000 {
		t.Fatalf("journal default %d", p.Journal.MaxLines)
	}
}

func TestPrivileged(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: /run/other/privd.sock\n", "privileged.socket")
	f.mustFail(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: /run/shell-mcp\n", "privileged.socket")
	f.mustFail(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: /run/shell-mcp/../x.sock\n", "privileged.socket")
	f.mustFail(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: run/shell-mcp/x.sock\n", "privileged.socket")
	f.mustFail(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: /run/shell-mcp/p.sock\n  broad_socket: /tmp/b.sock\n", "privileged.broad_socket")
	f.mustFail(t, "version: 1\nmax_tier: read\nprivileged:\n  enabled: true\n  socket: /run/shell-mcp/p.sock\n  max_tier: operator\n", "privileged.max_tier")
	f.mustFail(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n", "privileged.socket")
	p := f.mustLoad(t, "version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: /run/shell-mcp/p.sock\n")
	if p.Privileged.MaxTier != policy.TierRead {
		t.Fatalf("privileged.max_tier default %v", p.Privileged.MaxTier)
	}
	p = f.mustLoad(t, minimal+"privileged:\n  enabled: false\n")
	if p.Privileged.Enabled {
		t.Fatal("enabled")
	}
}

func TestRedact(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, minimal+"redact:\n  patterns: ['(unclosed']\n", "redact.patterns")
}

func cmdPolicy(extra string) string {
	return "version: 1\nmax_tier: destructive\nsandbox:\n  system_read_exec: [{BIN}]\ncommands:\n" + extra
}

func TestCommands(t *testing.T) {
	f := newFixture(t)
	ok := "  - id: ok-1\n    path: {BIN}/example-tool\n    tier: operator\n    templates: [[\"a\"], []]\n"
	p := f.mustLoad(t, cmdPolicy(ok))
	if c, _ := p.Command("ok-1"); len(c.Templates) != 2 || c.Tier != policy.TierOperator {
		t.Fatalf("command %+v", c)
	}
	f.mustFail(t, cmdPolicy("  - id: Bad_ID\n    path: {BIN}/example-tool\n    tier: read\n    templates: [[a]]\n"), "id")
	f.mustFail(t, cmdPolicy(ok+ok), "duplicate")
	f.mustFail(t, cmdPolicy("  - id: a\n    path: bin/example-tool\n    tier: read\n    templates: [[a]]\n"), "path")
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/missing\n    tier: read\n    templates: [[a]]\n"), "path")
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/example-tool\n    tier: admin\n    templates: [[a]]\n"), "tier")
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n"), "templates")
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    templates: [[\"{regex:abc}\"]]\n"), "templates")
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}\n    tier: read\n    templates: [[a]]\n"), "regular")
}

func TestHardDeny(t *testing.T) {
	f := newFixture(t)
	names := []string{"bash", "busybox", "python3", "python3.13", "pypy3", "perl5.40", "php8.4", "lua5.4", "awk", "mawk", "env", "xargs",
		"timeout", "strace", "less", "vim.basic", "nano", "sudo", "pkexec", "nsenter", "unshare", "setpriv", "ssh", "socat", "rsync",
		"tmux", "script", "useradd", "crontab", "reboot", "init", "modprobe", "mkfs.ext4", "dd", "mount", "nft", "iptables",
		"systemctl", "journalctl", "git"}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			f.exe(t, n)
			f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/"+n+"\n    tier: read\n    templates: [[a]]\n"), "")
		})
	}
	// Resolved through a symlink: a link named ls pointing at a shell.
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	link := filepath.Join(f.bin, "ls")
	if err := os.Symlink(shell, link); err != nil {
		t.Fatal(err)
	}
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/ls\n    tier: read\n    templates: [[a]]\n"), "hard-denied")
}

func TestContainerCLIsNeedAcknowledgement(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"docker", "podman", "ctr", "nerdctl", "kubectl"} {
		f.exe(t, n)
		f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/"+n+"\n    tier: read\n    templates: [[ps]]\n"), "root_equivalent")
		f.mustLoad(t, cmdPolicy("  - id: a\n    path: {BIN}/"+n+"\n    tier: read\n    root_equivalent: true\n    templates: [[ps]]\n"))
	}
}

func TestCommandOwnership(t *testing.T) {
	f := newFixture(t)
	y := cmdPolicy("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    templates: [[a]]\n")
	tool := filepath.Join(f.bin, "example-tool")

	chmod(t, tool, 0o775)
	f.mustFail(t, y, "writable")
	chmod(t, tool, 0o757)
	f.mustFail(t, y, "writable")
	chmod(t, tool, 0o644)
	f.mustFail(t, y, "executable")
	chmod(t, tool, 0o755)
	chmod(t, f.bin, 0o775)
	f.mustFail(t, y, "writable")
	chmod(t, f.bin, 0o755)
	f.mustLoad(t, y)
	// Under production trust, a binary owned by the test uid is refused.
	if os.Getuid() != 0 {
		p := f.put(t, y)
		_, err := policy.Parse([]byte(f.expand(y)), p, policy.LoadOptions{Trust: policy.RootTrust(), GateExecutable: f.gate, ServiceHome: f.home})
		if err == nil || !strings.Contains(err.Error(), "owned") {
			t.Fatalf("root trust accepted a non-root binary: %v", err)
		}
	}
}

func TestLoadOwnership(t *testing.T) {
	f := newFixture(t)
	p := f.put(t, minimal)
	if _, err := policy.Load(p, f.opts); err != nil {
		t.Fatal(err)
	}
	chmod(t, p, 0o664)
	if _, err := policy.Load(p, f.opts); err == nil {
		t.Fatal("group-writable policy accepted")
	}
	chmod(t, p, 0o644)
	chmod(t, f.etc, 0o777)
	if _, err := policy.Load(p, f.opts); err == nil {
		t.Fatal("world-writable parent accepted")
	}
	chmod(t, f.etc, 0o755)
	// A symlinked policy is judged by its target's chain.
	evil := filepath.Join(f.dir, "evil")
	gatetest.Mkdir(t, evil, 0o777)
	gatetest.WriteFile(t, filepath.Join(evil, "p.yaml"), minimal, 0o644)
	link := filepath.Join(f.etc, "link.yaml")
	if err := os.Symlink(filepath.Join(evil, "p.yaml"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(link, f.opts); err == nil {
		t.Fatal("policy in a world-writable directory accepted through a symlink")
	}
	// Too large.
	gatetest.WriteFile(t, p, minimal+"#"+strings.Repeat("x", policy.MaxPolicyBytes), 0o644)
	if _, err := policy.Load(p, f.opts); err == nil {
		t.Fatal("oversize policy accepted")
	}
	// Not a regular file.
	if _, err := policy.Load(f.etc, f.opts); err == nil {
		t.Fatal("directory accepted as policy")
	}
	// Production trust refuses a policy owned by the test uid.
	if os.Getuid() != 0 {
		gatetest.WriteFile(t, p, minimal, 0o644)
		_, err := policy.Load(p, policy.LoadOptions{Trust: policy.RootTrust(), GateExecutable: f.gate, ServiceHome: f.home})
		var oe *policy.OwnershipError
		if !errors.As(err, &oe) {
			t.Fatalf("root trust: %v", err)
		}
	}
}

func TestCheckChain(t *testing.T) {
	f := newFixture(t)
	if _, err := policy.CheckChain(gatetest.Trust(), f.gate); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.CheckChain(policy.RootTrust(), "/usr/bin"); err != nil {
		t.Fatalf("/usr/bin under root trust: %v", err)
	}
	if _, err := policy.CheckChain(gatetest.Trust(), filepath.Join(f.dir, "missing")); err == nil {
		t.Fatal("missing path accepted")
	}
}

// A service account whose home is "/" must not make "/" protected (every
// write root would be "inside" it); the home joins the protected set only
// when it is a real directory below "/".
func TestServiceHomeSlash(t *testing.T) {
	f := newFixture(t)
	f.opts.ServiceHome = "/"
	p := f.mustLoad(t, minimal+"paths:\n  write: [{W}]\n")
	if p.ServiceHome != "/" || p.Paths.Protected.Covers(f.write) {
		t.Fatalf("home / protected everything: %+v", p.ServiceHome)
	}
}

func TestParseTier(t *testing.T) {
	for s, want := range map[string]policy.Tier{"read": policy.TierRead, "operator": policy.TierOperator, "destructive": policy.TierDestructive} {
		if got, err := policy.ParseTier(s); err != nil || got != want || got.String() != s {
			t.Errorf("ParseTier(%q) = %v, %v", s, got, err)
		}
	}
	if _, err := policy.ParseTier("admin"); err == nil {
		t.Error("admin accepted")
	}
}
