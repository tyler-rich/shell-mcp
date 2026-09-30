//go:build linux

package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// fixture is an invented layout under a secure temp dir; nothing here
// describes a real host. Users, groups and ids are invented too.
type fixture struct {
	dir, bin, sysbin, etc, helper string
	opts                          policy.LoadOptions
}

var (
	fakeUsers  = map[string]uint32{"root": 0, "example-app": 1001, "svc-shell": 60123}
	fakeGroups = map[string]uint32{"root": 0, "example-app": 1001, "svc-shell-priv": 60124, "docker": 999, "sudo": 27, "adm": 4, "wheel": 10}
)

func newFixture(t testing.TB) *fixture {
	t.Helper()
	d := gatetest.SecureDir(t)
	f := &fixture{
		dir:    d,
		bin:    filepath.Join(d, "bin"),
		sysbin: filepath.Join(d, "sysbin"),
		etc:    filepath.Join(d, "etc", "shell-mcp"),
		helper: filepath.Join(d, "libexec", "shell-mcp-privd"),
	}
	for _, p := range []string{f.bin, f.sysbin, f.etc} {
		gatetest.Mkdir(t, p, 0o755)
	}
	gatetest.WriteFile(t, f.helper, "invented helper binary", 0o755)
	f.exe(t, "example-tool", "example tool\n")
	f.exe(t, "example-renew", "example renew\n")
	// The identity check's system directory holds hard-denied names.
	for name, body := range map[string]string{"bash": "shell body\n", "nft": "firewall body\n", "reboot": "power body\n"} {
		gatetest.WriteFile(t, filepath.Join(f.sysbin, name), body, 0o755)
	}
	f.opts = policy.LoadOptions{
		Trust:            gatetest.Trust(),
		HelperExecutable: f.helper,
		AptGet:           f.exe(t, "apt-get", "invented apt-get\n"),
		SystemBinDirs:    []string{f.sysbin},
		LookupUser: func(n string) (uint32, error) {
			if id, ok := fakeUsers[n]; ok {
				return id, nil
			}
			return 0, errors.New("unknown user")
		},
		LookupGroup: func(n string) (uint32, error) {
			if id, ok := fakeGroups[n]; ok {
				return id, nil
			}
			return 0, errors.New("unknown group")
		},
		UserName: func(uid uint32) string {
			for n, id := range fakeUsers {
				if id == uid {
					return n
				}
			}
			return ""
		},
	}
	return f
}

// exe creates an executable fixture named name in f.bin (never executed).
func (f *fixture) exe(t testing.TB, name, body string) string {
	t.Helper()
	p := filepath.Join(f.bin, name)
	gatetest.WriteFile(t, p, body, 0o755)
	return p
}

func (f *fixture) expand(y string) string {
	return strings.NewReplacer("{BIN}", f.bin, "{HELPER}", f.helper, "{D}", f.dir).Replace(y)
}

func (f *fixture) put(t *testing.T, y string) string {
	t.Helper()
	p := filepath.Join(f.etc, "privileged.yaml")
	gatetest.WriteFile(t, p, f.expand(y), 0o600)
	return p
}

func (f *fixture) load(t *testing.T, y string) (*policy.Policy, error) {
	t.Helper()
	return policy.Load(f.put(t, y), &f.opts)
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
		t.Fatalf("error %q does not contain %q\n%s", err, want, f.expand(y))
	}
}

const head = "version: 1\nclient_uid: 60123\nsocket_group: svc-shell-priv\nmax_tier: destructive\n"

// withPaths returns head plus a paths section.
func withPaths(section string) string { return head + "paths:\n" + section }

// withCommand returns head plus one command entry (indented list item).
func withCommand(entry string) string { return head + "commands:\n" + entry }

func TestLoadMinimalDefaults(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, head)
	if p.ClientUID != 60123 || p.SocketGroup != "svc-shell-priv" || p.SocketGID != 60124 || p.MaxTier != policy.TierDestructive {
		t.Fatalf("identity fields %+v", p)
	}
	if p.Landlock != policy.LandlockRequired {
		t.Errorf("landlock default %q", p.Landlock)
	}
	want := policy.Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxOutputBytes: 1 << 20, DefaultTimeoutS: 60, MaxTimeoutS: 900, MaxDeleteEntries: 1000}
	if p.Limits != want {
		t.Errorf("limits %+v, want %+v", p.Limits, want)
	}
	if p.ModesMax != 0o755 || p.BackupsKeep != 10 {
		t.Errorf("modes.max %04o keep %d", p.ModesMax, p.BackupsKeep)
	}
	if !slices.Equal(p.Capabilities, []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER"}) {
		t.Errorf("capabilities %v", p.Capabilities)
	}
	sum := sha256.Sum256([]byte(head))
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 %s is not the file bytes' hash", p.SHA256)
	}
	if p.Packages.Enabled || len(p.Commands) != 0 || len(p.Owners.Users) != 0 {
		t.Errorf("omitted sections allow something: %+v", p)
	}
}

// The PRIVILEGED §4 example, with invented binaries standing in for the
// ones it names.
const example = `version: 1
client_uid: 60123
socket_group: svc-shell-priv
max_tier: destructive
sandbox:
  landlock: best-effort
limits:
  max_read_bytes: 1048576
  max_write_bytes: 1048576
  max_output_bytes: 1048576
  default_timeout_s: 60
  max_timeout_s: 900
  max_delete_entries: 1000
paths:
  read:  [/etc/example-app, /var/log/example-app]
  write: [/etc/example-app/conf.d]
  persistence:
    - path: /etc/systemd/system/example-app.service.d
      acknowledge: "drop-ins for example-app only"
  deny: ["/etc/example-app/secrets/**"]
owners:
  users: [root, example-app]
  groups: [root, example-app]
modes:
  max: "0755"
backups:
  keep: 10
commands:
  - id: example-test
    path: {BIN}/example-tool
    tier: read
    description: "Configuration test"
    templates: [["-t"], ["--check", "{path:read}"]]
  - id: renew-certs
    path: {BIN}/example-renew
    tier: operator
    unit: broad
    templates: [["--all"]]
  - id: firewall-list
    path: {BIN}/nft
    tier: read
    acknowledge: "firewall rules are listed, never changed"
    templates: [["list", "ruleset"]]
power:
  allowed: [reboot]
  acknowledge: "planned maintenance windows only"
packages:
  enabled: true
  manager: apt
  install: [htop, jq]
  remove: [htop]
  allow_update_index: true
  allow_upgrade: false
`

func TestLoadExample(t *testing.T) {
	f := newFixture(t)
	f.exe(t, "nft", "firewall body\n") // same bytes as sysbin/nft: list B by name and by identity
	p := f.mustLoad(t, example)
	if p.Landlock != policy.LandlockBestEffort || p.MaxTier != policy.TierDestructive {
		t.Errorf("landlock %q max_tier %v", p.Landlock, p.MaxTier)
	}
	if !slices.Equal(p.Paths.Read, []string{"/etc/example-app", "/var/log/example-app"}) ||
		!slices.Equal(p.Paths.WriteRoots(), []string{"/etc/example-app/conf.d", "/etc/systemd/system/example-app.service.d"}) {
		t.Errorf("roots %+v", p.Paths)
	}
	if len(p.Owners.Users) != 2 || p.Owners.Users[1] != (policy.NamedID{Name: "example-app", ID: 1001}) ||
		p.Owners.Groups[0] != (policy.NamedID{Name: "root", ID: 0}) {
		t.Errorf("owners %+v", p.Owners)
	}
	c, ok := p.Command("firewall-list")
	if !ok || c.ListB != 13 || c.Unit != policy.UnitCore || c.Acknowledge != "firewall rules are listed, never changed" {
		t.Fatalf("firewall-list %+v", c)
	}
	if c, ok := p.Command("renew-certs"); !ok || c.Unit != policy.UnitBroad {
		t.Fatalf("renew-certs %+v", c)
	}
	if !slices.Equal(p.Capabilities, policy.BaseCapabilities) {
		t.Errorf("capabilities %v", p.Capabilities)
	}
	if !p.Packages.Enabled || p.Packages.Manager != "apt" || !slices.Equal(p.Packages.Install, []string{"htop", "jq"}) {
		t.Errorf("packages %+v", p.Packages)
	}
	if !slices.Equal(p.Power.Allowed, []string{"reboot"}) || p.Power.Acknowledge != "planned maintenance windows only" {
		t.Errorf("power %+v", p.Power)
	}
	if !p.UsesBroad() {
		t.Error("the example uses the broad unit")
	}
	kinds := map[string]bool{}
	for _, fd := range p.Acknowledged {
		kinds[fd.Kind] = true
	}
	for _, k := range []string{"list-b-binary", "persistence", "root-equivalent", "power"} {
		if !kinds[k] {
			t.Errorf("check-policy findings lack %s: %+v", k, p.Acknowledged)
		}
	}
}

func TestStrictParsing(t *testing.T) {
	f := newFixture(t)
	cases := map[string]struct{ y, want string }{
		"unknown top-level key": {head + "sudo: true\n", "field sudo not found"},
		"unknown nested key":    {head + "limits:\n  max_everything: 1\n", "field max_everything not found"},
		"duplicate key":         {head + "max_tier: read\n", "already defined"},
		"second document":       {head + "---\nversion: 1\n", "single YAML document"},
		"wrong type":            {"version: 1\nclient_uid: sixty\nsocket_group: svc-shell-priv\nmax_tier: read\n", "cannot unmarshal"},
		// The per-command key is `unit`; `sandbox` is only the top-level
		// Landlock section.
		"old per-command sandbox key": {withCommand("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    sandbox: broad\n    templates: [[]]\n"), "field sandbox not found"},
		"sandbox as a scalar":         {head + "sandbox: best-effort\n", "cannot unmarshal"},
		"unknown command key":         {withCommand("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    sudo: true\n    templates: [[]]\n"), "field sudo not found"},
		"unknown persistence key":     {withPaths("  persistence:\n    - path: /etc/cron.d\n      acknowledge: x\n      force: true\n"), "field force not found"},
		"empty file":                  {"", "empty"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { f.mustFail(t, c.y, c.want) })
	}
}

func TestRequiredAndIdentityFields(t *testing.T) {
	f := newFixture(t)
	for name, c := range map[string]struct{ y, want string }{
		"no version":       {"client_uid: 60123\nsocket_group: svc-shell-priv\nmax_tier: read\n", "version"},
		"version 2":        {"version: 2\nclient_uid: 60123\nsocket_group: svc-shell-priv\nmax_tier: read\n", "version"},
		"no client_uid":    {"version: 1\nsocket_group: svc-shell-priv\nmax_tier: read\n", "client_uid"},
		"client_uid 0":     {"version: 1\nclient_uid: 0\nsocket_group: svc-shell-priv\nmax_tier: read\n", "client_uid"},
		"client_uid -1":    {"version: 1\nclient_uid: -1\nsocket_group: svc-shell-priv\nmax_tier: read\n", "client_uid"},
		"client_uid max":   {"version: 1\nclient_uid: 4294967295\nsocket_group: svc-shell-priv\nmax_tier: read\n", "client_uid"},
		"client_uid huge":  {"version: 1\nclient_uid: 4294967296\nsocket_group: svc-shell-priv\nmax_tier: read\n", "client_uid"},
		"no socket_group":  {"version: 1\nclient_uid: 60123\nmax_tier: read\n", "socket_group"},
		"unknown group":    {"version: 1\nclient_uid: 60123\nsocket_group: no-such-group\nmax_tier: read\n", "socket_group"},
		"group docker":     {"version: 1\nclient_uid: 60123\nsocket_group: docker\nmax_tier: read\n", "D-020"},
		"group sudo":       {"version: 1\nclient_uid: 60123\nsocket_group: sudo\nmax_tier: read\n", "D-020"},
		"group root":       {"version: 1\nclient_uid: 60123\nsocket_group: root\nmax_tier: read\n", "socket_group"},
		"group adm":        {"version: 1\nclient_uid: 60123\nsocket_group: adm\nmax_tier: read\n", "D-020"},
		"no max_tier":      {"version: 1\nclient_uid: 60123\nsocket_group: svc-shell-priv\n", "max_tier"},
		"max_tier admin":   {"version: 1\nclient_uid: 60123\nsocket_group: svc-shell-priv\nmax_tier: admin\n", "max_tier"},
		"landlock unknown": {head + "sandbox:\n  landlock: off\n", "sandbox.landlock"},
	} {
		t.Run(name, func(t *testing.T) { f.mustFail(t, c.y, c.want) })
	}
}

func TestLimits(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		key  string
		bad  []int
		good []int
	}{
		{"max_read_bytes", []int{0, 4<<20 + 1}, []int{1, 4 << 20}},
		{"max_write_bytes", []int{0, 1<<20 + 1}, []int{1, 1 << 20}},
		{"max_output_bytes", []int{0, 4<<20 + 1}, []int{1, 4 << 20}},
		{"max_timeout_s", []int{0, 1801}, []int{60, 1800}},
		{"max_delete_entries", []int{0, 10001}, []int{1, 10000}},
		{"default_timeout_s", []int{0, 1801}, []int{1, 900}},
	} {
		for _, v := range c.bad {
			f.mustFail(t, head+fmt.Sprintf("limits:\n  %s: %d\n", c.key, v), "limits."+c.key)
		}
		for _, v := range c.good {
			f.mustLoad(t, head+fmt.Sprintf("limits:\n  %s: %d\n", c.key, v))
		}
	}
	f.mustFail(t, head+"limits:\n  default_timeout_s: 120\n  max_timeout_s: 60\n", "default_timeout_s")
	// An omitted default follows a lower maximum.
	if p := f.mustLoad(t, head+"limits:\n  max_timeout_s: 30\n"); p.Limits.DefaultTimeoutS != 30 {
		t.Errorf("default %d", p.Limits.DefaultTimeoutS)
	}
}

func TestRootRules(t *testing.T) {
	f := newFixture(t)
	bad := []string{"/", "/proc", "/proc/sys", "/sys", "/dev", "/dev/shm", "/run", "/run/example", "srv/app", "/srv/../etc", "/srv/app/", "/srv//app", ""}
	for _, r := range bad {
		f.mustFail(t, withPaths(fmt.Sprintf("  read: [%q]\n", r)), "paths.read")
		f.mustFail(t, withPaths(fmt.Sprintf("  write: [%q]\n", r)), "paths.write")
		f.mustFail(t, withPaths(fmt.Sprintf("  persistence:\n    - path: %q\n      acknowledge: x\n", r)), "paths.persistence")
	}
	f.mustFail(t, withPaths("  write: [/srv/app, /srv/app]\n"), "duplicate")
	f.mustFail(t, withPaths("  read: [/srv/app, /srv/app]\n"), "duplicate")
	// A root may be both read and write (PRIVILEGED §4's example lists
	// /etc/example-app under both); write roots are readable anyway.
	f.mustLoad(t, withPaths("  read: [/srv/app]\n  write: [/srv/app]\n"))
	f.mustFail(t, withPaths("  write: [/srv/app]\n  persistence:\n    - path: /srv/app\n      acknowledge: x\n"), "duplicate")
}

// List A (PRIVILEGED §5.3): never a write or persistence root, never inside
// one, never containing one — acknowledged or not.
func TestNeverListRoots(t *testing.T) {
	f := newFixture(t)
	for _, r := range []string{
		// equal
		"/etc/shadow", "/etc/passwd", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d",
		"/etc/security", "/etc/ssh", "/etc/polkit-1", "/usr/share/polkit-1", "/etc/shell-mcp", "/var/lib/shell-mcp",
		"/usr/local/libexec/shell-mcp-privd", "/usr/local/bin/shell-mcp-gate",
		// inside
		"/etc/ssh/sshd_config.d", "/etc/pam.d/local", "/etc/security/limits.d", "/etc/polkit-1/rules.d",
		"/etc/shell-mcp/extra", "/var/lib/shell-mcp/backups", "/srv/app/.ssh", "/home/example/.ssh/keys",
		"/etc/systemd/system/shell-mcp-privd@.service.d", "/etc/systemd/system/sockets.target.wants/shell-mcp-privd.socket",
		// containing
		"/etc", "/usr/share", "/usr/local", "/usr/local/bin", "/usr/local/libexec", "/var/lib", "/home/example",
		// the running helper binary and its directory
		f.helper, filepath.Dir(f.helper),
	} {
		f.mustFail(t, withPaths(fmt.Sprintf("  write: [%s]\n", r)), "never")
		f.mustFail(t, withPaths(fmt.Sprintf("  persistence:\n    - path: %s\n      acknowledge: \"acknowledged\"\n", r)), "never")
	}
	// Read roots may contain the never list (the deny list and the unit's
	// InaccessiblePaths= keep credentials out) but not be or sit inside it.
	for _, r := range []string{"/etc/ssh", "/etc/shell-mcp", "/etc/polkit-1/rules.d", "/srv/app/.ssh", "/etc/shadow"} {
		f.mustFail(t, withPaths(fmt.Sprintf("  read: [%s]\n", r)), "never")
	}
	f.mustLoad(t, withPaths("  read: [/etc, /var/lib, /usr/share]\n"))
}

// Writes never touch a .git directory (POLICY §3).
func TestGitWriteDeny(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, withPaths("  write: [/srv/app/.git]\n"), ".git")
	f.mustFail(t, withPaths("  write: [/srv/app/.git/hooks]\n"), ".git")
	p := f.mustLoad(t, withPaths("  write: [/srv/app]\n"))
	if !p.Paths.Protected.Covers("/srv/app/.git/config") || !p.Paths.Protected.Covers("/srv/app/sub/.git") {
		t.Error(".git is writable")
	}
}

// Gate-protected paths that are not on the never list (persistence areas)
// are writable only as acknowledged persistence roots.
func TestPersistenceNeedsAcknowledge(t *testing.T) {
	f := newFixture(t)
	for _, r := range []string{"/etc/systemd/system/example-app.service.d", "/etc/cron.d", "/etc/profile.d", "/usr/local/sbin", "/etc/ld.so.conf.d", "/usr/lib/example-app"} {
		f.mustFail(t, withPaths(fmt.Sprintf("  write: [%s]\n", r)), "paths.persistence")
		f.mustFail(t, withPaths(fmt.Sprintf("  persistence:\n    - path: %s\n", r)), "acknowledge")
		f.mustFail(t, withPaths(fmt.Sprintf("  persistence:\n    - path: %s\n      acknowledge: \"\"\n", r)), "acknowledge")
		f.mustFail(t, withPaths(fmt.Sprintf("  persistence:\n    - path: %s\n      acknowledge: \"two\\nlines\"\n", r)), "acknowledge")
		p := f.mustLoad(t, withPaths(fmt.Sprintf("  persistence:\n    - path: %s\n      acknowledge: \"reviewed\"\n", r)))
		if !slices.Contains(p.Paths.WriteRoots(), r) || p.Paths.Protected.Covers(r+"/x.conf") {
			t.Errorf("%s: persistence root not writable: %+v", r, p.Paths)
		}
	}
	// A persistence root that is not a persistence area is a warning.
	p := f.mustLoad(t, withPaths("  persistence:\n    - path: /srv/app\n      acknowledge: \"x\"\n"))
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "paths.write") {
		t.Errorf("warnings %q", p.Warnings)
	}
}

func TestMatchers(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, withPaths("  read: [/etc]\n  write: [/srv/app]\n  deny: [\"/srv/app/secrets/**\"]\n"))
	for _, d := range []string{"/etc/shadow", "/etc/gshadow-", "/root/x", "/srv/app/.ssh/id_ed25519", "/srv/app/secrets/k", "/var/lib/shell-mcp/backups/x", "/etc/sudoers.d/x"} {
		if !p.Paths.Deny.Covers(d) {
			t.Errorf("deny does not cover %s", d)
		}
	}
	for _, d := range []string{"/etc/passwd", "/etc/shell-mcp/gate.yaml", "/srv/app/.git/HEAD", "/usr/local/bin/shell-mcp-gate", f.helper,
		"/etc/systemd/system/shell-mcp-privd@.service", "/etc/systemd/system/sockets.target.wants/shell-mcp-privd.socket",
		"/srv/app/.ssh/authorized_keys", "/srv/app/x/authorized_keys", "/srv/app/bin/shell-mcp-gate"} {
		if !p.Paths.Protected.Covers(d) {
			t.Errorf("protected does not cover %s", d)
		}
	}
	for _, d := range []string{"/srv/app/config.yaml", "/etc/example-app/x"} {
		if p.Paths.Protected.Covers(d) || p.Paths.Deny.Covers(d) {
			t.Errorf("%s is refused", d)
		}
	}
}

func TestOwners(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, head+"owners:\n  users: [nobody-here]\n", "owners.users")
	f.mustFail(t, head+"owners:\n  groups: [nobody-here]\n", "owners.groups")
	f.mustFail(t, head+"owners:\n  users: [root, root]\n", "duplicate")
	p := f.mustLoad(t, head+"owners:\n  users: [svc-shell]\n")
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "service account") {
		t.Errorf("chown to the gate's own account is not flagged: %q", p.Warnings)
	}
}

func TestModesMax(t *testing.T) {
	f := newFixture(t)
	for _, m := range []string{"4755", "2755", "1755", "6755", "0777", "0757", "abc", "07555", "75", "", "0o755", "-755"} {
		f.mustFail(t, head+fmt.Sprintf("modes:\n  max: %q\n", m), "modes.max")
	}
	for m, want := range map[string]os.FileMode{"0755": 0o755, "750": 0o750, "0640": 0o640, "0775": 0o775} {
		if p := f.mustLoad(t, head+fmt.Sprintf("modes:\n  max: %q\n", m)); p.ModesMax != want {
			t.Errorf("%s: %04o", m, p.ModesMax)
		}
	}
}

func TestBackups(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, head+"backups:\n  keep: -1\n", "backups.keep")
	f.mustFail(t, head+"backups:\n  keep: 101\n", "backups.keep")
	p := f.mustLoad(t, head+"backups:\n  keep: 0\n")
	if p.BackupsKeep != 0 || !strings.Contains(strings.Join(p.Warnings, "\n"), "backups") {
		t.Errorf("keep 0: %d %q", p.BackupsKeep, p.Warnings)
	}
}

func cmd(id, path, extra string) string {
	return fmt.Sprintf("  - id: %s\n    path: %s\n    tier: operator\n%s    templates: [[]]\n", id, path, extra)
}

func TestCommandListA(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"bash", "sh", "python3", "awk", "env", "xargs", "strace", "less", "vim", "sudo", "pkexec", "nsenter", "ssh", "rsync", "tmux", "useradd", "passwd", "crontab"} {
		p := f.exe(t, name, "denied "+name+"\n")
		f.mustFail(t, withCommand(cmd("x", p, "")), "never")
		f.mustFail(t, withCommand(cmd("x", p, "    acknowledge: \"really\"\n")), "never")
	}
	// Identity: a copy of a group 1 binary under an innocent name.
	f.exe(t, "innocent", "shell body\n")
	f.mustFail(t, withCommand(cmd("x", "{BIN}/innocent", "    acknowledge: \"really\"\n")), "never")
	// Built-in gate operations and this project's trust anchors.
	for _, name := range []string{"systemctl", "journalctl", "git", "shell-mcp-gate", "shell-mcp-privd", "shell-mcp"} {
		p := f.exe(t, name, "anchor "+name+"\n")
		f.mustFail(t, withCommand(cmd("x", p, "")), "may not")
	}
	f.mustFail(t, withCommand(cmd("x", "{HELPER}", "")), "may not")
}

func TestCommandListB(t *testing.T) {
	f := newFixture(t)
	for name, group := range map[string]int{"reboot": 11, "shutdown": 11, "modprobe": 12, "sysctl": 12, "mount": 12, "dd": 12, "nft": 13, "iptables": 13} {
		p := f.exe(t, name, "list b "+name+"\n")
		f.mustFail(t, withCommand(cmd("x", p, "")), "acknowledge")
		pol := f.mustLoad(t, withCommand(cmd("x", p, "    acknowledge: \"reviewed\"\n")))
		if c, _ := pol.Command("x"); c.ListB != group {
			t.Errorf("%s: list B group %d, want %d", name, c.ListB, group)
		}
	}
	// Identity: a copy of a firewall binary under an innocent name.
	f.exe(t, "fw-tool", "firewall body\n")
	f.mustFail(t, withCommand(cmd("x", "{BIN}/fw-tool", "")), "acknowledge")
	pol := f.mustLoad(t, withCommand(cmd("x", "{BIN}/fw-tool", "    acknowledge: \"reviewed\"\n")))
	if c, _ := pol.Command("x"); c.ListB != 13 {
		t.Errorf("identity list B group %d", c.ListB)
	}
}

func TestCommandBinaryChecks(t *testing.T) {
	f := newFixture(t)
	f.mustFail(t, withCommand(cmd("x", "{BIN}/missing", "")), "cannot be resolved")
	f.mustFail(t, withCommand(cmd("x", "bin/example-tool", "")), "commands")
	w := f.exe(t, "writable", "x\n")
	if err := os.Chmod(w, 0o775); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
		t.Fatal(err)
	}
	f.mustFail(t, withCommand(cmd("x", w, "")), "writable")
	n := f.exe(t, "noexec", "x\n")
	if err := os.Chmod(n, 0o644); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
		t.Fatal(err)
	}
	f.mustFail(t, withCommand(cmd("x", n, "")), "executable")
	d := f.exe(t, "docker", "container cli\n")
	f.mustFail(t, withCommand(cmd("x", d, "")), "root_equivalent")
	f.mustLoad(t, withCommand(cmd("x", d, "    root_equivalent: true\n")))
	f.mustFail(t, withCommand(cmd("Bad_ID", "{BIN}/example-tool", "")), "id")
	f.mustFail(t, withCommand(cmd("x", "{BIN}/example-tool", "")+cmd("x", "{BIN}/example-renew", "")), "duplicate")
	f.mustFail(t, withCommand("  - id: x\n    path: {BIN}/example-tool\n    tier: admin\n    templates: [[]]\n"), "tier")
	f.mustFail(t, withCommand("  - id: x\n    path: {BIN}/example-tool\n    tier: read\n    templates: []\n"), "templates")
	f.mustFail(t, withCommand("  - id: x\n    path: {BIN}/example-tool\n    tier: read\n    templates: [[\"{unit}\"]]\n"), "{unit}")
	f.mustFail(t, withCommand("  - id: x\n    path: {BIN}/example-tool\n    tier: read\n    templates: [[\"{bogus}\"]]\n"), "templates")
	f.mustFail(t, withCommand(cmd("x", "{BIN}/example-tool", "    acknowledge: \"two\\nlines\"\n")), "acknowledge")
	f.mustFail(t, withCommand(cmd("x", "{BIN}/example-tool", "    description: \"two\\nlines\"\n")), "description")
	f.mustFail(t, withCommand(cmd("x", "{BIN}/example-tool", "    unit: sideways\n")), "unit")
	p := f.mustLoad(t, "version: 1\nclient_uid: 60123\nsocket_group: svc-shell-priv\nmax_tier: read\ncommands:\n"+cmd("x", "{BIN}/example-tool", ""))
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "max_tier") {
		t.Errorf("above-max_tier command not warned: %q", p.Warnings)
	}
}

func TestCapabilities(t *testing.T) {
	f := newFixture(t)
	tool := "{BIN}/example-tool"
	f.mustFail(t, withCommand(cmd("x", tool, "    capabilities: [CAP_SYS_MODULE]\n")), "capabilities")
	f.mustFail(t, withCommand(cmd("x", tool, "    capabilities: [cap_kill]\n")), "capabilities")
	f.mustFail(t, withCommand(cmd("x", tool, "    capabilities: [CAP_KILL, CAP_KILL]\n")), "duplicate")
	f.mustFail(t, withCommand(cmd("x", tool, "    capabilities: [CAP_SYS_ADMIN]\n")), "root_equivalent")
	f.mustLoad(t, withCommand(cmd("x", tool, "    capabilities: [CAP_SYS_ADMIN]\n    root_equivalent: true\n")))
	// These three have no effect in the core unit (ProtectClock=yes drops
	// CAP_SYS_TIME; PrivateNetwork=yes and RestrictAddressFamilies=AF_UNIX
	// leave the network capabilities nothing to act on).
	for _, c := range []string{"CAP_SYS_TIME", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE"} {
		f.mustFail(t, withCommand(cmd("x", tool, "    capabilities: ["+c+"]\n")), "unit: broad")
	}
	p := f.mustLoad(t, withCommand(cmd("a", tool, "    capabilities: [CAP_KILL]\n")+cmd("b", "{BIN}/example-renew", "    capabilities: [CAP_SYS_BOOT, CAP_KILL]\n")))
	if !slices.Equal(p.Capabilities, []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_KILL", "CAP_SYS_BOOT"}) {
		t.Errorf("unit capabilities %v", p.Capabilities)
	}
}

func TestOwnershipOfPolicyFile(t *testing.T) {
	f := newFixture(t)
	p := f.put(t, head)
	if err := os.Chmod(p, 0o620); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
		t.Fatal(err)
	}
	if _, err := policy.Load(p, &f.opts); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable policy: %v", err)
	}
	p = f.put(t, head)
	if err := os.Chmod(f.etc, 0o775); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
		t.Fatal(err)
	}
	if _, err := policy.Load(p, &f.opts); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable directory: %v", err)
	}
	if err := os.Chmod(f.etc, 0o755); err != nil { //nolint:gosec // G302: a deliberately insecure or test fixture mode
		t.Fatal(err)
	}
	link := filepath.Join(f.etc, "link.yaml")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load("relative.yaml", &f.opts); err == nil {
		t.Fatal("relative policy path accepted")
	}
	big := head + "# " + strings.Repeat("x", policy.MaxPolicyBytes) + "\n"
	if _, err := f.load(t, big); err == nil {
		t.Fatal("oversized policy accepted")
	}
}

// Commands declared `unit: broad` run in the broad unit: they are
// root-equivalent (the unit has network and full root capabilities), are
// always reported, and never widen the core unit's bounding set.
func TestBroadCommands(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, withCommand(cmd("x", "{BIN}/example-renew", "    unit: broad\n")))
	if c, _ := p.Command("x"); c.Unit != policy.UnitBroad || !p.UsesBroad() {
		t.Fatalf("broad command %+v, uses broad %v", c, p.UsesBroad())
	}
	if !slices.ContainsFunc(p.Acknowledged, func(fd policy.Finding) bool { return fd.Kind == "root-equivalent" && fd.Item == "x" }) {
		t.Errorf("broad command not reported as root-equivalent: %+v", p.Acknowledged)
	}
	if f.mustLoad(t, withCommand(cmd("x", "{BIN}/example-renew", ""))).UsesBroad() {
		t.Error("a core command alone makes the policy use the broad unit")
	}
	// A broad command is validated like any other.
	f.mustFail(t, withCommand(cmd("x", "{BIN}/missing", "    unit: broad\n")), "cannot be resolved")
	bash := f.exe(t, "bash", "shell body\n")
	f.mustFail(t, withCommand(cmd("x", bash, "    unit: broad\n")), "never")
}

// CAP_SYS_TIME, CAP_NET_ADMIN and CAP_NET_BIND_SERVICE are valid on broad
// commands (and still refused on core ones, TestCapabilities); capabilities
// of broad commands never reach the core unit's bounding set. A broad
// CAP_SYS_TIME turns ProtectClock= off in the broad unit — the only
// directive a capability relaxes there.
func TestBroadCapabilities(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"CAP_SYS_TIME", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_KILL", "CAP_SYS_BOOT"} {
		p := f.mustLoad(t, withCommand(cmd("x", "{BIN}/example-renew", "    unit: broad\n    capabilities: ["+c+"]\n")))
		if !slices.Equal(p.Capabilities, policy.BaseCapabilities) {
			t.Errorf("%s on a broad command reached the core unit: %v", c, p.Capabilities)
		}
		if got, want := p.BroadProtectClock(), c != "CAP_SYS_TIME"; got != want {
			t.Errorf("%s: BroadProtectClock %v, want %v", c, got, want)
		}
	}
	f.mustFail(t, withCommand(cmd("x", "{BIN}/example-renew", "    unit: broad\n    capabilities: [CAP_SYS_ADMIN]\n")), "root_equivalent")
	if !f.mustLoad(t, head+"packages:\n  enabled: true\n  install: [htop]\n").BroadProtectClock() {
		t.Error("ProtectClock is off without a broad CAP_SYS_TIME")
	}
}

func TestPackages(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, head+"packages:\n  enabled: true\n  manager: apt\n  install: [htop, libfoo2.0, g++]\n  remove: [htop]\n  allow_update_index: true\n")
	if !p.Packages.Enabled || !p.UsesBroad() || !slices.Equal(p.Packages.Install, []string{"htop", "libfoo2.0", "g++"}) || !p.Packages.AllowUpdateIndex || p.Packages.AllowUpgrade {
		t.Fatalf("packages %+v, uses broad %v", p.Packages, p.UsesBroad())
	}
	if !slices.ContainsFunc(p.Acknowledged, func(fd policy.Finding) bool { return fd.Kind == "root-equivalent" && fd.Item == "packages" }) {
		t.Errorf("packages not reported as root-equivalent: %+v", p.Acknowledged)
	}
	if f.mustLoad(t, head+"packages:\n  enabled: false\n  install: [htop]\n").UsesBroad() {
		t.Error("disabled packages make the policy use the broad unit")
	}
	f.mustFail(t, head+"packages:\n  enabled: false\n  manager: dnf\n", "packages.manager")
	for _, name := range []string{"-rf", "Htop", "h", "../x", "htop jq", "a;b", "htop=1.0", "htop/stable", "htop:amd64"} {
		f.mustFail(t, head+fmt.Sprintf("packages:\n  install: [%q]\n", name), "packages.install")
	}
	// apt reads a trailing "-" on an install argument as "remove", and a
	// trailing "+" on a remove argument as "install", when no package has
	// that exact name: such names could turn one operation into the other.
	f.mustFail(t, head+"packages:\n  install: [htop-]\n", "packages.install")
	f.mustFail(t, head+"packages:\n  remove: [htop+]\n", "packages.remove")
	f.mustFail(t, head+"packages:\n  install: [htop, htop]\n", "duplicate")
	// Enabled packages need a root-owned, not group/other-writable apt-get.
	f.opts.AptGet = filepath.Join(f.bin, "missing-apt-get")
	f.mustFail(t, head+"packages:\n  enabled: true\n  install: [htop]\n", "packages")
	f.opts.AptGet = f.exe(t, "apt-get-writable", "apt\n")
	if err := os.Chmod(f.opts.AptGet, 0o775); err != nil { //nolint:gosec // G302: a deliberately insecure fixture mode
		t.Fatal(err)
	}
	f.mustFail(t, head+"packages:\n  enabled: true\n  install: [htop]\n", "writable")
}

// The built-in power operation (priv_power) needs a power section with a
// non-empty acknowledge; it runs in the broad unit and is always reported.
func TestPower(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, head+"power:\n  allowed: [reboot, poweroff]\n  acknowledge: \"maintenance windows\"\n")
	if !slices.Equal(p.Power.Allowed, []string{"reboot", "poweroff"}) || !p.UsesBroad() {
		t.Fatalf("power %+v, uses broad %v", p.Power, p.UsesBroad())
	}
	if !slices.ContainsFunc(p.Acknowledged, func(fd policy.Finding) bool { return fd.Kind == "power" }) {
		t.Errorf("power not reported: %+v", p.Acknowledged)
	}
	if p := f.mustLoad(t, head); p.UsesBroad() || len(p.Power.Allowed) != 0 {
		t.Errorf("no power section: %+v", p.Power)
	}
	for y, want := range map[string]string{
		"power:\n  allowed: [reboot]\n":                                      "power.acknowledge",
		"power:\n  allowed: [reboot]\n  acknowledge: \"\"\n":                 "power.acknowledge",
		"power:\n  allowed: [reboot]\n  acknowledge: \"two\\nlines\"\n":      "power.acknowledge",
		"power:\n  allowed: []\n  acknowledge: \"x\"\n":                      "power.allowed",
		"power:\n  acknowledge: \"x\"\n":                                     "power.allowed",
		"power:\n  allowed: [halt]\n  acknowledge: \"x\"\n":                  "power.allowed",
		"power:\n  allowed: [reboot, reboot]\n  acknowledge: \"x\"\n":        "duplicate",
		"power:\n  allowed: [reboot]\n  acknowledge: \"x\"\n  kexec: true\n": "field kexec not found",
	} {
		f.mustFail(t, head+y, want)
	}
	low := f.mustLoad(t, "version: 1\nclient_uid: 60123\nsocket_group: svc-shell-priv\nmax_tier: operator\npower:\n  allowed: [reboot]\n  acknowledge: \"x\"\n")
	if !strings.Contains(strings.Join(low.Warnings, "\n"), "power") {
		t.Errorf("power under max_tier operator is not warned: %q", low.Warnings)
	}
}
