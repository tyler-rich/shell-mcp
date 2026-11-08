//go:build linux

package setup_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/polkit"
	"github.com/tyler-rich/shell-mcp/internal/gate/setup"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// Several service accounts on one host (TARGET-SETUP §4, "A second service
// account"; §7 and §8 per account). The placeholders: svc-shell 60123 (the
// drop-in's first account), svc-shell-std 60125, svc-shell-ops 60126.
const (
	stdUser  = "svc-shell-std"
	stdKeys  = "/etc/ssh/authorized_keys.d/svc-shell-std"
	stdSlice = "/etc/systemd/system/user-60125.slice.d/50-shell-mcp.conf"
	stdRule  = "/etc/polkit-1/rules.d/60-shell-mcp-svc-shell-std.rules"
	stdKey   = "/root/in/std.pub"
	opPath   = "/etc/shell-mcp/operator.yaml"
	adPath   = "/etc/shell-mcp/admin.yaml"
	opSHA    = "1111111111111111111111111111111111111111111111111111111111111111"
	adSHA    = "2222222222222222222222222222222222222222222222222222222222222222"
)

var errNoSpace = errors.New("no space left on device")

// stdFlags installs the key stdKey for svc-shell-std (principal web), after
// baseArgs, whose values these replace.
func stdFlags(extra ...string) []string {
	return append([]string{"--user", stdUser, "--uid", "60125", "--gid", "60125", "--key", stdKey, "--principal", "web"}, extra...)
}

func operatorPolicy() *policy.Policy {
	p := readOnlyPolicy()
	p.MaxTier = policy.TierOperator
	p.Services.ControlUnits = []string{"example-app.service"}
	p.Services.ControlVerbs = []string{"restart"}
	p.SHA256 = opSHA
	return p
}

func adminPolicy() *policy.Policy {
	p := readOnlyPolicy()
	p.Privileged.Enabled = true
	p.SHA256 = adSHA
	return p
}

// withPolicies gives the fake the operator and admin policies by path.
func withPolicies(h *host) {
	h.pols = map[string]*policy.Policy{polPath: h.pol, opPath: operatorPolicy(), adPath: adminPolicy()}
	h.Put(opPath, "invented operator policy\n", 0o644, 0, 0)
	h.Put(adPath, "invented admin policy\n", 0o644, 0, 0)
}

// putKey writes a new server key file at p and returns its line.
func putKey(t *testing.T, h *host, p string) string {
	t.Helper()
	l := pubLine(t)
	h.Put(p, l+" shell-mcp\n", 0o644, 0, 0)
	return l
}

func rule(t *testing.T, user string, p *policy.Policy) string {
	t.Helper()
	r, err := polkit.Rule(&polkit.Spec{User: user, Units: p.Services.ControlUnits, Verbs: p.Services.ControlVerbs, PolicySHA256: p.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// refusals are the reasons of the run's refusal audit lines, sorted.
func refusals(t *testing.T, r result) []string {
	t.Helper()
	var out []string
	for _, l := range r.audit {
		var rec setupx.Record
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		if rec.Action == setupx.ActionRefuse {
			out = append(out, rec.Reason)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// twoAccounts installs svc-shell (the read-only key) and then svc-shell-std
// (the key stdKey) with install alone.
func twoAccounts(t *testing.T) *host {
	t.Helper()
	h, _ := newHost(t)
	withPolicies(h)
	if r := install(t, h); r.code != 0 {
		t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
	}
	putKey(t, h, stdKey)
	if r := install(t, h, stdFlags()...); r.code != 0 {
		t.Fatalf("svc-shell-std: %d\n%s", r.code, r.out)
	}
	return h
}

// TestInstallSecondAccount: a second account gets its own block appended
// to the same drop-in (one empty line between), its own slice and keys
// file; check-policy runs as it; the owner scan covers its ids; sshd is
// checked for both accounts and reloaded (PR #90's finding: a new block's
// keys are refused until sshd reloads). The same flags again, and the
// first account's flags again, change nothing; a third account appends a
// third block.
func TestInstallSecondAccount(t *testing.T) {
	h, _ := newHost(t)
	if r := install(t, h); r.code != 0 {
		t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
	}
	line := putKey(t, h, stdKey)
	h.runAs, h.scanned = nil, nil
	r := install(t, h, stdFlags()...)
	if r.code != 0 {
		t.Fatalf("svc-shell-std: %d\n%s", r.code, r.out)
	}
	want := map[string]string{
		dropPath: string(setup.DropIn("svc-shell")) + "\n" + string(setup.DropIn(stdUser)),
		stdSlice: "[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n",
		stdKeys: `restrict,from="192.0.2.10",command="/usr/local/bin/shell-mcp-gate serve --policy /etc/shell-mcp/read-only.yaml --principal web" ssh-ed25519 ` +
			strings.Fields(line)[1] + " shell-mcp-web\n",
	}
	for p, w := range want {
		if got, ok := h.Get(p); !ok || got != w {
			t.Errorf("%s:\n%q\nwant\n%q", p, got, w)
		}
		if e := h.Files[p]; e == nil || e.UID != 0 || e.GID != 0 || e.Mode != 0o644 {
			t.Errorf("%s: %+v", p, e)
		}
	}
	if !reflect.DeepEqual(h.runAs, []*execx.Credential{{UID: 60125, GID: 60125}}) {
		t.Fatalf("check-policy ran as %+v", h.runAs)
	}
	if !reflect.DeepEqual(h.scanned, [][]uint32{{60125, 60125}}) {
		t.Fatalf("owner scan for %v", h.scanned)
	}
	for _, seq := range [][]string{
		{"write " + dropPath, "write " + stdKeys, "sshd -t"},
		{"sshd -t", "sshd -T -C user=svc-shell,host=client.example.test,addr=192.0.2.10", "/usr/bin/systemctl reload ssh.service"},
		{"sshd -t", "sshd -T -C user=svc-shell-std,host=client.example.test,addr=192.0.2.10", "/usr/bin/systemctl reload ssh.service"},
	} {
		if !inOrder(h.order, seq) {
			t.Errorf("not in order %q:\n%s", seq, strings.Join(h.order, "\n"))
		}
	}
	if !strings.Contains(r.out, "     |+Match User svc-shell-std") {
		t.Errorf("no diff of the appended block:\n%s", r.out)
	}
	// The same flags again, the first account's again, and dry runs of both:
	// only unchanged, nothing written, no reload.
	for _, args := range [][]string{stdFlags(), nil, stdFlags("--dry-run"), {"--dry-run"}} {
		r := install(t, h, args...)
		done := "nothing to do: every item unchanged"
		if slices.Contains(args, "--dry-run") {
			done = "dry run: every check passed"
		}
		if r.code != 0 || !strings.Contains(r.out, done) || !reflect.DeepEqual(h.Snapshot(), r.before) {
			t.Fatalf("%v: %d, changed %v:\n%s", args, r.code, !reflect.DeepEqual(h.Snapshot(), r.before), r.out)
		}
		if strings.Contains(r.out, ": create") || strings.Contains(r.out, ": replace") {
			t.Fatalf("%v plans a change:\n%s", args, r.out)
		}
		for _, o := range h.order {
			if strings.HasSuffix(o, "reload ssh.service") || strings.HasPrefix(o, "write ") || strings.HasPrefix(o, "mkdir ") {
				t.Fatalf("%v ran %q", args, o)
			}
		}
	}
	// A third account appends a third block.
	putKey(t, h, "/root/in/ops.pub")
	r = install(t, h, "--user", "svc-shell-ops", "--uid", "60126", "--gid", "60126", "--key", "/root/in/ops.pub", "--principal", "ops")
	if r.code != 0 {
		t.Fatalf("svc-shell-ops: %d\n%s", r.code, r.out)
	}
	if got, _ := h.Get(dropPath); got != string(setup.DropInFor([]string{"svc-shell", stdUser, "svc-shell-ops"})) {
		t.Fatalf("drop-in with three accounts:\n%s", got)
	}
}

// TestInstallSecondAccountDryRun: the dry run for a second account writes
// nothing, runs only what reads, and shows the appended block.
func TestInstallSecondAccountDryRun(t *testing.T) {
	h, _ := newHost(t)
	if r := install(t, h); r.code != 0 {
		t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
	}
	putKey(t, h, stdKey)
	r := install(t, h, stdFlags("--dry-run")...)
	if r.code != 0 || !reflect.DeepEqual(h.Snapshot(), r.before) {
		t.Fatalf("exit %d, changed: %v\n%s", r.code, !reflect.DeepEqual(h.Snapshot(), r.before), r.out)
	}
	for _, s := range []string{"file " + dropPath + " root:root 0644: replace", "     |+Match User svc-shell-std", "would run /usr/bin/systemctl reload ssh.service",
		"would run /usr/sbin/groupadd --gid 60125 svc-shell-std"} {
		if !strings.Contains(r.out, s) {
			t.Errorf("dry run lacks %q:\n%s", s, r.out)
		}
	}
	if len(r.audit) != 0 {
		t.Fatalf("a dry run audited %v", r.audit)
	}
}

// handSplit applies PR #90's hand steps (TARGET-SETUP §4 "A second service
// account", §7 "With a second account" and "Moving a line", §8 "Per
// account") to a host install set up for svc-shell with two keys, the second
// (principal web, the operator policy) being moved to svc-shell-std. The
// drop-in is built as §7's commands build it ({ cat f; echo; sed '1s/…/' f;
// }), and the keys files as its grep commands do, not with install's
// renderers.
func handSplit(t *testing.T, h *host) {
	t.Helper()
	for _, c := range [][]string{
		{setupx.Groupadd, "--gid", "60125", stdUser},
		{setupx.Useradd, "--uid", "60125", "--gid", "60125", "--home-dir", "/var/lib/svc-shell-std", "--create-home", "--shell", "/bin/sh", stdUser},
		{setupx.Usermod, "-L", stdUser},
	} {
		if _, err := h.Fake.Simulate(c[0], c[1:]); err != nil {
			t.Fatal(err)
		}
	}
	h.Dir("/etc/systemd/system/user-60125.slice.d", 0o755, 0, 0)
	h.Put(stdSlice, "[Slice]\nMemoryMax=4G\nMemorySwapMax=0\n", 0o644, 0, 0)
	f, _ := h.Get(dropPath)
	first, rest, _ := strings.Cut(f, "\n")
	if first != "Match User svc-shell" {
		t.Fatalf("drop-in starts with %q", first)
	}
	h.Put(dropPath, f+"\n"+"Match User svc-shell-std\n"+rest, 0o644, 0, 0)
	keys, _ := h.Get(keysPath)
	var moved, kept string
	for _, l := range strings.SplitAfter(keys, "\n") {
		switch {
		case l == "":
		case strings.Contains(l, `--principal web"`):
			moved += l
		default:
			kept += l
		}
	}
	h.Put(stdKeys, moved, 0o644, 0, 0)
	h.Put(keysPath, kept, 0o644, 0, 0)
	h.Put(stdRule, rule(t, stdUser, operatorPolicy()), 0o644, 0, 0)
	delete(h.Files, setup.PolkitRule) // the moved key took svc-shell's only services.control
}

// TestInstallAdoptsHandSplit: a host split by hand with PR #90's steps
// reports only unchanged for install of both accounts, and byte for byte
// equals the same host taken to two accounts by install alone.
func TestInstallAdoptsHandSplit(t *testing.T) {
	build := func(t *testing.T) *host {
		h, _ := newHost(t)
		withPolicies(h)
		if r := install(t, h); r.code != 0 {
			t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
		}
		return h
	}
	h := build(t)
	webLine := putKey(t, h, stdKey)
	if r := install(t, h, "--policy", opPath, "--key", stdKey, "--principal", "web"); r.code != 0 {
		t.Fatalf("the shared layout's operator key: %d\n%s", r.code, r.out)
	}
	handSplit(t, h)
	for _, args := range [][]string{nil, stdFlags("--policy", opPath)} {
		writes := h.Writes
		r := install(t, h, args...)
		if r.code != 0 || !strings.Contains(r.out, "nothing to do: every item unchanged") || h.Writes != writes {
			t.Fatalf("install %v over the hand steps: %d:\n%s", args, r.code, r.out)
		}
	}
	// install alone, on a fresh host with the same keys.
	g := build(t)
	g.Put(stdKey, webLine+" shell-mcp\n", 0o644, 0, 0)
	if r := install(t, g, stdFlags("--policy", opPath)...); r.code != 0 {
		t.Fatalf("install alone: %d\n%s", r.code, r.out)
	}
	for _, p := range []string{dropPath, keysPath, stdKeys, stdSlice, stdRule, "/etc/passwd", "/etc/group"} {
		a, _ := h.Get(p)
		b, _ := g.Get(p)
		if a != b || h.Files[p].Mode != g.Files[p].Mode || h.Files[p].UID != g.Files[p].UID {
			t.Errorf("%s differs:\nhand:\n%s\ninstall:\n%s", p, a, b)
		}
	}
	if _, ok := g.Get(setup.PolkitRule); ok {
		t.Error("install alone wrote svc-shell's rule for a policy without services.control")
	}
}

// TestInstallDropInRefusals: dropin_other_account and file_differs refuse
// anything but a sequence of install's own blocks: a block install did not
// write, an edited block, a missing or extra empty line, a block twice.
// Each is refused before anything is written, for either account.
func TestInstallDropInRefusals(t *testing.T) {
	a, b := string(setup.DropIn("svc-shell")), string(setup.DropIn(stdUser))
	for _, c := range []struct {
		name, dropIn, reason string
		std                  bool
	}{
		{"a Match Group block after the first", a + "\nMatch Group admins\n    PermitTTY yes\n", "dropin_other_account", false},
		{"a Match Group block, for the second account", a + "\nMatch Group admins\n    PermitTTY yes\n", "dropin_other_account", true},
		{"a block for two users", "Match User svc-shell,svc-other\n" + a[len("Match User svc-shell\n"):], "dropin_other_account", true},
		{"a block that matches all", a + "\nMatch all\n    PermitTTY yes\n", "dropin_other_account", false},
		{"the second block edited", a + "\n" + strings.Replace(b, "PermitTTY no", "PermitTTY yes", 1), "file_differs", false},
		{"the first block edited, for the second account", strings.Replace(a, "MaxSessions 8", "MaxSessions 10", 1), "file_differs", true},
		{"no empty line between the blocks", a + b, "file_differs", false},
		{"two empty lines between the blocks", a + "\n\n" + b, "file_differs", false},
		{"an empty line at the end", a + "\n", "file_differs", true},
		{"a comment first", "# shell-mcp\n" + a, "file_differs", true},
		{"the same block twice", a + "\n" + a, "file_differs", true},
		{"no line break at the end", strings.TrimSuffix(a, "\n"), "file_differs", true},
		{"empty", "", "file_differs", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newHost(t)
			putKey(t, h, stdKey)
			h.Put(dropPath, c.dropIn, 0o644, 0, 0)
			var args []string
			if c.std {
				args = stdFlags()
			}
			r := install(t, h, args...)
			if got := refusals(t, r); r.code != 1 || !slices.Equal(got, []string{c.reason}) {
				t.Fatalf("exit %d, refusals %v, want [%s]:\n%s", r.code, got, c.reason, r.out)
			}
			if !reflect.DeepEqual(h.Snapshot(), r.before) {
				t.Fatal("a refused run changed the filesystem")
			}
		})
	}
}

// TestParseDropIn: the accounts of a drop-in install wrote, in order.
func TestParseDropIn(t *testing.T) {
	for _, users := range [][]string{{"svc-shell"}, {"svc-shell", stdUser}, {stdUser, "svc-shell", "svc-shell-ops"}} {
		got, err := setup.ParseDropIn(setup.DropInFor(users))
		if err != nil || !slices.Equal(got, users) {
			t.Fatalf("%v: %v, %v", users, got, err)
		}
	}
}

// TestInstallSecondAccountRefusals: every S8-1 refusal applies to the
// second account as to the first, and is the only refusal: ids in use (the
// first account's own), the from= floor, privileged and other supplementary
// groups (the helper's socket group for a policy without privileged
// forwarding: S8 Q5 and PR #90), the socket group missing for one with it,
// and the owner scan of its new ids.
func TestInstallSecondAccountRefusals(t *testing.T) {
	member := func(group string) func(*host) {
		return func(h *host) {
			for _, c := range [][]string{{setupx.Groupadd, "--gid", "60125", stdUser},
				{setupx.Useradd, "--uid", "60125", "--gid", "60125", "--home-dir", "/var/lib/svc-shell-std", "--create-home", "--shell", "/bin/sh", stdUser},
				{setupx.Usermod, "-aG", group, stdUser}} {
				_, _ = h.Fake.Simulate(c[0], c[1:])
			}
		}
	}
	for _, c := range []struct {
		name   string
		mod    func(*host)
		args   []string
		reason string
		text   string
	}{
		{"the first account's uid", nil, []string{"--uid", "60123"}, "uid_in_use", "uid 60123 is already account svc-shell's"},
		{"the first account's gid", nil, []string{"--gid", "60123"}, "gid_in_use", "gid 60123 is already group svc-shell's"},
		{"the socket group's gid", nil, []string{"--gid", "60124"}, "gid_in_use", "gid 60124 is already group svc-shell-priv's"},
		{"from /16", nil, []string{"--from", "192.0.0.0/16"}, "from", "floor for IPv4"},
		{"in the helper's socket group without forwarding", member("svc-shell-priv"), nil, "supplementary_group", "member of svc-shell-priv"},
		{"in docker", member("docker"), nil, "privileged_group", "member of docker, a privileged group"},
		{"a forwarding policy without the socket group", nil, []string{"--policy", adPath}, "socket_group", "give --socket-group and --socket-gid"},
		{"its new ids own files", func(h *host) { h.scan.Hit = "/srv/app/data/old.db" }, nil, "id_owns_files", "is owned by one of the new ids"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newHost(t)
			withPolicies(h)
			if r := install(t, h, "--policy", adPath, "--socket-group", "svc-shell-priv", "--socket-gid", "60124"); r.code != 0 {
				t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
			}
			putKey(t, h, stdKey)
			if c.mod != nil {
				c.mod(h)
			}
			h.scanned = nil
			r := install(t, h, stdFlags(c.args...)...)
			if got := refusals(t, r); r.code != 1 || !slices.Equal(got, []string{c.reason}) || !strings.Contains(r.out, c.text) {
				t.Fatalf("exit %d, refusals %v, want [%s] with %q:\n%s", r.code, got, c.reason, c.text, r.out)
			}
			if !reflect.DeepEqual(h.Snapshot(), r.before) {
				t.Fatal("a refused run changed the filesystem")
			}
			if c.reason == "id_owns_files" && !reflect.DeepEqual(h.scanned, [][]uint32{{60125, 60125}}) {
				t.Fatalf("owner scan for %v, want the second account's ids", h.scanned)
			}
		})
	}
}

// TestInstallPolkitPerAccount: the drop-in's first account keeps
// 60-shell-mcp.rules; any other account's rule is 60-shell-mcp-<user>.rules,
// exactly polkit's output for its policy and name, and only when its policy
// has services.control.
func TestInstallPolkitPerAccount(t *testing.T) {
	t.Run("only the second account has services.control", func(t *testing.T) {
		h := twoAccounts(t)
		if r := install(t, h, stdFlags("--policy", opPath, "--key", stdKey, "--replace-key")...); r.code != 0 {
			t.Fatalf("%d\n%s", r.code, r.out)
		}
		if got, ok := h.Get(stdRule); !ok || got != rule(t, stdUser, operatorPolicy()) || h.Files[stdRule].Mode != 0o644 || h.Files[stdRule].UID != 0 {
			t.Fatalf("%s: %q", stdRule, got)
		}
		if _, ok := h.Get(setup.PolkitRule); ok {
			t.Fatal("60-shell-mcp.rules written for the second account")
		}
	})
	t.Run("both accounts", func(t *testing.T) {
		h, _ := newHost(t)
		withPolicies(h)
		if r := install(t, h, "--policy", opPath); r.code != 0 {
			t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
		}
		putKey(t, h, stdKey)
		if r := install(t, h, stdFlags("--policy", opPath)...); r.code != 0 {
			t.Fatalf("svc-shell-std: %d\n%s", r.code, r.out)
		}
		if got, _ := h.Get(setup.PolkitRule); got != rule(t, "svc-shell", operatorPolicy()) {
			t.Fatalf("svc-shell's rule:\n%s", got)
		}
		if got, _ := h.Get(stdRule); got != rule(t, stdUser, operatorPolicy()) {
			t.Fatalf("svc-shell-std's rule:\n%s", got)
		}
		for _, args := range [][]string{{"--policy", opPath}, stdFlags("--policy", opPath)} {
			if r := install(t, h, args...); r.code != 0 || !strings.Contains(r.out, "nothing to do") {
				t.Fatalf("again %v: %d\n%s", args, r.code, r.out)
			}
		}
	})
	t.Run("no services.control, no rule", func(t *testing.T) {
		h := twoAccounts(t)
		if _, ok := h.Get(stdRule); ok {
			t.Fatal("a rule for a policy without services.control")
		}
	})
	t.Run("another account's rule differs", func(t *testing.T) {
		h, _ := newHost(t)
		withPolicies(h)
		if r := install(t, h); r.code != 0 {
			t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
		}
		putKey(t, h, stdKey)
		h.Put(stdRule, "// hand-written\n", 0o644, 0, 0)
		r := install(t, h, stdFlags("--policy", opPath)...)
		if got := refusals(t, r); r.code != 1 || !slices.Equal(got, []string{"file_differs"}) || !strings.Contains(r.out, stdRule+" exists with other content") {
			t.Fatalf("exit %d, %v:\n%s", r.code, got, r.out)
		}
	})
}

// TestInstallSecondAccountRollback: when a check after the writes fails,
// the drop-in gets its one block back, and every file the run created for
// the second account is gone, with no temp file left: the second account's
// block not in force, the first account's block no longer in force after
// the append, and a failed write of the keys file.
func TestInstallSecondAccountRollback(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*host)
		want string
	}{
		{"the second block is not in force", func(h *host) {
			h.sshdOverrideFor = map[string]map[string]string{stdUser: {"permittty": "yes"}}
		}, "user=svc-shell-std"},
		{"the first block is no longer in force", func(h *host) {
			h.sshdOverrideFor = map[string]map[string]string{"svc-shell": {"maxsessions": "10"}}
		}, "user=svc-shell,"},
		{"the keys file cannot be written", func(h *host) { h.FailWrite[stdKeys] = errNoSpace }, "no space"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newHost(t)
			if r := install(t, h); r.code != 0 {
				t.Fatalf("svc-shell: %d\n%s", r.code, r.out)
			}
			putKey(t, h, stdKey)
			c.mod(h)
			r := install(t, h, stdFlags()...)
			if r.code != 1 || !strings.Contains(r.out, c.want) || !strings.Contains(r.out, "every file this run changed was restored") {
				t.Fatalf("exit %d:\n%s", r.code, r.out)
			}
			after := h.Snapshot()
			for p, e := range r.before {
				if p == "/etc/passwd" || p == "/etc/group" {
					continue
				}
				if !reflect.DeepEqual(after[p], e) {
					t.Errorf("%s not restored", p)
				}
			}
			for p := range after {
				if _, ok := r.before[p]; !ok && p != "/var/lib/svc-shell-std" {
					t.Errorf("%s left behind", p)
				}
			}
			if got, _ := h.Get(dropPath); got != string(setup.DropIn("svc-shell")) {
				t.Fatalf("drop-in after the rollback:\n%s", got)
			}
		})
	}
}
