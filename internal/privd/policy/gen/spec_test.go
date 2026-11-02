//go:build linux

package gen_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	ggen "github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/setuptest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy/gen"
)

const out = "/etc/shell-mcp/privileged.yaml"

// testLoad is the privileged loader as check-policy runs it, with the
// test's trust (the repository checkout is not root's) and an invented
// user and group database.
func testLoad(data []byte, p string) (*policy.Policy, error) {
	ids := map[string]uint32{"root": 0, "example-app": 1001, "svc-shell-priv": 60124}
	lookup := func(n string) (uint32, error) {
		if id, ok := ids[n]; ok {
			return id, nil
		}
		return 0, errors.New("unknown")
	}
	return policy.Parse(data, p, &policy.LoadOptions{Trust: gatetest.Trust(), HelperExecutable: "/usr/local/libexec/shell-mcp-privd",
		LookupUser: lookup, LookupGroup: lookup, UserName: func(uint32) string { return "" }})
}

// privHost is a fake target with the socket group (created by
// shell-mcp-gate install) and the answers at /root/setup.yaml.
func privHost(t *testing.T, answers string) *setuptest.Fake {
	t.Helper()
	f := setuptest.New()
	f.Put("/etc/group", "root:x:0:\nsvc-shell-priv:x:60124:svc-shell\nexample-app:x:1001:\n", 0o644, 0, 0)
	f.Dir("/root", 0o700, 0, 0)
	f.Put("/root/setup.yaml", answers, 0o600, 0, 0)
	return f
}

func runPriv(t *testing.T, f *setuptest.Fake, o *ggen.Options, checkCode int) (code int, stdout, stderr string, checks []string) {
	t.Helper()
	check := func(p string, w io.Writer) int {
		checks = append(checks, p)
		_, _ = io.WriteString(w, "privileged check-policy output\n")
		return checkCode
	}
	var so, se bytes.Buffer
	a := &setupx.Auditor{Stderr: &se, Tag: "shell-mcp-privd", Component: "privd", DryRun: o.DryRun || o.Out == "-"}
	code = ggen.Run(o, gen.Spec(f, testLoad, check), f, &so, &se, a)
	return code, so.String(), se.String(), checks
}

func adminSrc(t *testing.T) string {
	t.Helper()
	return string(readFile(t, examples+"/policies/admin.answers.yaml"))
}

// TestSpecWrites: the privileged policy is written root:root 0600, the
// helper's check-policy runs on it, and the write is audited with the
// preset; a second run is unchanged.
func TestSpecWrites(t *testing.T) {
	f := privHost(t, adminSrc(t))
	code, so, se, checks := runPriv(t, f, &ggen.Options{Answers: "/root/setup.yaml", Out: out}, 0)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, so)
	}
	want, err := gen.Render(adminAnswers(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Files[out]; got == nil || !bytes.Equal(got.Data, want) || got.Mode != 0o600 || got.UID != 0 || got.GID != 0 {
		t.Fatalf("written: %+v", got)
	}
	if !reflect.DeepEqual(checks, []string{out}) || !strings.Contains(so, "privileged check-policy output") || !strings.Contains(so, "--accept") {
		t.Fatalf("check-policy %v\n%s", checks, so)
	}
	if !strings.Contains(se, `"component":"privd","action":"create","object":"policy","path":"`+out+`"`) || !strings.Contains(se, `"mode":"0600"`) ||
		!strings.Contains(se, `"preset":"admin"`) {
		t.Fatalf("audit:\n%s", se)
	}
	before := f.Snapshot()
	if code, so, _, _ := runPriv(t, f, &ggen.Options{Answers: "/root/setup.yaml", Out: out}, 0); code != 0 || !strings.Contains(so, "unchanged") ||
		!reflect.DeepEqual(f.Snapshot(), before) {
		t.Fatalf("second run: exit %d\n%s", code, so)
	}
	if tmp := f.Temps(); len(tmp) > 0 {
		t.Fatalf("temp files: %v", tmp)
	}
}

// TestSpecSocketGroup: the privileged loader needs the socket group, which
// shell-mcp-gate install creates, so before install the command refuses
// and says to run install first; a group with another gid is refused.
func TestSpecSocketGroup(t *testing.T) {
	for _, c := range []struct{ group, want string }{
		{"root:x:0:\n", "the group svc-shell-priv does not exist on this host yet; run shell-mcp-gate install (with --socket-group svc-shell-priv --socket-gid 60124)"},
		{"root:x:0:\nsvc-shell-priv:x:60999:\n", "answers root.socket_group.gid: 60124, but the local group svc-shell-priv has gid 60999"},
	} {
		f := privHost(t, adminSrc(t))
		f.Put("/etc/group", c.group, 0o644, 0, 0)
		before := f.Snapshot()
		for _, o := range []string{out, "-"} {
			code, so, se, checks := runPriv(t, f, &ggen.Options{Answers: "/root/setup.yaml", Out: o}, 0)
			if code != 1 || !strings.Contains(so+se, c.want) || !reflect.DeepEqual(f.Snapshot(), before) || len(checks) != 0 {
				t.Fatalf("--out %s: exit %d\n%s%s", o, code, so, se)
			}
		}
	}
}

// TestSpecNeedsRoot: answers without root: are refused.
func TestSpecNeedsRoot(t *testing.T) {
	f := privHost(t, string(readFile(t, examples+"/policies/operator.answers.yaml")))
	before := f.Snapshot()
	if code, so, _, _ := runPriv(t, f, &ggen.Options{Answers: "/root/setup.yaml", Out: out}, 0); code != 1 ||
		!strings.Contains(so, "answers root: is absent") || !reflect.DeepEqual(f.Snapshot(), before) {
		t.Fatalf("exit %d\n%s", code, so)
	}
}

const rootBase = "preset: admin\naccount: { user: svc-shell, uid: 60123 }\nroot:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n"

// TestSpecListsRefused: the privileged loader refuses, before anything is
// written, a root on the never list (PRIVILEGED §5.3 list A) naming that
// rule, and a list B item without its acknowledge naming the key to add.
func TestSpecListsRefused(t *testing.T) {
	for _, c := range []struct{ name, root, want string }{
		{"write root on list A", "  write: [/etc/ssh]\n", "answers root.write[0]: /etc/ssh is, or is inside, a path on the never list (PRIVILEGED §5.3 list A)"},
		{"write root around list A", "  write: [/etc/polkit-1/rules.d/x]\n", "answers root.write[0]: /etc/polkit-1/rules.d/x is, or is inside, a path on the never list"},
		{"write root over the policies", "  write: [/etc]\n", "answers root.write[0]: /etc contains a path on the never list"},
		{"read root on list A", "  read: [/etc/sudoers.d]\n", "answers root.read[0]: /etc/sudoers.d is, or is inside, a path on the never list"},
		{"persistence on list A", "  persistence: [{ path: /etc/ssh/sshd_config.d, acknowledge: \"x\" }]\n", "answers root.persistence[0].path: /etc/ssh/sshd_config.d is, or is inside, a path on the never list"},
		{"persistence without acknowledge", "  persistence: [{ path: /etc/systemd/system/example-app.service.d }]\n", "answers root.persistence[0].acknowledge: is required"},
		{"protected write root", "  write: [/etc/systemd/system/example-app.service.d]\n", "answers root.write[0]: /etc/systemd/system/example-app.service.d is, is inside, or contains a protected path (POLICY §3); declare it under paths.persistence with an acknowledge"},
		{"power without acknowledge", "  power: { allowed: [reboot] }\n", "answers root.power.acknowledge: is required"},
		{"find action without acknowledge", "  commands:\n    - { id: clean-cache, path: /usr/bin/find, tier: destructive, templates: [[\"{path:write}\", \"-delete\"]] }\n",
			"answers root.commands[clean-cache].acknowledge:"},
		{"shell", "  commands:\n    - { id: shell, path: /bin/sh, tier: read, templates: [[\"-c\", \"true\"]] }\n", "answers root.commands[shell]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := privHost(t, rootBase+c.root)
			before := f.Snapshot()
			code, so, se, checks := runPriv(t, f, &ggen.Options{Answers: "/root/setup.yaml", Out: out}, 0)
			if code != 1 || !strings.Contains(so, c.want) || !reflect.DeepEqual(f.Snapshot(), before) || len(checks) != 0 {
				t.Fatalf("exit %d\n%s%s", code, so, se)
			}
			if c.name == "find action without acknowledge" && !strings.Contains(so, "acknowledge") {
				t.Fatalf("does not name the acknowledge:\n%s", so)
			}
		})
	}
}

// TestSpecCheckPolicyFailRollsBack: a FAIL from the helper's check-policy
// after the write removes the file and the directory the run created.
func TestSpecCheckPolicyFailRollsBack(t *testing.T) {
	f := privHost(t, adminSrc(t))
	before := f.Snapshot()
	if code, so, _, _ := runPriv(t, f, &ggen.Options{Answers: "/root/setup.yaml", Out: out}, 1); code != 1 || !reflect.DeepEqual(f.Snapshot(), before) {
		t.Fatalf("exit %d or not rolled back\n%s", code, so)
	}
}

// TestField: loader fields name their answers keys.
func TestField(t *testing.T) {
	for in, want := range map[string]string{
		"privileged policy: client_uid: 0 is not in 1..4294967294":    "answers account.uid: 0 is not in 1..4294967294",
		"privileged policy: socket_group: group \"x\" does not exist": "answers root.socket_group.name: group \"x\" does not exist",
		"privileged policy: paths.deny[2]: bad glob":                  "answers deny[2]: bad glob",
		"privileged policy: owners.users[0]: \"x\" does not exist":    "answers root.owners.users[0]: \"x\" does not exist",
		"privileged policy: packages.install[1]: bad name":            "answers root.packages.install[1]: bad name",
		"privileged policy: limits.max_timeout_s: 9 is not in range":  "the admin preset's limits.max_timeout_s: 9 is not in range",
		"privileged policy: policy is empty":                          "answers: policy is empty",
		"something else":                                              "something else",
	} {
		if got := gen.Field(in, "admin"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
