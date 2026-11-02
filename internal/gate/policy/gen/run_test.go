//go:build linux

package gen_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/setuptest"
)

const out = "/etc/shell-mcp/operator.yaml"

// host is a fake target holding the operator example's answers at
// /root/setup.yaml.
func host(t *testing.T) *setuptest.Fake {
	t.Helper()
	f := setuptest.New()
	f.Dir("/root", 0o700, 0, 0)
	f.Put("/root/setup.yaml", string(readFile(t, filepath.Join(examples, "policies", "operator.answers.yaml"))), 0o600, 0, 0)
	return f
}

// fakeSpec is the gate's Spec with a loader that accepts (or returns
// loadErr) and a check-policy that exits checkCode; calls records the
// paths check-policy ran on.
type fakeSpec struct {
	loadErr   error
	checkCode int
	loads     []string
	checks    []string
}

func (sp *fakeSpec) spec(mode fs.FileMode) *gen.Spec {
	return &gen.Spec{
		Command:    "shell-mcp-gate policy new",
		Kind:       "gate policy",
		Mode:       mode,
		DefaultOut: func(a *gen.Answers) string { return gen.Dir + "/" + a.Preset + ".yaml" },
		Render:     gen.RenderGate,
		Load: func(_ []byte, p string, _ *gen.Answers) ([]string, error) {
			sp.loads = append(sp.loads, p)
			return []string{"a loader warning"}, sp.loadErr
		},
		Field: gen.GateField,
		CheckPolicy: func(p string, w io.Writer) int {
			sp.checks = append(sp.checks, p)
			_, _ = io.WriteString(w, "check-policy output\n")
			return sp.checkCode
		},
		Notes: []string{"a note"},
	}
}

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, f *setuptest.Fake, s *gen.Spec, args ...string) result {
	t.Helper()
	o, err := gen.ParseFlags(args, "/root")
	if err != nil {
		t.Fatalf("flags %q: %v", args, err)
	}
	var so, se bytes.Buffer
	a := &setupx.Auditor{Stderr: &se, Tag: "shell-mcp-gate", Component: "gate", DryRun: o.DryRun || o.Out == "-"}
	code := gen.Run(o, s, f, &so, &se, a)
	return result{code, so.String(), se.String()}
}

func rendered(t *testing.T) []byte {
	t.Helper()
	b, err := gen.RenderGate(decodeFile(t, filepath.Join(examples, "policies", "operator.answers.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noTemps(t *testing.T, f *setuptest.Fake) {
	t.Helper()
	if tmp := f.Temps(); len(tmp) > 0 {
		t.Fatalf("temp files left: %v", tmp)
	}
}

// TestRunWrites: the policy is written root:root with the spec's mode,
// /etc/shell-mcp created 0755, check-policy run on it, the write audited
// with the preset (POLICY §9.4).
func TestRunWrites(t *testing.T) {
	for _, mode := range []fs.FileMode{0o644, 0o600} {
		f, sp := host(t), &fakeSpec{}
		r := run(t, f, sp.spec(mode), "--answers", "setup.yaml", "--out", out)
		if r.code != 0 {
			t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
		}
		got := f.Files[out]
		if got == nil || !bytes.Equal(got.Data, rendered(t)) || got.Mode != mode || got.UID != 0 || got.GID != 0 {
			t.Fatalf("written: %+v", got)
		}
		if d := f.Files[gen.Dir]; d == nil || d.Mode != fs.ModeDir|0o755 || d.UID != 0 {
			t.Fatalf("directory: %+v", d)
		}
		if !reflect.DeepEqual(sp.checks, []string{out}) || !reflect.DeepEqual(sp.loads, []string{out}) {
			t.Fatalf("loads %v, checks %v", sp.loads, sp.checks)
		}
		for _, want := range []string{"WARN a loader warning", "check-policy output", "NOTE a note", "written: " + out} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
			}
		}
		for _, want := range []string{`"action":"create","object":"policy","path":"` + out + `","sha256":"` + setupx.Hash(rendered(t)) + `"`,
			`"preset":"operator"`, `"owner":"root:root"`, `"action":"create","object":"directory","path":"/etc/shell-mcp"`} {
			if !strings.Contains(r.stderr, want) {
				t.Errorf("audit lacks %q:\n%s", want, r.stderr)
			}
		}
		if strings.Contains(r.stderr, "max_tier") || strings.Contains(r.stderr, "/srv/app") {
			t.Errorf("the audit holds the policy's content:\n%s", r.stderr)
		}
		noTemps(t, f)
	}
}

// TestRunSecondRunUnchanged: the same answers again change nothing and say
// unchanged (§3.2's owned class).
func TestRunSecondRunUnchanged(t *testing.T) {
	f, sp := host(t), &fakeSpec{}
	if r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out); r.code != 0 {
		t.Fatalf("first run: %d\n%s", r.code, r.stdout)
	}
	before, writes := f.Snapshot(), f.Writes
	r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out)
	if r.code != 0 || !strings.Contains(r.stdout, out+": unchanged") || !strings.Contains(r.stdout, "nothing to do") {
		t.Fatalf("second run: %d\n%s", r.code, r.stdout)
	}
	if f.Writes != writes || !reflect.DeepEqual(f.Snapshot(), before) || strings.Contains(r.stderr, `"action":"create"`) {
		t.Fatalf("the second run changed something:\n%s", r.stderr)
	}
}

// TestRunRefusesDifferentFile: an existing policy with other content,
// owner or mode is refused, never overwritten; content shows a diff.
func TestRunRefusesDifferentFile(t *testing.T) {
	for name, put := range map[string]func(*setuptest.Fake){
		"content": func(f *setuptest.Fake) { f.Put(out, "version: 1\nmax_tier: read\n", 0o644, 0, 0) },
		"mode":    func(f *setuptest.Fake) { f.Put(out, string(rendered(t)), 0o664, 0, 0) },
		"owner":   func(f *setuptest.Fake) { f.Put(out, string(rendered(t)), 0o644, 1000, 0) },
		"a dir":   func(f *setuptest.Fake) { f.Dir(out, 0o755, 0, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			f, sp := host(t), &fakeSpec{}
			f.Dir(gen.Dir, 0o755, 0, 0)
			put(f)
			before := f.Snapshot()
			r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out)
			if r.code != 1 || !reflect.DeepEqual(f.Snapshot(), before) || len(sp.checks) != 0 {
				t.Fatalf("exit %d, changed or checked\n%s", r.code, r.stdout)
			}
			if name == "content" && !strings.Contains(r.stdout, "--- "+out+" (on the host)") {
				t.Errorf("no diff:\n%s", r.stdout)
			}
			if !strings.Contains(r.stderr, `"action":"refuse"`) || !strings.Contains(r.stderr, `"reason":"file_differs"`) {
				t.Errorf("refusal not audited:\n%s", r.stderr)
			}
		})
	}
}

// TestRunRefusesDirectory: /etc/shell-mcp must be a root:root 0755
// directory, under a chain root owns.
func TestRunRefusesDirectory(t *testing.T) {
	for name, put := range map[string]func(*setuptest.Fake){
		"mode":   func(f *setuptest.Fake) { f.Dir(gen.Dir, 0o750, 0, 0) },
		"owner":  func(f *setuptest.Fake) { f.Dir(gen.Dir, 0o755, 1000, 0) },
		"a file": func(f *setuptest.Fake) { f.Put(gen.Dir, "x", 0o644, 0, 0) },
		"chain":  func(f *setuptest.Fake) { f.Dir("/etc", 0o777, 0, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			f, sp := host(t), &fakeSpec{}
			put(f)
			before := f.Snapshot()
			if r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out); r.code != 1 || !reflect.DeepEqual(f.Snapshot(), before) {
				t.Fatalf("exit %d or changed\n%s", r.code, r.stdout)
			}
		})
	}
}

// TestRunDryRun: --dry-run writes nothing, audits nothing, runs no
// check-policy, and shows the file and its class.
func TestRunDryRun(t *testing.T) {
	f, sp := host(t), &fakeSpec{}
	before := f.Snapshot()
	r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out, "--dry-run")
	if r.code != 0 || !reflect.DeepEqual(f.Snapshot(), before) || len(sp.checks) != 0 || r.stderr != "" {
		t.Fatalf("exit %d, changed, checked or audited\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{"file " + out + " root:root 0644: create", "directory /etc/shell-mcp root:root 0755: create",
		"     | max_tier: operator", "would run shell-mcp-gate check-policy --policy " + out} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("dry run lacks %q:\n%s", want, r.stdout)
		}
	}
}

// TestRunStdout: --out - prints exactly the policy on stdout, writes
// nothing, needs no root, and puts the report on stderr.
func TestRunStdout(t *testing.T) {
	f, sp := host(t), &fakeSpec{}
	f.EUID = 60123
	before := f.Snapshot()
	r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", "-")
	if r.code != 0 || r.stdout != string(rendered(t)) || !reflect.DeepEqual(f.Snapshot(), before) || len(sp.checks) != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	if !reflect.DeepEqual(sp.loads, []string{"/etc/shell-mcp/operator.yaml"}) || !strings.Contains(r.stderr, "loads strictly") {
		t.Fatalf("not loaded strictly before printing: %v\n%s", sp.loads, r.stderr)
	}
}

// TestRunRefusals: a forced command, a non-root writer and an --out
// outside /etc/shell-mcp are refused before anything else, and nothing is
// written.
func TestRunRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*setuptest.Fake)
		out  string
		want string
	}{
		{"forced command", func(f *setuptest.Fake) { f.Env["SSH_ORIGINAL_COMMAND"] = "x" }, out, "SSH_ORIGINAL_COMMAND"},
		{"forced command printing", func(f *setuptest.Fake) { f.Env["SSH_ORIGINAL_COMMAND"] = "x" }, "-", "SSH_ORIGINAL_COMMAND"},
		{"not root", func(f *setuptest.Fake) { f.EUID = 60123 }, out, "root only"},
		{"outside", nil, "/tmp/operator.yaml", "must be - or /etc/shell-mcp/<name>.yaml"},
		{"deeper", nil, "/etc/shell-mcp/sub/operator.yaml", "must be"},
		{"dot dot", nil, "/etc/shell-mcp/../operator.yaml", "must be"},
		{"relative", nil, "operator.yaml", "must be"},
		{"no yaml", nil, "/etc/shell-mcp/operator", "must be"},
		{"space", nil, "/etc/shell-mcp/my policy.yaml", "must be"},
		{"leading dot", nil, "/etc/shell-mcp/.operator.yaml", "must be"},
		{"shell metacharacter", nil, "/etc/shell-mcp/a;b.yaml", "must be"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, sp := host(t), &fakeSpec{}
			if c.mod != nil {
				c.mod(f)
			}
			before := f.Snapshot()
			r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", c.out)
			report := r.stdout + r.stderr
			if r.code != 1 || !strings.Contains(report, c.want) || !reflect.DeepEqual(f.Snapshot(), before) || len(sp.loads) != 0 {
				t.Fatalf("exit %d, loads %v\n%s", r.code, sp.loads, report)
			}
		})
	}
}

// TestRunAnswersFile: a missing, unreadable or refused answers file
// writes nothing; one another account can write gets a WARN.
func TestRunAnswersFile(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*setuptest.Fake)
		code int
		want string
	}{
		{"missing", func(f *setuptest.Fake) { delete(f.Files, "/root/setup.yaml") }, 1, "does not exist"},
		{"directory", func(f *setuptest.Fake) { delete(f.Files, "/root/setup.yaml"); f.Dir("/root/setup.yaml", 0o755, 0, 0) }, 1, "not a regular file"},
		{"refused", func(f *setuptest.Fake) { f.Put("/root/setup.yaml", "preset: read-only\nsudo: true\n", 0o600, 0, 0) }, 1, "field sudo not found"},
		{"preset rule", func(f *setuptest.Fake) {
			f.Put("/root/setup.yaml", minimal+"write: [/srv/app/config]\n", 0o600, 0, 0)
		}, 1, "answers write: is not allowed under the read-only preset"},
		{"another owner", func(f *setuptest.Fake) {
			f.Put("/root/setup.yaml", string(readFile(t, filepath.Join(examples, "policies", "operator.answers.yaml"))), 0o600, 1000, 1000)
		}, 0, "WARN --answers /root/setup.yaml is 1000:1000 0600"},
		{"group-writable", func(f *setuptest.Fake) {
			f.Put("/root/setup.yaml", string(readFile(t, filepath.Join(examples, "policies", "operator.answers.yaml"))), 0o664, 0, 0)
		}, 0, "WARN --answers /root/setup.yaml is 0:0 0664"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, sp := host(t), &fakeSpec{}
			c.mod(f)
			before := f.Snapshot()
			r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out, "--dry-run")
			if r.code != c.code || !strings.Contains(r.stdout, c.want) || !reflect.DeepEqual(f.Snapshot(), before) {
				t.Fatalf("exit %d\n%s", r.code, r.stdout)
			}
		})
	}
}

// TestRunLoaderRefusalWritesNothing: a policy its loader refuses is never
// written, and each error names its answers key.
func TestRunLoaderRefusalWritesNothing(t *testing.T) {
	f := host(t)
	sp := &fakeSpec{loadErr: errors.Join(
		errors.New("policy: paths.write[0]: /etc/ssh is, or is inside, a protected path"),
		errors.New("policy: commands[apt-upgradable]: /usr/bin/apt is not owned by root"),
		errors.New("policy: limits.max_output_bytes: 9 is not in range"))}
	before := f.Snapshot()
	for _, o := range []string{out, "-"} {
		r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", o)
		report := r.stdout + r.stderr
		if r.code != 1 || !reflect.DeepEqual(f.Snapshot(), before) || len(sp.checks) != 0 {
			t.Fatalf("--out %s: exit %d or written\n%s", o, r.code, report)
		}
		if o == "-" && strings.Contains(r.stdout, "version:") {
			t.Fatalf("--out -: the refused policy was printed:\n%s", r.stdout)
		}
		for _, want := range []string{
			"FAIL answers write[0]: /etc/ssh is, or is inside, a protected path (the gate's built-in protected set, POLICY §3)",
			"FAIL answers commands[apt-upgradable]: /usr/bin/apt is not owned by root",
			"FAIL the operator preset's limits.max_output_bytes: 9 is not in range",
			"does not load, so nothing was written",
		} {
			if !strings.Contains(report, want) {
				t.Errorf("--out %s: lacks %q:\n%s", o, want, report)
			}
		}
	}
}

// TestRunRealGateLoader: shell-mcp-gate policy new's own Spec loads with
// the gate's loader before anything is written: a write root in the
// protected set, a forbidden read root, and a root over the policy
// directory are refused naming the rule, and nothing is written.
func TestRunRealGateLoader(t *testing.T) {
	check := func(string, io.Writer) int { return 0 }
	for _, c := range []struct{ answers, want string }{
		{strings.Replace(minimal, "read-only", "operator", 1) + "write: [/etc/ssh]\n", "answers write[0]: /etc/ssh is, or is inside, a protected path (the gate's built-in protected set, POLICY §3)"},
		{strings.Replace(minimal, "read-only", "operator", 1) + "write: [/etc/shell-mcp/extra]\n", "answers write[0]: /etc/shell-mcp/extra is, or is inside, a protected path"},
		{strings.Replace(minimal, "read-only", "operator", 1) + "write: [/var/lib/svc-shell]\n", "answers write[0]: /var/lib/svc-shell is, or is inside, a protected path"},
		{strings.Replace(minimal, "read-only", "operator", 1) + "write: [/etc]\n", "answers write[0]: /etc contains a protected path"},
		{strings.Replace(minimal, "/srv/app", "/proc/1", 1), "answers read[0]: /proc may not be a root or contain one"},
		{minimal + "commands:\n  - { id: shell, path: /bin/sh, tier: read, templates: [[\"-c\"]] }\n", "answers commands["},
	} {
		f := host(t)
		f.Put("/root/setup.yaml", c.answers, 0o600, 0, 0)
		before := f.Snapshot()
		var so, se bytes.Buffer
		o := &gen.Options{Answers: "/root/setup.yaml", Out: out}
		code := gen.Run(o, gen.GateSpec(f, "/usr/local/bin/shell-mcp-gate", check), f, &so, &se, &setupx.Auditor{Stderr: &se})
		if code != 1 || !strings.Contains(so.String(), c.want) || !reflect.DeepEqual(f.Snapshot(), before) {
			t.Errorf("%s: exit %d\n%s", c.answers, code, so.String())
		}
	}
	// And a policy the gate's loader accepts is written.
	f := host(t)
	f.Put("/root/setup.yaml", minimal, 0o600, 0, 0)
	var so, se bytes.Buffer
	o := &gen.Options{Answers: "/root/setup.yaml", Out: "/etc/shell-mcp/read-only.yaml"}
	if code := gen.Run(o, gen.GateSpec(f, "/usr/local/bin/shell-mcp-gate", check), f, &so, &se, &setupx.Auditor{Stderr: &se}); code != 0 || f.Files[o.Out] == nil {
		t.Fatalf("exit %d\n%s", code, so.String())
	}
}

// TestRunCheckPolicyFailRollsBack: a FAIL from check-policy after the
// write removes what the run created (handoff §3.4) and exits 1; a file
// that was already there and unchanged stays.
func TestRunCheckPolicyFailRollsBack(t *testing.T) {
	f, sp := host(t), &fakeSpec{checkCode: 1}
	before := f.Snapshot()
	r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out)
	if r.code != 1 || !reflect.DeepEqual(f.Snapshot(), before) {
		t.Fatalf("exit %d or not rolled back\n%s", r.code, r.stdout)
	}
	if !strings.Contains(r.stdout, "rolled back") || !strings.Contains(r.stderr, `"action":"rollback"`) || !strings.Contains(r.stderr, `"reason":"check_policy"`) {
		t.Fatalf("rollback not reported:\n%s\n%s", r.stdout, r.stderr)
	}
	noTemps(t, f)

	f.Dir(gen.Dir, 0o755, 0, 0)
	f.Put(out, string(rendered(t)), 0o644, 0, 0)
	before = f.Snapshot()
	if r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out); r.code != 1 || !reflect.DeepEqual(f.Snapshot(), before) {
		t.Fatalf("unchanged file: exit %d or changed\n%s", r.code, r.stdout)
	}
}

// TestRunWriteFailureLeavesNothing: a write that fails before or after its
// rename leaves no file, no directory the run created and no temp file.
func TestRunWriteFailureLeavesNothing(t *testing.T) {
	for name, fail := range map[string]func(*setuptest.Fake){
		"before the rename": func(f *setuptest.Fake) { f.FailWrite[out] = errors.New("disk full") },
		"read-back":         func(f *setuptest.Fake) { f.FailCommitted[out] = errors.New("read-back differs") },
	} {
		t.Run(name, func(t *testing.T) {
			f, sp := host(t), &fakeSpec{}
			fail(f)
			before := f.Snapshot()
			r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out)
			if r.code != 1 || !reflect.DeepEqual(f.Snapshot(), before) || len(sp.checks) != 0 {
				t.Fatalf("exit %d, left something or checked\n%s", r.code, r.stdout)
			}
			noTemps(t, f)
		})
	}
}

// TestRunRemovesLeftoverTemp: a temp file a killed run left for the
// target is removed, with a WARN, before the write.
func TestRunRemovesLeftoverTemp(t *testing.T) {
	f, sp := host(t), &fakeSpec{}
	f.Dir(gen.Dir, 0o755, 0, 0)
	left := gen.Dir + "/.operator.yaml.shell-mcp-abcdefghijkl"
	f.Put(left, "partial", 0o600, 0, 0)
	r := run(t, f, sp.spec(0o644), "--answers", "/root/setup.yaml", "--out", out)
	if r.code != 0 || f.Files[left] != nil || !strings.Contains(r.stdout, "WARN removed "+left) {
		t.Fatalf("exit %d\n%s", r.code, r.stdout)
	}
	noTemps(t, f)
}

// TestParseFlags: usage errors (exit 2 in the commands).
func TestParseFlags(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--out", out}, {"--answers", "a.yaml"}, {"--answers", "a.yaml", "--out", out, "extra"},
		{"--answers", "a.yaml", "--out", "-", "--dry-run"}, {"--answers", "a.yaml", "--out", out, "--force"},
	} {
		var ue *gen.UsageError
		if _, err := gen.ParseFlags(args, "/root"); !errors.As(err, &ue) {
			t.Errorf("%q: %v", args, err)
		}
	}
	o, err := gen.ParseFlags([]string{"--answers", "../x/setup.yaml", "--out", out, "--dry-run"}, "/root/sub")
	if err != nil || o.Answers != "/root/x/setup.yaml" || o.Out != out || !o.DryRun {
		t.Fatalf("%+v %v", o, err)
	}
}
