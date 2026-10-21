//go:build linux

package ops_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
)

// priv_exec_preview and priv_exec bound to it (handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-6: D6, P-2d, P-3, Q5, Q14), and the
// command killed when the gate's connection drops (must-fix (a)). Every
// path, name and command is an invented fixture.

type execPreview struct {
	CommandID      string   `json:"command_id"`
	Tier           string   `json:"tier"`
	Unit           string   `json:"unit"`
	Description    string   `json:"description"`
	RootEquivalent bool     `json:"root_equivalent"`
	Capabilities   []string `json:"capabilities"`
	Template       []string `json:"template"`
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// execCommands adds commands for every placeholder type, and commands that
// sleep ignoring SIGTERM in each unit (the policy then uses the broad
// unit).
func execCommands() opt {
	return func(f *fixture, s *string) {
		add := fmt.Sprintf(`  - id: probe-all
    path: %[1]s
    tier: read
    description: "every placeholder type"
    templates:
      - ["echo", "{regex:^[a-z]{1,8}$}", "{int:0-99}"]
      - ["echo", "{enum:alpha|beta}", "{path:read}"]
      - ["echo", "fixed", "{path:write}"]
  - id: probe-sleep
    path: %[1]s
    tier: read
    templates: [["ignore-term", "31s"]]
  - id: probe-op-sleep
    path: %[1]s
    tier: operator
    templates: [["ignore-term", "32s"]]
  - id: probe-broad-sleep
    path: %[1]s
    tier: read
    unit: broad
    templates: [["ignore-term", "34s"]]
  - id: probe-op
`, f.probe)
		if !strings.Contains(*s, "  - id: probe-op\n") {
			f.t.Fatal("fixture policy lacks probe-op")
		}
		*s = strings.Replace(*s, "  - id: probe-op\n", add, 1)
	}
}

// as makes the fixture's next instances the given unit's.
func (f *fixture) as(unit string) {
	f.unit, f.opts.Unit = unit, unit
	f.status = statusFor("0", "1", "000000000000000f")
	if unit == "broad" {
		f.status = statusFor("0", "1", broadCapBnd)
	}
}

func (f *fixture) execPreview(args m) execPreview {
	f.t.Helper()
	var p execPreview
	f.ok("priv_exec_preview", args, &p)
	if !hex64.MatchString(p.PreviewSHA256) {
		f.t.Fatalf("preview hash %q", p.PreviewSHA256)
	}
	return p
}

func realPath(t testing.TB, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func absent(t testing.TB, p string) {
	t.Helper()
	if _, err := os.Lstat(p); err == nil {
		t.Fatalf("%s exists: something ran", p)
	}
}

// TestPrivExecPreview: the preview resolves a command as priv_exec would
// and runs nothing; it reports the command's unit, also for a broad
// command, from the core instance.
func TestPrivExecPreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t, execCommands())
	out := filepath.Join(f.write, "preview-out")
	p := f.execPreview(m{"command_id": "probe-echo", "args": []string{"write", out, "x"}, "cwd": f.read})
	if p.CommandID != "probe-echo" || p.Tier != "read" || p.Unit != "core" || p.RootEquivalent || p.Capabilities == nil || len(p.Capabilities) != 0 ||
		!slices.Equal(p.Template, []string{"write", "{path:write}", "{regex:^[a-z]+$}"}) ||
		!slices.Equal(p.Argv, []string{f.probe, "write", realPath(t, f.write) + "/preview-out", "x"}) ||
		p.Cwd != realPath(t, f.read) || p.PolicySHA256 != f.opts.ExpectedSHA256 {
		t.Fatalf("preview %+v", p)
	}
	absent(t, out)
	q := f.execPreview(m{"command_id": "probe-all", "args": []string{"echo", "alpha", filepath.Join(f.read, "hello.txt")}})
	if q.Description != "every placeholder type" || q.Cwd != "/" || !slices.Equal(q.Template, []string{"echo", "{enum:alpha|beta}", "{path:read}"}) {
		t.Fatalf("preview %+v", q)
	}
	// The same request hashes the same; any other argument differently.
	if again := f.execPreview(m{"command_id": "probe-all", "args": []string{"echo", "alpha", filepath.Join(f.read, "hello.txt")}}); again.PreviewSHA256 != q.PreviewSHA256 {
		t.Fatal("the same request hashed differently")
	}
	if other := f.execPreview(m{"command_id": "probe-all", "args": []string{"echo", "beta", filepath.Join(f.read, "hello.txt")}}); other.PreviewSHA256 == q.PreviewSHA256 {
		t.Fatal("another argument hashed the same")
	}
	// The audit line has the command id and the argument count, never the
	// arguments.
	if l := f.lastAudit(); !strings.Contains(l, `"op":"priv_exec_preview"`) || !strings.Contains(l, `"arg_count":3`) || strings.Contains(l, "beta") {
		t.Fatalf("audit %q", l)
	}
	// A broad command is previewed by the core instance, which names its unit.
	if b := f.execPreview(m{"command_id": "probe-broad-sleep", "args": []string{"ignore-term", "34s"}}); b.Unit != "broad" {
		t.Fatalf("broad command previewed as %+v", b)
	}

	// Refused as priv_exec would refuse it.
	f.fail("priv_exec_preview", m{"command_id": "no-such-command", "args": []string{}}, "policy_denied")
	f.fail("priv_exec_preview", m{"command_id": "probe-all", "args": []string{"echo", "UPPER", "1"}}, "template_mismatch")
	f.fail("priv_exec_preview", m{"command_id": "probe-all", "args": []string{"echo", "fixed", "/etc/passwd"}}, "path_denied")
	f.fail("priv_exec_preview", m{"command_id": "probe-echo", "args": []string{"echo", "x"}, "cwd": "/etc"}, "path_denied")
	f.fail("priv_exec_preview", m{"command_id": "probe-echo", "args": []string{"echo", "x"}, "unit": "core"}, "bad_request")
	f.fail("priv_exec_preview", m{"command_id": "probe-echo", "args": []string{"echo", "x"}, "expected_preview_sha256": q.PreviewSHA256}, "bad_request")
	if r := f.serveAt("read", "priv_exec_preview", m{"command_id": "probe-op", "args": []string{"echo", "operator"}}); r.Error == nil || r.Error.Code != "tier_denied" {
		t.Fatalf("an operator command previewed at ceiling read: %+v", r.Error)
	}
	// Only the core instance previews.
	f.as("broad")
	f.fail("priv_exec_preview", m{"command_id": "probe-broad-sleep", "args": []string{"ignore-term", "34s"}}, "helper_wrong_unit")
}

// TestPrivExecBindsPreview (Q14): an operator or destructive command runs
// only with the hash of its preview; a read command runs without one, and
// with one only while it matches.
func TestPrivExecBindsPreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	out := filepath.Join(f.write, "op-out")
	args := m{"command_id": "probe-op", "args": []string{"write", out}}
	f.fail("priv_exec", args, "bad_request")
	absent(t, out)
	p := f.execPreview(args)
	if p.Tier != "operator" || p.Unit != "core" {
		t.Fatalf("preview %+v", p)
	}
	for _, bad := range []string{"", "zz", strings.ToUpper(p.PreviewSHA256)} {
		f.fail("priv_exec", m{"command_id": "probe-op", "args": []string{"write", out}, "expected_preview_sha256": bad}, "bad_request")
	}
	f.fail("priv_exec", m{"command_id": "probe-op", "args": []string{"write", out}, "expected_preview_sha256": strings.Repeat("0", 64)}, "exists")
	absent(t, out)
	var d execData
	f.ok("priv_exec", m{"command_id": "probe-op", "args": []string{"write", out}, "expected_preview_sha256": p.PreviewSHA256}, &d)
	if !slices.Equal(d.Argv, p.Argv) || readFile(t, out) != "probe" {
		t.Fatalf("ran %v, previewed %v", d.Argv, p.Argv)
	}
	// The audit line never carries the hash.
	if l := f.lastAudit(); strings.Contains(l, p.PreviewSHA256) || strings.Contains(l, "expected_preview_sha256") {
		t.Fatalf("audit %q", l)
	}
	// A read command needs none, and a wrong one is still refused.
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}}, &d)
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}, "expected_preview_sha256": p.PreviewSHA256}, "exists")
	rp := f.execPreview(m{"command_id": "probe-echo", "args": []string{"echo", "x"}})
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}, "expected_preview_sha256": rp.PreviewSHA256}, &d)
	if d.Stdout != "x\n" {
		t.Fatalf("stdout %q", d.Stdout)
	}
}

// TestPrivExecPolicyEditAfterPreview: an edit of the command between its
// preview and priv_exec (binary, template, tier, unit, description) is
// refused, and nothing runs.
func TestPrivExecPolicyEditAfterPreview(t *testing.T) {
	t.Parallel()
	const opEntry = "  - id: probe-op\n    path: %s\n    tier: operator\n    templates: [[\"echo\", \"operator\"], [\"write\", \"{path:write}\"]]\n"
	for name, c := range map[string]struct {
		edit func(f *fixture) string
		code string
	}{
		"binary": {func(f *fixture) string {
			other := filepath.Join(filepath.Dir(f.probe), "example-probe-2")
			b, err := os.ReadFile(f.probe)
			if err != nil {
				t.Fatal(err)
			}
			gatetest.WriteFile(t, other, string(b), 0o755)
			return fmt.Sprintf("  - id: probe-op\n    path: %s\n    tier: operator\n    templates: [[\"echo\", \"operator\"], [\"write\", \"{path:write}\"]]\n", other)
		}, "exists"},
		"template": {func(f *fixture) string {
			return fmt.Sprintf("  - id: probe-op\n    path: %s\n    tier: operator\n    templates: [[\"echo\", \"operator\"]]\n", f.probe)
		}, "template_mismatch"},
		"tier": {func(f *fixture) string {
			return fmt.Sprintf("  - id: probe-op\n    path: %s\n    tier: destructive\n    templates: [[\"echo\", \"operator\"], [\"write\", \"{path:write}\"]]\n", f.probe)
		}, "tier_denied"},
		"unit": {func(f *fixture) string {
			return fmt.Sprintf("  - id: probe-op\n    path: %s\n    tier: operator\n    unit: broad\n    templates: [[\"echo\", \"operator\"], [\"write\", \"{path:write}\"]]\n", f.probe)
		}, "helper_wrong_unit"},
		"description": {func(f *fixture) string {
			return fmt.Sprintf("  - id: probe-op\n    path: %s\n    tier: operator\n    description: \"changed\"\n    templates: [[\"echo\", \"operator\"], [\"write\", \"{path:write}\"]]\n", f.probe)
		}, "exists"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			out := filepath.Join(f.write, "edit-out")
			args := m{"command_id": "probe-op", "args": []string{"write", out}}
			p := f.execPreview(args)
			y := readFile(t, f.policyPath)
			old := fmt.Sprintf(opEntry, f.probe)
			if !strings.Contains(y, old) {
				t.Fatalf("policy lacks %q", old)
			}
			gatetest.WriteFile(t, f.policyPath, strings.Replace(y, old, c.edit(f), 1), 0o600)
			f.rehash()
			r := f.serveAt("operator", "priv_exec", m{"command_id": "probe-op", "args": []string{"write", out}, "expected_preview_sha256": p.PreviewSHA256})
			if r.OK || r.Error == nil || r.Error.Code != c.code {
				t.Fatalf("got ok=%v %+v, want %s", r.OK, r.Error, c.code)
			}
			absent(t, out)
		})
	}
}

// TestPrivExecPathRetargeted: a path placeholder or the cwd that resolves
// elsewhere after the preview (a directory link retargeted) is refused,
// and nothing runs.
func TestPrivExecPathRetargeted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, d := range []string{"a", "b"} {
		gatetest.Mkdir(t, filepath.Join(f.write, d), 0o755)
	}
	link := filepath.Join(f.write, "link")
	if err := os.Symlink("a", link); err != nil {
		t.Fatal(err)
	}
	args := m{"command_id": "probe-op", "args": []string{"write", filepath.Join(link, "x")}}
	p := f.execPreview(args)
	if p.Argv[2] != realPath(t, f.write)+"/a/x" {
		t.Fatalf("resolved %v", p.Argv)
	}
	retarget := func(to string) {
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
	}
	retarget("b")
	f.fail("priv_exec", m{"command_id": "probe-op", "args": []string{"write", filepath.Join(link, "x")}, "expected_preview_sha256": p.PreviewSHA256}, "exists")
	absent(t, filepath.Join(f.write, "a", "x"))
	absent(t, filepath.Join(f.write, "b", "x"))
	// The cwd (a final symlink is refused, so through a link above it).
	gatetest.Mkdir(t, filepath.Join(f.write, "a", "sub"), 0o755)
	gatetest.Mkdir(t, filepath.Join(f.write, "b", "sub"), 0o755)
	retarget("a")
	cwd := filepath.Join(link, "sub")
	cp := f.execPreview(m{"command_id": "probe-op", "args": []string{"echo", "operator"}, "cwd": cwd})
	if cp.Cwd != realPath(t, f.write)+"/a/sub" {
		t.Fatalf("cwd %q", cp.Cwd)
	}
	retarget("b")
	f.fail("priv_exec", m{"command_id": "probe-op", "args": []string{"echo", "operator"}, "cwd": cwd, "expected_preview_sha256": cp.PreviewSHA256}, "exists")
}

// TestPrivExecBroadRecomputes (D6): a broad command previewed by the core
// instance runs in the broad instance with that preview's hash, which the
// broad instance recomputes; a resolution that differs there is refused,
// and nothing runs. Each instance runs only its own unit's commands.
func TestPrivExecBroadRecomputes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, broadUsers())
	out := filepath.Join(f.write, "broad-out")
	args := m{"command_id": "probe-broad", "args": []string{"write", out, "x"}}
	p := f.execPreview(args)
	if p.Unit != "broad" {
		t.Fatalf("preview %+v", p)
	}
	f.fail("priv_exec", m{"command_id": "probe-broad", "args": []string{"write", out, "x"}, "unit": "broad", "expected_preview_sha256": p.PreviewSHA256}, "helper_wrong_unit")
	absent(t, out)

	gatetest.Mkdir(t, filepath.Join(f.write, "a"), 0o755)
	gatetest.Mkdir(t, filepath.Join(f.write, "b"), 0o755)
	link := filepath.Join(f.write, "link")
	if err := os.Symlink("a", link); err != nil {
		t.Fatal(err)
	}
	moved := f.execPreview(m{"command_id": "probe-broad", "args": []string{"write", filepath.Join(link, "y"), "x"}})

	f.as("broad")
	var d execData
	f.ok("priv_exec", m{"command_id": "probe-broad", "args": []string{"write", out, "x"}, "unit": "broad", "expected_preview_sha256": p.PreviewSHA256}, &d)
	if !slices.Equal(d.Argv, p.Argv) || readFile(t, out) != "probe" {
		t.Fatalf("ran %v, previewed %v", d.Argv, p.Argv)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", link); err != nil {
		t.Fatal(err)
	}
	f.fail("priv_exec", m{"command_id": "probe-broad", "args": []string{"write", filepath.Join(link, "y"), "x"}, "unit": "broad", "expected_preview_sha256": moved.PreviewSHA256}, "exists")
	absent(t, filepath.Join(f.write, "a", "y"))
	absent(t, filepath.Join(f.write, "b", "y"))
	// A core command never runs in the broad instance, and a broad one is
	// never previewed there.
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}}, "helper_wrong_unit")
	f.fail("priv_exec_preview", m{"command_id": "probe-broad", "args": []string{"echo", "x"}}, "helper_wrong_unit")
}

// serveHangup runs Serve on one end of a socket pair after writing in to
// the other end, waits until the command started with args ignores
// SIGTERM, and then hangs up as the gate would: "close" closes the gate's
// end (the gate exited or was killed), "half" shuts down its sending side
// (the gate stopped waiting and still reads). It returns what the helper
// wrote, how long Serve took after the hang-up, and whether the command
// was still running when Serve returned.
func (f *fixture) serveHangup(in, mode string, args ...string) (out string, took time.Duration, aliveAtReturn bool) {
	f.t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.helperFD = fds[0]
	if _, err := unix.Write(fds[1], []byte(in)); err != nil {
		f.t.Fatal(err)
	}
	conn := os.NewFile(uintptr(fds[0]), "conn")
	o := f.opts
	o.Conn = conn
	type result struct {
		alive bool
		at    time.Time
	}
	done := make(chan result, 1)
	var p gatetest.Proc
	found := make(chan struct{})
	go func() {
		ops.Serve(&o)
		<-found
		done <- result{alive: p.Alive(), at: time.Now()}
	}()
	p = gatetest.FindChild(f.t, os.Getpid(), args...)
	f.t.Cleanup(p.Kill)
	p.WaitIgnoring(f.t, unix.SIGTERM)
	close(found)
	start := time.Now()
	switch mode {
	case "close":
		_ = unix.Close(fds[1])
	case "half":
		_ = unix.Shutdown(fds[1], unix.SHUT_WR)
	}
	var r result
	select {
	case r = <-done:
	case <-time.After(25 * time.Second):
		f.t.Fatalf("Serve did not return 25 s after the hang-up (%s)", mode)
	}
	_ = conn.Close()
	if mode == "half" {
		var b []byte
		buf := make([]byte, 64<<10)
		for {
			n, err := unix.Read(fds[1], buf)
			if n <= 0 || err != nil {
				break
			}
			b = append(b, buf[:n]...)
		}
		_ = unix.Close(fds[1])
		out = string(b)
	}
	return out, r.at.Sub(start), r.alive
}

// TestExecKilledOnHangup (must-fix (a)): when the gate's connection drops
// or the gate stops waiting while a command runs, the helper kills the
// command (SIGTERM, then SIGKILL after the grace, on its process group)
// before it returns, in both units, also a command that ignores SIGTERM;
// to a gate that still reads it answers outcome_unknown for a command that
// can change the host and timeout for a read command. Its audit line
// records the hang-up and that code. Not parallel: it finds its command by
// its arguments among every child of this test process, and it bounds how
// long the kill takes.
func TestExecKilledOnHangup(t *testing.T) {
	for _, c := range []struct {
		unit, command, ceiling, sleep string
	}{
		{"core", "probe-sleep", "read", "31s"},
		{"core", "probe-op-sleep", "operator", "32s"},
		{"broad", "probe-broad-sleep", "read", "34s"},
	} {
		for _, mode := range []string{"close", "half"} {
			t.Run(c.unit+"/"+c.command+"/"+mode, func(t *testing.T) {
				f := newFixture(t, execCommands())
				args := m{"command_id": c.command, "args": []string{"ignore-term", c.sleep}}
				if c.ceiling != "read" {
					args["expected_preview_sha256"] = f.execPreview(args).PreviewSHA256
				}
				if c.unit == "broad" {
					f.as("broad")
					args["unit"] = "broad"
				}
				out, took, alive := f.serveHangup(requestAt(c.ceiling, "priv_exec", args), mode, "ignore-term", c.sleep)
				if alive {
					t.Fatal("the helper returned while the command was still running")
				}
				if took > 4*time.Second {
					t.Fatalf("the helper took %v after the hang-up", took)
				}
				want := "timeout"
				if c.ceiling != "read" {
					want = "outcome_unknown"
				}
				if mode == "half" {
					var r response
					if err := json.Unmarshal([]byte(out), &r); err != nil || r.OK || r.Error == nil || r.Error.Code != want {
						t.Fatalf("answer %q, want %s", out, want)
					}
				}
				if l := f.lastAudit(); !strings.Contains(l, `"outcome":"`+want+`"`) || !strings.Contains(l, `"hung_up":true`) {
					t.Fatalf("audit %q", l)
				}
			})
		}
	}
}

// TestExecNotStartedAfterHangup: a request whose gate hung up before the
// command started runs nothing.
func TestExecNotStartedAfterHangup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	out := filepath.Join(f.write, "late-out")
	args := m{"command_id": "probe-op", "args": []string{"write", out}}
	args["expected_preview_sha256"] = f.execPreview(args).PreviewSHA256
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.helperFD = fds[0]
	if _, err := unix.Write(fds[1], []byte(requestAt("operator", "priv_exec", args))); err != nil {
		t.Fatal(err)
	}
	_ = unix.Shutdown(fds[1], unix.SHUT_WR)
	conn := os.NewFile(uintptr(fds[0]), "conn")
	o := f.opts
	o.Conn = conn
	ops.Serve(&o)
	_ = conn.Close()
	b := make([]byte, 64<<10)
	n, _ := unix.Read(fds[1], b)
	_ = unix.Close(fds[1])
	var r response
	if n <= 0 || json.Unmarshal(b[:n], &r) != nil || r.Error == nil || r.Error.Code != "timeout" {
		t.Fatalf("answer %q", b[:max(n, 0)])
	}
	absent(t, out)
	if l := f.lastAudit(); !strings.Contains(l, `"hung_up":true`) {
		t.Fatalf("audit %q", l)
	}
}

// TestExecReapFailureIsOutcomeUnknown (must-fix (a), fail closed): when the
// helper cannot list the children a command left, it cannot confirm that
// none is still running, so the answer is outcome_unknown, never the
// command's success, and the journal line says why.
func TestExecReapFailureIsOutcomeUnknown(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.opts.ReapOrphans = true
	f.opts.ReapHooks = &ops.ReapHooks{
		Children: func() ([]int, error) { return nil, errors.New("injected: children unreadable") },
		Wait:     func() (int, error) { return 0, unix.ECHILD },
	}
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}}, "outcome_unknown")
	if l := f.lastAudit(); !strings.Contains(l, `"outcome":"outcome_unknown"`) || !strings.Contains(l, "injected: children unreadable") {
		t.Fatalf("audit %q", l)
	}
	// Control: the same command with the children readable and none left.
	f.opts.ReapHooks.Children = func() ([]int, error) { return []int{}, nil }
	var d execData
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}}, &d)
	if d.Stdout != "x\n" || strings.Contains(f.lastAudit(), "reap_error") {
		t.Fatalf("control %+v audit %q", d, f.lastAudit())
	}
}
