//go:build linux

package ops_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The gate's own versions of gaps closed on the privileged side (handoff
// docs/handoff/S4C-PRIVILEGED.md N-11, N-18, N-4), through the gate's
// configuration: commands' path placeholders and cwd under the chain rule
// (trusting root and the service account, the test's own uid here),
// moves staged in the destination's directory, and chmod's read-back.
// Every layout and name is invented. An unprivileged test cannot give a
// directory to another account, so another account's write access is a
// group- or world-writable (or sticky) directory; e2e-host runs the real
// case with another account.

// chainCommands are this file's commands, appended to the base policy.
const chainCommands = `  - id: probe-cat
    path: {BIN}/probe
    tier: read
    templates: [["cat", "{path:read}"], ["cat", "t"], ["echo", "{path:read}"]]
  - id: probe-put
    path: {BIN}/probe
    tier: operator
    templates: [["write", "{path:write}"], ["echo", "{path:write}"]]
`

func chainFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, "destructive")
	f.rawPolicy(strings.NewReplacer("{TIER}", "destructive", "{PRIV}", "").Replace(basePolicy + chainCommands))
	return f
}

// chainRun previews a command, then runs it twice, with an invalid
// expected_preview_sha256 and without one; it returns the three answers.
func (f *fixture) chainRun(command string, args []string, cwd string) [3]response {
	f.t.Helper()
	req := m{"command_id": command, "args": args}
	if cwd != "" {
		req["cwd"] = cwd
	}
	var out [3]response
	out[0] = f.call("exec_preview", req)
	req["expected_preview_sha256"] = strings.Repeat("0", 64)
	out[1] = f.call("exec", req)
	delete(req, "expected_preview_sha256")
	out[2] = f.call("exec", req)
	return out
}

type chainReq struct {
	command string
	args    []string
	cwd     string
}

// TestExecPathChain: with every directory from / to the parent closed (the
// service account's or root's, neither group- nor world-writable, not
// sticky), {path:read}, {path:write} and the cwd resolve and run; with one
// of them open (above the roots, the read root, the write root, an
// intermediate directory, the parent), exec_preview and exec refuse with
// path_denied naming it, the same message each time, and nothing runs.
func TestExecPathChain(t *testing.T) {
	t.Parallel()
	f := chainFixture(t)
	a := filepath.Join(f.write, "a")
	b := filepath.Join(a, "b")
	sub := filepath.Join(b, "c")
	file := filepath.Join(b, "t")
	gatetest.Mkdir(t, a, 0o755)
	gatetest.Mkdir(t, b, 0o755)
	gatetest.Mkdir(t, sub, 0o755)
	gatetest.WriteFile(t, file, "original\n", 0o644)

	var d execData
	f.ok("exec", m{"command_id": "probe-cat", "args": []string{"cat", file}}, &d)
	if d.Stdout != "READ:original\n\n" {
		t.Fatalf("closed chain: cat %q", d.Stdout)
	}
	f.ok("exec", m{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": sub}, &d)
	if d.Stdout != sub+"\n" {
		t.Fatalf("closed chain: pwd %q", d.Stdout)
	}
	newFile := filepath.Join(b, "new")
	f.ok("exec", m{"command_id": "probe-put", "args": []string{"write", newFile}}, &d)
	if got, _ := os.ReadFile(newFile); string(got) != "probe" { //nolint:gosec // G304: the test's own fixture
		t.Fatalf("closed chain: wrote %q", got)
	}
	must(t, os.Remove(newFile))

	levels := []struct{ name, dir string }{
		{"above the roots", filepath.Dir(f.read)}, {"read root", f.read}, {"write root", f.write}, {"intermediate", a}, {"parent", b},
	}
	for _, lvl := range levels {
		for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o777, os.ModeSticky | 0o755} {
			t.Run(fmt.Sprintf("%s %v", lvl.name, mode), func(t *testing.T) {
				openDir(t, lvl.dir, mode)
				for _, c := range []chainReq{
					{"probe-cat", []string{"cat", file}, ""},
					{"probe-io", []string{"pwd"}, sub},
					{"probe-put", []string{"write", newFile}, ""},
					{"probe-put", []string{"write", file}, ""},
				} {
					wantChainRefused(t, ptr(f.chainRun(c.command, c.args, c.cwd)), lvl.dir, c)
				}
				if _, err := os.Lstat(newFile); err == nil {
					t.Fatal("a refused command wrote its file")
				}
				if got, _ := os.ReadFile(file); string(got) != "original\n" { //nolint:gosec // G304: the test's own fixture
					t.Fatalf("a refused command wrote %q", got)
				}
			})
		}
	}
}

// TestExecDirTarget: a directory given to a command (the cwd, a
// {path:read} or {path:write} that is one) must be closed itself; a file's
// own mode does not matter.
func TestExecDirTarget(t *testing.T) {
	t.Parallel()
	f := chainFixture(t)
	dir := filepath.Join(f.write, "d")
	gatetest.Mkdir(t, dir, 0o755)
	file := filepath.Join(f.write, "f")
	gatetest.WriteFile(t, file, "f\n", 0o666)
	reqs := []chainReq{
		{"probe-io", []string{"pwd"}, dir},
		{"probe-cat", []string{"echo", dir}, ""},
		{"probe-put", []string{"echo", dir}, ""},
	}
	for _, c := range reqs {
		r := f.chainRun(c.command, c.args, c.cwd)
		if !r[0].OK || !r[2].OK {
			t.Fatalf("a closed directory %v: %+v %+v", c, r[0].Error, r[2].Error)
		}
	}
	f.ok("exec", m{"command_id": "probe-cat", "args": []string{"cat", file}}, nil)
	for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o777, os.ModeSticky | 0o755} {
		t.Run(mode.String(), func(t *testing.T) {
			openDir(t, dir, mode)
			for _, c := range reqs {
				wantChainRefused(t, ptr(f.chainRun(c.command, c.args, c.cwd)), dir, c)
			}
		})
	}
}

// openDir gives dir mode until the test ends, then closes it again (0755).
func openDir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	must(t, os.Chmod(dir, mode))
	gatetest.ExactMode(t, dir, mode)
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) //nolint:gosec // G302: a directory, closed again
}

// wantChainRefused: the preview and both execs refused with path_denied
// naming dir, all with the preview's message, which does not say "as root".
func wantChainRefused(t *testing.T, r *[3]response, dir string, c chainReq) {
	t.Helper()
	p := r[0]
	if p.OK || p.Error.Code != "path_denied" || !strings.Contains(p.Error.Message, dir) || !strings.Contains(p.Error.Message, "is not given to a command:") ||
		strings.Contains(p.Error.Message, "as root") {
		t.Fatalf("%v cwd %q: preview %+v %s, want path_denied naming %s", c.args, c.cwd, p.Error, p.Data, dir)
	}
	for _, e := range r[1:] {
		if e.OK || e.Error.Code != "path_denied" || e.Error.Message != p.Error.Message {
			t.Fatalf("%v cwd %q: exec %+v %s, want the preview's refusal", c.args, c.cwd, e.Error, e.Data)
		}
	}
}

// TestExecPathChainRace: a directory another account can write (here
// world-writable) holds a command's target, or a directory above it, or is
// its cwd, and a racer exchanges that name with a symlink to a file the
// policy denies, again and again, while the command is previewed and run
// with the fresh preview's hash. Every request is refused at the
// resolution, and the denied file is never read or written.
func TestExecPathChainRace(t *testing.T) {
	t.Parallel()
	f := chainFixture(t)
	secret := filepath.Join(f.secrets, "token")
	race := filepath.Join(f.write, "race")
	for _, c := range []struct{ name, target, swap, to, cwd string }{
		{"the target in its parent", "t", "t", secret, ""},
		{"a directory above the target", "sub/t", "sub", f.secrets, ""},
		{"a symlink planted in the cwd", "t", "t", secret, race},
	} {
		t.Run(c.name, func(t *testing.T) {
			must(t, os.RemoveAll(race))
			gatetest.Mkdir(t, race, 0o777)
			gatetest.Mkdir(t, filepath.Join(race, "sub"), 0o755)
			gatetest.WriteFile(t, filepath.Join(race, "t"), "decoy\n", 0o644)
			gatetest.WriteFile(t, filepath.Join(race, "sub", "t"), "decoy\n", 0o644)
			// What sub/t names through the symlink to the denied directory.
			gatetest.WriteFile(t, filepath.Join(f.secrets, "t"), "TOPSECRET\n", 0o644)
			name, alt := filepath.Join(race, c.swap), filepath.Join(race, c.swap+".alt")
			must(t, os.Symlink(c.to, alt))
			var stopped atomic.Bool
			var swaps atomic.Int64
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stopped.Load() {
					if unix.Renameat2(unix.AT_FDCWD, alt, unix.AT_FDCWD, name, unix.RENAME_EXCHANGE) == nil {
						swaps.Add(1)
					}
				}
			}()
			target := filepath.Join(race, c.target)
			reqs := []chainReq{{"probe-cat", []string{"cat", target}, ""}, {"probe-put", []string{"write", target}, ""}}
			if c.cwd != "" {
				reqs = []chainReq{{"probe-cat", []string{"cat", c.target}, c.cwd}}
			}
			for i := range 30 {
				for _, rc := range reqs {
					req := m{"command_id": rc.command, "args": rc.args}
					if rc.cwd != "" {
						req["cwd"] = rc.cwd
					}
					pr := f.call("exec_preview", req)
					hash := strings.Repeat("0", 64)
					if pr.OK {
						var pv struct {
							PreviewSHA256 string `json:"preview_sha256"`
						}
						_ = json.Unmarshal(pr.Data, &pv)
						hash = pv.PreviewSHA256
					}
					req["expected_preview_sha256"] = hash
					er := f.call("exec", req)
					for _, r := range []response{pr, er} {
						if strings.Contains(string(r.Data), "TOPSECRET") {
							stopped.Store(true)
							wg.Wait()
							t.Fatalf("run %d: %v read the denied file: %s", i, rc.args, r.Data)
						}
						if r.OK || r.Error.Code != "path_denied" {
							stopped.Store(true)
							wg.Wait()
							t.Fatalf("run %d: %v cwd %q: %+v %s, want path_denied", i, rc.args, rc.cwd, r.Error, r.Data)
						}
					}
				}
			}
			stopped.Store(true)
			wg.Wait()
			if swaps.Load() == 0 {
				t.Fatal("the racer did not swap")
			}
			for p, want := range map[string]string{secret: "TOPSECRET", filepath.Join(f.secrets, "t"): "TOPSECRET\n"} {
				if got, _ := os.ReadFile(p); string(got) != want { //nolint:gosec // G304: the test's own fixture
					t.Fatalf("the denied file %s was written: %q", p, got)
				}
			}
			t.Logf("every request refused; the racer made %d exchanges", swaps.Load())
		})
	}
}

// TestChmodReadsBack (handoff N-4): the gate's chmod re-reads the mode,
// owner and group through the descriptor it changed; a mismatch is
// verify_failed, never a success.
func TestChmodReadsBack(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "operator")
	p := filepath.Join(f.write, "x.conf")
	gatetest.WriteFile(t, p, "x\n", 0o600)
	f.opts.InjectMetadataReadBackFault = func(m fsx.Meta) fsx.Meta { m.Mode ^= 0o004; return m }
	r := f.call("chmod", m{"path": p, "mode": "0640"})
	if r.OK || r.Error.Code != "verify_failed" || !strings.Contains(r.Error.Message, "read back") {
		t.Fatalf("chmod with a read-back fault: %+v %s, want verify_failed", r.Error, r.Data)
	}
	f.opts.InjectMetadataReadBackFault = nil
	f.ok("chmod", m{"path": p, "mode": "0600"}, nil)
	gatetest.ExactMode(t, p, 0o600)
}

// TestMoveStagingNameRefused (handoff N-18): a name a stopped gate move
// left (.shell-mcp-move-<32 hex>) is never read, changed, moved or deleted
// through any operation, a command is never given it, and nothing moves
// into or out of the directory that holds it; the refusals name it.
func TestMoveStagingNameRefused(t *testing.T) {
	t.Parallel()
	f := chainFixture(t)
	dir := filepath.Join(f.write, "s")
	gatetest.Mkdir(t, dir, 0o755)
	staged := filepath.Join(dir, ".shell-mcp-move-"+strings.Repeat("ab", 16))
	gatetest.WriteFile(t, staged, "left by a stopped move\n", 0o640)
	x := filepath.Join(dir, "x.conf")
	gatetest.WriteFile(t, x, "x\n", 0o640)
	out := filepath.Join(f.write, "out.conf")
	gatetest.WriteFile(t, out, "out\n", 0o640)
	content := base64.StdEncoding.EncodeToString([]byte("y\n"))
	for _, c := range []struct {
		op   string
		args m
	}{
		{"read_file", m{"path": staged}},
		{"stat", m{"path": staged}},
		{"write_file", m{"path": staged, "content_b64": content}},
		{"chmod", m{"path": staged, "mode": "0600"}},
		{"copy", m{"source": staged, "destination": filepath.Join(f.write, "c.conf")}},
		{"move", m{"source": staged, "destination": filepath.Join(f.write, "m.conf")}},
		{"delete_preview", m{"path": staged}},
		{"delete_preview", m{"path": dir, "recursive": true}},
		{"move", m{"source": x, "destination": filepath.Join(dir, "y.conf")}},
		{"move", m{"source": x, "destination": filepath.Join(f.write, "x.conf")}},
		{"move", m{"source": out, "destination": filepath.Join(dir, "out.conf")}},
		{"exec_preview", m{"command_id": "probe-cat", "args": []string{"cat", staged}}},
	} {
		r := f.call(c.op, c.args)
		if r.OK || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, ".shell-mcp-move-") {
			t.Fatalf("%s %v: %+v %s, want path_denied naming the staging entry", c.op, c.args, r.Error, r.Data)
		}
	}
	if got, _ := os.ReadFile(staged); string(got) != "left by a stopped move\n" { //nolint:gosec // G304: the test's own fixture
		t.Fatalf("the staging entry changed: %q", got)
	}
	for _, p := range []string{x, out} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s was moved: %v", p, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
