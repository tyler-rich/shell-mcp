//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// Root commands' path placeholders and cwd under the chain rule (handoff
// docs/handoff/S4C-PRIVILEGED.md N-10; PRIVILEGED §6, "Commands"): the
// command looks the resolved path up again itself, as root, so every
// directory from / to its parent must be one only root can change, or the
// request is refused (path_denied) by priv_exec_preview and priv_exec alike,
// in both units, and nothing runs. Every path, name and command is an
// invented fixture. An unprivileged test cannot give a directory to another
// account, so "another account can write it" is a group- or world-writable
// directory here (the owner case is fsx's TestResolveExecChainOwner and
// e2e-host's TestPrivExecPathChain).

// chainRoot is the extra write root chainCommands adds, under its own
// ancestor, so that every level of its chain can be opened by a test.
func chainRoot(f *fixture) (anc, root string) {
	return filepath.Join(f.d, "x"), filepath.Join(f.d, "x", "w")
}

// chainCommands adds the write root <d>/x/w (under <d>/x, both 0755) and
// root commands that read and write through path placeholders and print
// their cwd, in each unit.
func chainCommands() opt {
	return func(f *fixture, s *string) {
		anc, root := chainRoot(f)
		gatetest.Mkdir(f.t, root, 0o755)
		if err := os.Chmod(anc, 0o755); err != nil {
			f.t.Fatal(err)
		}
		from := "  write: [" + f.write + "]\n"
		if !strings.Contains(*s, from) {
			f.t.Fatalf("fixture policy lacks %q", from)
		}
		*s = strings.Replace(*s, from, "  write: ["+f.write+", "+root+"]\n", 1)
		*s = strings.Replace(*s, "commands:\n", fmt.Sprintf(`commands:
  - id: chain-read
    path: %[1]s
    tier: read
    templates: [["cat", "{path:read}"], ["pwd"]]
  - id: chain-write
    path: %[1]s
    tier: operator
    templates: [["write", "{path:write}"]]
  - id: chain-broad-read
    path: %[1]s
    tier: read
    unit: broad
    templates: [["cat", "{path:read}"], ["pwd"]]
  - id: chain-broad-write
    path: %[1]s
    tier: operator
    unit: broad
    templates: [["write", "{path:write}"]]
`, f.probe), 1)
	}
}

// chainCase is one request: a command, its arguments and cwd, and the
// file it would write (empty for a read).
type chainCase struct {
	name, core, broad string
	args              []string
	cwd               string
	writes            string
}

func chainCases(file, newFile, sub string) []chainCase {
	return []chainCase{
		{"read", "chain-read", "chain-broad-read", []string{"cat", file}, "", ""},
		{"write new", "chain-write", "chain-broad-write", []string{"write", newFile}, "", newFile},
		{"write existing", "chain-write", "chain-broad-write", []string{"write", file}, "", file},
		{"cwd", "chain-read", "chain-broad-read", []string{"pwd"}, sub, ""},
	}
}

func (c *chainCase) req(command string, hash string) m {
	r := m{"command_id": command, "args": c.args}
	if c.cwd != "" {
		r["cwd"] = c.cwd
	}
	if hash != "" {
		r["expected_preview_sha256"] = hash
	}
	return r
}

// TestPrivExecChainRefused: an open directory at any level from / to the
// parent (an ancestor above the privileged root, the root, an intermediate
// directory, the parent) refuses every placeholder and the cwd, in the
// preview and in priv_exec of either unit, with the same message naming the
// directory, and nothing runs.
func TestPrivExecChainRefused(t *testing.T) {
	f := newFixture(t, chainCommands())
	anc, root := chainRoot(f)
	a := filepath.Join(root, "a")
	b := filepath.Join(a, "b")
	gatetest.Mkdir(t, filepath.Join(b, "c"), 0o755)
	file := filepath.Join(b, "t")
	gatetest.WriteFile(t, file, "original\n", 0o644)
	cases := chainCases(file, filepath.Join(b, "new"), filepath.Join(b, "c"))
	zero := strings.Repeat("0", 64)
	for _, lvl := range []struct{ name, dir string }{{"ancestor", anc}, {"root", root}, {"intermediate", a}, {"parent", b}} {
		for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o777, os.ModeSticky | 0o775} {
			t.Run(fmt.Sprintf("%s %v", lvl.name, mode), func(t *testing.T) {
				f.t = t
				if err := os.Chmod(lvl.dir, mode); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = os.Chmod(lvl.dir, 0o755) }()
				for _, c := range cases {
					f.as("core")
					pr := f.serve("priv_exec_preview", c.req(c.core, ""))
					if pr.OK || pr.Error == nil || pr.Error.Code != "path_denied" || !strings.Contains(pr.Error.Message, lvl.dir) {
						t.Fatalf("%s: preview %+v %s, want path_denied naming %s", c.name, pr.Error, pr.Data, lvl.dir)
					}
					// priv_exec in each instance refuses at the resolution, before
					// the hash: the same code and message, whatever hash is sent.
					for _, u := range []struct{ unit, command string }{{"core", c.core}, {"broad", c.broad}} {
						f.as(u.unit)
						for _, hash := range []string{"", zero} {
							r := f.serveAt("operator", "priv_exec", c.req(u.command, hash))
							if r.OK || r.Error == nil || r.Error.Code != pr.Error.Code || r.Error.Message != pr.Error.Message {
								t.Fatalf("%s in %s (hash %q): %+v %s, want the preview's %+v", c.name, u.unit, hash, r.Error, r.Data, pr.Error)
							}
						}
					}
					if c.writes != "" && c.writes != file {
						absent(t, c.writes)
					}
					if readFile(t, file) != "original\n" {
						t.Fatalf("%s: %s was written", c.name, file)
					}
				}
			})
		}
	}
}

// TestPrivExecChainClosed: with every directory from / to the parent closed
// (the test's uid stands for root), {path:read}, {path:write} and the cwd
// resolve and run, previewed in the core unit and run in either.
func TestPrivExecChainClosed(t *testing.T) {
	f := newFixture(t, chainCommands())
	_, root := chainRoot(f)
	b := filepath.Join(root, "a", "b")
	gatetest.Mkdir(t, filepath.Join(b, "c"), 0o755)
	file := filepath.Join(b, "t")
	for _, u := range []struct{ unit string }{{"core"}, {"broad"}} {
		t.Run(u.unit, func(t *testing.T) {
			f.t = t
			gatetest.WriteFile(t, file, "original\n", 0o644)
			newFile := filepath.Join(b, "new-"+u.unit)
			for _, c := range chainCases(file, newFile, filepath.Join(b, "c")) {
				command := c.core
				if u.unit == "broad" {
					command = c.broad
				}
				f.as("core")
				p := f.execPreview(c.req(command, ""))
				if p.Unit != u.unit {
					t.Fatalf("%s: previewed for %q", c.name, p.Unit)
				}
				f.as(u.unit)
				var d execData
				f.ok("priv_exec", c.req(command, p.PreviewSHA256), &d)
				want := map[string]string{"read": "READ:original\n\n", "write new": "WROTE\n", "write existing": "WROTE\n", "cwd": filepath.Join(b, "c") + "\n"}[c.name]
				if d.Stdout != want {
					t.Fatalf("%s: stdout %q, want %q", c.name, d.Stdout, want)
				}
				if c.writes != "" && readFile(t, c.writes) != "probe" {
					t.Fatalf("%s: %s not written", c.name, c.writes)
				}
			}
		})
	}
}

// swapper exchanges name with alt (RENAME_EXCHANGE: name always exists) as
// fast as it can until stop is closed, as an account that can write their
// directory could.
func swapper(t *testing.T, name, alt string, stop <-chan struct{}, wg *sync.WaitGroup) {
	t.Helper()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = unix.Renameat2(unix.AT_FDCWD, alt, unix.AT_FDCWD, name, unix.RENAME_EXCHANGE)
		}
	}()
}

// TestPrivExecChainRace: an account that can write a directory on the path
// swaps the target (in the parent) or a directory above it (an intermediate
// directory) for a symlink to a file it cannot read or write, again and
// again, while root commands are previewed and run, approved with each
// fresh preview's hash. Every request is refused at the resolution, and the
// command never reads or writes the symlink's target.
func TestPrivExecChainRace(t *testing.T) {
	f := newFixture(t, chainCommands())
	_, root := chainRoot(f)
	outside := filepath.Join(f.d, "outside")
	gatetest.Mkdir(t, outside, 0o700)
	victim := filepath.Join(outside, "t")
	gatetest.WriteFile(t, victim, "VICTIM\n", 0o600)
	for _, c := range []struct {
		desc string
		// target is the placeholder's path; name and alt are exchanged.
		target, name, alt string
	}{
		{"the target in its parent", "open/t", "open/t", "open/t.alt"},
		{"a directory above the target", "open/sub/t", "open/sub", "open/sub.alt"},
	} {
		t.Run(c.desc, func(t *testing.T) {
			f.t = t
			open := filepath.Join(root, "open")
			_ = os.RemoveAll(open)
			gatetest.Mkdir(t, filepath.Join(open, "sub"), 0o755)
			gatetest.WriteFile(t, filepath.Join(open, "t"), "decoy\n", 0o644)
			gatetest.WriteFile(t, filepath.Join(open, "sub", "t"), "decoy\n", 0o644)
			if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
				t.Fatal(err)
			}
			to := victim
			if strings.HasSuffix(c.desc, "target") {
				to = outside
			}
			if err := os.Symlink(to, filepath.Join(root, c.alt)); err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			swapper(t, filepath.Join(root, c.name), filepath.Join(root, c.alt), stop, &wg)
			defer func() { close(stop); wg.Wait() }()
			target := filepath.Join(root, c.target)
			refused := 0
			for i := 0; i < 100; i++ {
				for _, rc := range []struct {
					command string
					args    []string
				}{{"chain-read", []string{"cat", target}}, {"chain-write", []string{"write", target}}} {
					f.as("core")
					req := m{"command_id": rc.command, "args": rc.args}
					pr := f.serve("priv_exec_preview", req)
					hash := strings.Repeat("0", 64)
					if pr.OK {
						var p execPreview
						if err := json.Unmarshal(pr.Data, &p); err != nil {
							t.Fatal(err)
						}
						hash = p.PreviewSHA256
					}
					req["expected_preview_sha256"] = hash
					er := f.serveAt("operator", "priv_exec", req)
					for _, r := range []response{pr, er} {
						if strings.Contains(string(r.Data), "VICTIM") {
							t.Fatalf("run %d: %s read the symlink's target: %s", i, rc.command, r.Data)
						}
						if r.OK || r.Error == nil || r.Error.Code != "path_denied" {
							t.Fatalf("run %d: %s %v: ok=%v %+v %s, want path_denied", i, rc.command, rc.args, r.OK, r.Error, r.Data)
						}
					}
					refused++
				}
				if readFile(t, victim) != "VICTIM\n" {
					t.Fatalf("run %d: the symlink's target was written", i)
				}
			}
			t.Logf("%d requests, each refused at the preview and at priv_exec", refused)
		})
	}
}
