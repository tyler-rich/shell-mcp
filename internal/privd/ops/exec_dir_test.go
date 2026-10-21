//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// A directory given to a root command (the cwd, or a {path:read} or
// {path:write} that is a directory) is closed itself, besides its chain from
// /: the command works inside it, and another account that can change its
// entries could plant a symlink there (handoff N-10, maintainer decision of
// 2026-10-21). A file keeps the chain rule alone. Every path, name and
// command is an invented fixture; "another account" is a group- or
// world-writable or sticky directory here (e2e-host's TestPrivExecPathChain
// gives the directory to example-app).

func dirCases(dir string) []chainCase {
	return []chainCase{
		{"cwd", "chain-read", "chain-broad-read", []string{"pwd"}, dir, ""},
		{"read", "chain-read", "chain-broad-read", []string{"echo", dir}, "", ""},
		{"write", "chain-write", "chain-broad-write", []string{"echo", dir}, "", ""},
	}
}

// TestPrivExecDirTargetRefused: an open directory as the cwd, {path:read} or
// {path:write} is refused by the preview and by priv_exec in either
// instance, with the same message naming it, and nothing runs.
func TestPrivExecDirTargetRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, chainCommands())
	_, root := chainRoot(f)
	dir := filepath.Join(root, "a", "d")
	gatetest.Mkdir(t, dir, 0o755)
	zero := strings.Repeat("0", 64)
	for _, mode := range []os.FileMode{0o775, 0o777, os.ModeSticky | 0o777, os.ModeSticky | 0o755} {
		t.Run(mode.String(), func(t *testing.T) {
			f.t = t
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(dir, 0o755) }() //nolint:gosec // G302: a directory, closed again
			for _, c := range dirCases(dir) {
				f.as("core")
				pr := f.serve("priv_exec_preview", c.req(c.core, ""))
				if pr.OK || pr.Error == nil || pr.Error.Code != "path_denied" || !strings.Contains(pr.Error.Message, dir) {
					t.Fatalf("%s: preview %+v %s, want path_denied naming %s", c.name, pr.Error, pr.Data, dir)
				}
				for _, u := range []struct{ unit, command string }{{"core", c.core}, {"broad", c.broad}} {
					f.as(u.unit)
					for _, hash := range []string{"", zero} {
						r := f.serveAt("operator", "priv_exec", c.req(u.command, hash))
						if r.OK || r.Error == nil || r.Error.Code != pr.Error.Code || r.Error.Message != pr.Error.Message {
							t.Fatalf("%s in %s (hash %q): %+v %s, want the preview's %+v", c.name, u.unit, hash, r.Error, r.Data, pr.Error)
						}
					}
				}
			}
		})
	}
}

// TestPrivExecDirTargetClosed: a closed directory as the cwd, {path:read}
// and {path:write} is previewed in the core unit and runs with the hash in
// either unit.
func TestPrivExecDirTargetClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, chainCommands())
	_, root := chainRoot(f)
	dir := filepath.Join(root, "a", "d")
	gatetest.Mkdir(t, dir, 0o755)
	for _, unit := range []string{"core", "broad"} {
		for _, c := range dirCases(dir) {
			command := c.core
			if unit == "broad" {
				command = c.broad
			}
			f.as("core")
			p := f.execPreview(c.req(command, ""))
			f.as(unit)
			var d execData
			f.ok("priv_exec", c.req(command, p.PreviewSHA256), &d)
			if d.Stdout != dir+"\n" {
				t.Fatalf("%s in %s: stdout %q, want %q", c.name, unit, d.Stdout, dir+"\n")
			}
		}
	}
}

// TestPrivExecDirTargetRace: an account that can write the cwd plants a
// symlink to a file outside under the name the command reads relative to
// it, swapping it with its own file again and again, while the command is
// previewed and run in each unit with the fresh hash. Every request is
// refused at the resolution, and the command never reads the file.
func TestPrivExecDirTargetRace(t *testing.T) {
	t.Parallel()
	f := newFixture(t, chainCommands())
	_, root := chainRoot(f)
	outside := filepath.Join(f.d, "outside")
	gatetest.Mkdir(t, outside, 0o700)
	victim := filepath.Join(outside, "t")
	gatetest.WriteFile(t, victim, "VICTIM\n", 0o600)
	cwd := filepath.Join(root, "open")
	gatetest.WriteFile(t, filepath.Join(cwd, "t"), "decoy\n", 0o644)
	if err := os.Chmod(cwd, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(cwd, "t.alt")); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	swapper(t, filepath.Join(cwd, "t"), filepath.Join(cwd, "t.alt"), stop, &wg)
	defer func() { close(stop); wg.Wait() }()
	requests := 0
	for i := 0; i < 100; i++ {
		for _, u := range []struct{ unit, command string }{{"core", "chain-read"}, {"broad", "chain-broad-read"}} {
			f.as("core")
			req := m{"command_id": u.command, "args": []string{"cat", "t"}, "cwd": cwd}
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
			f.as(u.unit)
			er := f.serveAt("operator", "priv_exec", req)
			for _, r := range []response{pr, er} {
				if strings.Contains(string(r.Data), "VICTIM") {
					t.Fatalf("run %d in %s: the command read the symlink's target: %s", i, u.unit, r.Data)
				}
				if r.OK || r.Error == nil || r.Error.Code != "path_denied" {
					t.Fatalf("run %d in %s: ok=%v %+v %s, want path_denied", i, u.unit, r.OK, r.Error, r.Data)
				}
			}
			requests++
		}
	}
	t.Logf("%d requests, each refused at the preview and at priv_exec", requests)
}
