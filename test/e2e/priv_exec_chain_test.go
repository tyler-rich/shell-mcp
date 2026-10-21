//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/test/e2e/runner"
)

// Root commands' path placeholders and cwd under the chain rule (handoff
// docs/handoff/S4C-PRIVILEGED.md N-10), end to end: the real gate and the
// real helper in both units, as root, with a real other account
// (example-app). setup.sh declares the write root /srv/e2e-priv-exec/root
// under its own ancestor, and the commands probe-cat (core, read: cat a
// {path:read}, pwd), probe-broad (broad, read: the same templates),
// probe-root-op and probe-broad-op (operator: write a {path:write}). Every
// path and name is an invented fixture.

const (
	chainAnc  = "/srv/e2e-priv-exec"
	chainRoot = chainAnc + "/root"
)

type chainUnit struct{ unit, read, write string }

var chainUnits = []chainUnit{{"core", "probe-cat", "probe-root-op"}, {"broad", "probe-broad", "probe-broad-op"}}

// chainExec previews command through the gate (the core socket) and runs
// it in unit with the preview's hash, or with an invalid one when the
// preview is refused; it returns both answers.
func chainExec(t *testing.T, unit, command string, args []string, cwd string) (preview, run response) {
	t.Helper()
	req := map[string]any{"command_id": command, "args": args}
	if cwd != "" {
		req["cwd"] = cwd
	}
	preview, _ = gate(t, svcShell, "priv_exec_preview", req)
	hash := strings.Repeat("0", 64)
	if preview.OK {
		var p struct {
			Unit          string `json:"unit"`
			PreviewSHA256 string `json:"preview_sha256"`
		}
		if err := json.Unmarshal(preview.Data, &p); err != nil || p.Unit != unit {
			t.Fatalf("%s previewed %s: %v", command, preview.Data, err)
		}
		hash = p.PreviewSHA256
	}
	req["unit"] = unit
	req["expected_preview_sha256"] = hash
	run, _ = gate(t, svcShell, "priv_exec", req)
	return preview, run
}

func stdoutOf(t *testing.T, r *response) string {
	t.Helper()
	var d struct {
		Stdout string `json:"stdout"`
	}
	if !r.OK || json.Unmarshal(r.Data, &d) != nil {
		t.Fatalf("not run: %+v %s", r.Error, r.Data)
	}
	return d.Stdout
}

// chainFixture makes root:root 0755 directories a/b/c under the root and a
// root:root 0644 file a/b/t, and puts every directory of the chain back to
// root:root 0755 when the test ends.
func chainFixture(t *testing.T) (a, b string) {
	t.Helper()
	a = filepath.Join(chainRoot, "a")
	b = filepath.Join(a, "b")
	_ = os.RemoveAll(a)
	if err := os.MkdirAll(filepath.Join(b, "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	rootFile(t, filepath.Join(b, "t"), "original\n", 0o644)
	t.Cleanup(func() {
		for _, d := range []string{chainAnc, chainRoot} {
			_ = os.Chown(d, 0, 0)
			_ = os.Chmod(d, 0o755)
		}
		_ = os.RemoveAll(a)
	})
	return a, b
}

// TestPrivExecPathChain: with every directory from / to the parent root's
// and closed, {path:read}, {path:write} and the cwd resolve and run in both
// units; with any one of them (an ancestor above the privileged root, the
// root, an intermediate directory, the parent) owned by example-app, or
// group-writable, world-writable or sticky, the preview and priv_exec in
// either unit refuse with path_denied naming it, and nothing runs.
func TestPrivExecPathChain(t *testing.T) {
	a, b := chainFixture(t)
	file := filepath.Join(b, "t")
	sub := filepath.Join(b, "c")

	t.Run("closed", func(t *testing.T) {
		for _, u := range chainUnits {
			rootFile(t, file, "original\n", 0o644)
			_, r := chainExec(t, u.unit, u.read, []string{"cat", file}, "")
			if out := stdoutOf(t, &r); out != "READ:original\n\n" {
				t.Fatalf("%s read %q", u.unit, out)
			}
			_, r = chainExec(t, u.unit, u.read, []string{"pwd"}, sub)
			if out := stdoutOf(t, &r); out != sub+"\n" {
				t.Fatalf("%s cwd %q", u.unit, out)
			}
			newFile := filepath.Join(b, "new-"+u.unit)
			_, r = chainExec(t, u.unit, u.write, []string{"write", newFile}, "")
			if out := stdoutOf(t, &r); out != "WROTE\n" {
				t.Fatalf("%s write %q", u.unit, out)
			}
			fileIs(t, newFile, "probe")
			_ = os.Remove(newFile)
		}
	})

	for _, lvl := range []struct{ name, dir string }{{"ancestor", chainAnc}, {"root", chainRoot}, {"intermediate", a}, {"parent", b}} {
		for _, o := range []struct {
			name string
			uid  int
			mode os.FileMode
		}{
			{"owned by example-app", exampleApp, 0o755},
			{"group-writable", 0, 0o775},
			{"world-writable", 0, 0o777},
			{"sticky", 0, os.ModeSticky | 0o777},
		} {
			t.Run(lvl.name+" "+o.name, func(t *testing.T) {
				if err := os.Chown(lvl.dir, o.uid, o.uid); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(lvl.dir, o.mode); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = os.Chown(lvl.dir, 0, 0)
					_ = os.Chmod(lvl.dir, 0o755)
				}()
				for _, u := range chainUnits {
					newFile := filepath.Join(b, "new-"+u.unit)
					for _, c := range []struct {
						command string
						args    []string
						cwd     string
					}{
						{u.read, []string{"cat", file}, ""},
						{u.read, []string{"pwd"}, sub},
						{u.write, []string{"write", newFile}, ""},
						{u.write, []string{"write", file}, ""},
					} {
						pr, er := chainExec(t, u.unit, c.command, c.args, c.cwd)
						if pr.code() != "path_denied" || !strings.Contains(pr.Error.Message, lvl.dir) {
							t.Fatalf("%s %v cwd %q: preview %s %+v, want path_denied naming %s", c.command, c.args, c.cwd, pr.code(), pr.Error, lvl.dir)
						}
						if er.code() != "path_denied" || er.Error.Message != pr.Error.Message {
							t.Fatalf("%s %v in %s: %s %+v, want the preview's refusal", c.command, c.args, u.unit, er.code(), er.Error)
						}
					}
					if _, err := os.Lstat(newFile); err == nil {
						t.Fatalf("%s: %s was created", u.unit, newFile)
					}
					fileIs(t, file, "original\n")
				}
			})
		}
	}
}

// swapClient is the racer: run as another account, it makes the symlink
// E2E_SWAP_ALT pointing at E2E_SWAP_TO and exchanges it with E2E_SWAP_NAME
// (RENAME_EXCHANGE, so the name always exists) until its stdin closes,
// then prints how many exchanges succeeded.
func swapClient() int {
	name, alt := os.Getenv("E2E_SWAP_NAME"), os.Getenv("E2E_SWAP_ALT")
	if err := os.Symlink(os.Getenv("E2E_SWAP_TO"), alt); err != nil {
		fmt.Println("SYMLINK:", err)
		return 3
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	n := 0
	for {
		select {
		case <-done:
			fmt.Println("SWAPS", n)
			return 0
		default:
		}
		if unix.Renameat2(unix.AT_FDCWD, alt, unix.AT_FDCWD, name, unix.RENAME_EXCHANGE) == nil {
			n++
		}
	}
}

// TestPrivExecPathChainRace: example-app, which owns a directory under the
// privileged root, swaps the target (in that directory) or a directory
// above it for a symlink to a root-only file in the same root (which both
// units' commands could reach), again and again, while root commands of
// each unit are previewed and run with each fresh preview's hash. Every
// request is refused at the resolution, and the commands never read or
// write the file.
func TestPrivExecPathChainRace(t *testing.T) {
	vault := filepath.Join(chainRoot, "vault")
	race := filepath.Join(chainRoot, "race")
	t.Cleanup(func() {
		_ = os.RemoveAll(vault)
		_ = os.RemoveAll(race)
	})
	_ = os.RemoveAll(vault)
	if err := os.Mkdir(vault, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(vault, "t")
	rootFile(t, victim, "VICTIM\n", 0o600)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, target, swap, to string }{
		{"the target in its parent", "t", "t", victim},
		{"a directory above the target", "sub/t", "sub", vault},
	} {
		t.Run(c.name, func(t *testing.T) {
			// race/t and race/sub/t are example-app's decoys, in its directories.
			_ = os.RemoveAll(race)
			if err := os.MkdirAll(filepath.Join(race, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{filepath.Join(race, "t"), filepath.Join(race, "sub", "t")} {
				if err := os.WriteFile(p, []byte("decoy\n"), 0o644); err != nil { //nolint:gosec // G306: the account's own readable decoy
					t.Fatal(err)
				}
			}
			for _, p := range []string{race, filepath.Join(race, "sub"), filepath.Join(race, "t"), filepath.Join(race, "sub", "t")} {
				if err := os.Lchown(p, exampleApp, exampleApp); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.CommandContext(t.Context(), self) //nolint:gosec // G204: this test binary itself, in client mode
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, exampleApp)}
			cmd.Env = append(runner.Env(), "E2E_CLIENT=swap", "E2E_SWAP_NAME="+filepath.Join(race, c.swap),
				"E2E_SWAP_ALT="+filepath.Join(race, c.swap+".alt"), "E2E_SWAP_TO="+c.to)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			cmd.Stdout = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(race, c.target)
			requests := 0
			for i := 0; i < 15; i++ {
				for _, u := range chainUnits {
					for _, rc := range []struct {
						command string
						args    []string
					}{{u.read, []string{"cat", target}}, {u.write, []string{"write", target}}} {
						pr, er := chainExec(t, u.unit, rc.command, rc.args, "")
						for _, r := range []response{pr, er} {
							if strings.Contains(string(r.Data), "VICTIM") {
								t.Fatalf("run %d: %s read the root-only file: %s", i, rc.command, r.Data)
							}
							if r.code() != "path_denied" {
								t.Fatalf("run %d: %s %v in %s: %s %+v %s, want path_denied", i, rc.command, rc.args, u.unit, r.code(), r.Error, r.Data)
							}
						}
						requests++
					}
				}
			}
			_ = stdin.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatalf("racer: %v %q", err, out.String())
			}
			f := strings.Fields(out.String())
			if len(f) != 2 || f[0] != "SWAPS" {
				t.Fatalf("racer: %q", out.String())
			}
			if n, err := strconv.Atoi(f[1]); err != nil || n == 0 {
				t.Fatalf("the racer did not swap: %q", out.String())
			}
			fileIs(t, victim, "VICTIM\n")
			t.Logf("%d requests refused at the preview and at priv_exec; racer: %s", requests, strings.TrimSpace(out.String()))
		})
	}
}
