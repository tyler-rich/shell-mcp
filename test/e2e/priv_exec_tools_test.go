//go:build e2e && linux

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/test/e2e/runner"
)

// shell_priv_run_command and priv_exec end to end (S4c-6): the real server
// (admin profile, web approval with a simulated human), the real gate and
// the real helper in both units; a command previewed in the core unit and
// run in its own; and the command killed when the gate hangs up (must-fix
// (a)). The commands are the invented example-probe declared by setup.sh.

// execPreviewHash previews command with args through the gate (the core
// socket) and returns its hash and unit.
func execPreviewHash(t *testing.T, command string, args []string) (hash, unit string) {
	t.Helper()
	var p struct {
		Unit          string `json:"unit"`
		PreviewSHA256 string `json:"preview_sha256"`
	}
	mustGate(t, "priv_exec_preview", map[string]any{"command_id": command, "args": args}, &p)
	return p.PreviewSHA256, p.Unit
}

// helperUnitOf returns the unit (core or broad) whose instance wrote a
// journal entry.
func helperUnitOf(j *journalEntry) string {
	switch {
	case strings.HasPrefix(j.Unit, "shell-mcp-privd-broad@"):
		return "broad"
	case strings.HasPrefix(j.Unit, "shell-mcp-privd@"):
		return "core"
	}
	return ""
}

// TestPrivRunCommandToolApproval: an operator command of each unit is
// previewed in the core unit, approved, and run once in its own unit,
// through the real server; a second re-call is approval_invalid. A read
// command runs without approval.
func TestPrivRunCommandToolApproval(t *testing.T) {
	srv, h := privWriteServer(t)
	conn := connOf(t, srv.cs)
	for _, c := range []struct{ command, unit string }{{"probe-root-op", "core"}, {"probe-broad-op", "broad"}} {
		t.Run(c.unit, func(t *testing.T) {
			out := filepath.Join(privWriteDir, "exec-"+c.unit)
			_ = os.Remove(out)
			args := map[string]any{"command_id": c.command, "args": []string{"write", out}}
			id := pendingID(t, srv.callTool(t, "shell_priv_run_command", args))
			if _, err := os.Lstat(out); err == nil {
				t.Fatal("ran before approval")
			}
			pv := conn.waitHelper(t, `"op":"priv_exec_preview"`, `"command_id":"`+c.command+`"`, `"outcome":"ok"`)
			if helperUnitOf(&pv) != "core" {
				t.Fatalf("previewed by %q", pv.Unit)
			}
			srv.decide(t, h, id, "approve")
			d := okDataAs(t, srv.callTool(t, "shell_priv_run_command", withApproval(args, id)), "e2e-ssh")
			fileIs(t, out, "probe")
			if d["command_id"] != c.command {
				t.Fatalf("data %v", d)
			}
			j := conn.waitHelper(t, `"op":"priv_exec"`, `"command_id":"`+c.command+`"`, `"unit":"`+c.unit+`"`, `"outcome":"ok"`)
			if helperUnitOf(&j) != c.unit || strings.Contains(j.Message, "expected_preview_sha256") || strings.Contains(j.Message, out) {
				t.Fatalf("exec journal line from %q: %s", j.Unit, j.Message)
			}
			if c.unit == "broad" && j.Priority != "4" {
				t.Fatalf("broad line at priority %s", j.Priority)
			}
			refusal(t, srv.callTool(t, "shell_priv_run_command", withApproval(args, id)), "approval_invalid", "")
			time.Sleep(time.Second)
			if n := len(conn.helper(t, `"op":"priv_exec"`, `"command_id":"`+c.command+`"`)); n != 1 {
				t.Fatalf("%d priv_exec lines, want 1", n)
			}
		})
	}
	conn.same(t)
	t.Run("read command, unapproved", func(t *testing.T) {
		d := okDataAs(t, srv.callTool(t, "shell_priv_run_command", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "as-root"}}), "e2e-ssh")
		if d["stdout"] != "as-root\n" {
			t.Fatalf("data %v", d)
		}
	})
}

// TestPrivExecPreviewMisrouted: the broad instance never previews, and each
// instance refuses the other unit's commands, whatever the label says.
func TestPrivExecPreviewMisrouted(t *testing.T) {
	line := func(op, args string) string {
		return fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"operator","op":%q,"args":%s,"timeout_ms":5000}`+"\n", newID(), op, args)
	}
	for _, c := range []struct{ socket, op, args string }{
		{broadSocket, "priv_exec_preview", `{"command_id":"probe-broad-op","args":["write","/etc/example-app/x"]}`},
		{broadSocket, "priv_exec", `{"command_id":"probe-root-op","args":["write","/etc/example-app/x"],"unit":"broad"}`},
		{socketPath, "priv_exec", `{"command_id":"probe-broad-op","args":["write","/etc/example-app/x"]}`},
	} {
		if out := directTo(t, svcShell, c.socket, line(c.op, c.args)); !strings.Contains(out, `"code":"helper_wrong_unit"`) {
			t.Fatalf("%s %s at %s: %s", c.op, c.args, c.socket, out)
		}
	}
}

// hangupClient runs this binary as svc-shell in client mode against socket:
// it sends line and hangs up after delay ("drop" or "half"). It returns the
// started client and a buffer that receives what the helper wrote.
func hangupClient(t *testing.T, mode, socket, line string, delay time.Duration) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), self) //nolint:gosec // G204: this test binary itself, in client mode
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
	cmd.Env = append(runner.Env(), "E2E_CLIENT="+mode, "E2E_SOCKET="+socket, "E2E_HANGUP_MS="+strconv.FormatInt(delay.Milliseconds(), 10))
	cmd.Stdin = strings.NewReader(line)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd, &out
}

// TestPrivExecKilledOnHangup (must-fix (a)): in each unit, an approved
// command that ignores SIGTERM, and one that has also started a process in
// a session of its own (outside its process group), are stopped by the
// helper when the gate hangs up: dead before the helper answers a gate
// that stopped waiting (the case of an instance that started late, behind
// S4c-1's residual), and within the kill grace when the gate's connection
// is simply gone. The journal line records the hang-up.
func TestPrivExecKilledOnHangup(t *testing.T) {
	for _, c := range []struct {
		unit, command, socket, sleep, detach string
	}{
		{"core", "probe-root-op", socketPath, "61s", "62s"},
		{"broad", "probe-broad-op", broadSocket, "63s", "64s"},
	} {
		for _, mode := range []string{"half", "drop"} {
			for _, detach := range []bool{false, true} {
				name := c.unit + "/" + mode
				args := []string{"ignore-term", c.sleep}
				if detach {
					name += "/detached"
					args = []string{"detach", c.detach}
				}
				t.Run(name, func(t *testing.T) {
					hash, unit := execPreviewHash(t, c.command, args)
					if unit != c.unit {
						t.Fatalf("previewed unit %q", unit)
					}
					a := map[string]any{"command_id": c.command, "args": args, "expected_preview_sha256": hash}
					if c.unit == "broad" {
						a["unit"] = "broad"
					}
					b, _ := json.Marshal(a)
					reqID := newID()
					line := fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"operator","op":"priv_exec","args":%s,"timeout_ms":60000}`+"\n", reqID, b)
					cl, out := hangupClient(t, mode, c.socket, line, 3*time.Second)
					p := gatetest.FindChild(t, 0, args...)
					t.Cleanup(p.Kill)
					p.WaitIgnoring(t, syscall.SIGTERM)
					helperOf(t, p, c.unit == "broad")
					var lingering gatetest.Proc
					if detach {
						lingering = gatetest.FindChild(t, 0, "linger", c.detach)
						t.Cleanup(lingering.Kill)
						lingering.WaitIgnoring(t, syscall.SIGTERM)
					}
					if err := cl.Wait(); err != nil {
						t.Fatalf("client: %v %q", err, out.String())
					}
					hungUp := time.Now()
					switch mode {
					case "half":
						// The helper answered only after the command, and what
						// it started in a session of its own, were killed and
						// reaped: both pids gone from /proc, not even zombies.
						if !p.Reaped() || (detach && !lingering.Reaped()) {
							t.Fatalf("the helper answered before the command and its children were gone: %s", out.String())
						}
						var r struct {
							Error *struct {
								Code string `json:"code"`
							} `json:"error"`
						}
						if json.Unmarshal(out.Bytes(), &r) != nil || r.Error == nil || r.Error.Code != "outcome_unknown" {
							t.Fatalf("answer %s", out.String())
						}
					case "drop":
						if !p.WaitReaped(4*time.Second) || (detach && !lingering.WaitReaped(time.Second)) {
							t.Fatalf("the command outlived the gate's connection by %v", time.Since(hungUp))
						}
					}
					waitLine(t, "shell-mcp-privd", `"id":"`+reqID+`"`, `"op":"priv_exec"`, `"command_id":"`+c.command+`"`, `"hung_up":true`, `"outcome":"outcome_unknown"`)
				})
			}
		}
	}
}

// TestPrivExecGateKilled: the real gate forwarding an approved command is
// killed mid-run; the helper kills the command, in each unit.
func TestPrivExecGateKilled(t *testing.T) {
	for _, c := range []struct{ unit, command, sleep string }{{"core", "probe-root-op", "61s"}, {"broad", "probe-broad-op", "63s"}} {
		t.Run(c.unit, func(t *testing.T) {
			args := []string{"ignore-term", c.sleep}
			hash, _ := execPreviewHash(t, c.command, args)
			a := map[string]any{"command_id": c.command, "args": args, "expected_preview_sha256": hash}
			if c.unit == "broad" {
				a["unit"] = "broad"
			}
			b, _ := json.Marshal(a)
			req := fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"operator","op":"priv_exec","args":%s,"timeout_ms":60000}`+"\n", newID(), b)
			cmd := exec.CommandContext(t.Context(), gateBin, "serve", "--policy", gatePolicy, "--principal", "e2e")
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			cmd.Dir = "/"
			cmd.Stdin = strings.NewReader(req)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			p := gatetest.FindChild(t, 0, args...)
			t.Cleanup(p.Kill)
			p.WaitIgnoring(t, syscall.SIGTERM)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if !p.WaitGone(4 * time.Second) {
				t.Fatal("the command outlived the killed gate")
			}
		})
	}
}
