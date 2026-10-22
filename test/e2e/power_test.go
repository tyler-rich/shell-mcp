//go:build e2e && linux

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The power operations on the runner (S4c-8; PRIVILEGED §6, "Power"): the
// real gate, the real helper in its broad unit, the runner's own logind and
// systemd (259 on ubuntu-26.04).
//
// The runner must never reboot or power off. reboot.target and
// poweroff.target are masked at runtime before anything is sent, and each
// test refuses to go on unless systemd reports both masked. Two layers then
// stop a request that reaches logind: logind refuses a target whose load
// state is not "loaded" before it tells anyone to prepare for shutdown
// (bus_manager_shutdown_or_sleep_now_or_later, systemd 257 and 259), and
// PID 1 refuses to start a masked unit. So a cancel that fails cannot take
// the runner down. The cleanup cancels any waiting action, waits until the
// package operation record is released (the waiting instance has ended),
// and only then unmasks; if it cannot confirm that, both targets stay
// masked (the runner VM is disposed of after the job). No test build tag:
// the release build is exercised, with its 60 s delay.

const pkgRecordPath = "/run/shell-mcp-privd-pkg"

// maskPower masks both targets for the test, proves it, and undoes it only
// once no power action can still be waiting.
func maskPower(t *testing.T) {
	t.Helper()
	run(t, "systemctl", "mask", "--runtime", "reboot.target", "poweroff.target")
	t.Cleanup(func() {
		if !drainPower(t) {
			// Fail the test and the job; never unmask while an action may
			// still be requested.
			t.Errorf("CLEANUP FAILED: the cancel could not be confirmed (the package operation record is still held after 90 s), " +
				"so a power action may still be waiting; reboot.target and poweroff.target are left masked on this runner")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "systemctl", "unmask", "--runtime", "reboot.target", "poweroff.target").CombinedOutput(); err != nil {
			t.Errorf("CLEANUP FAILED: unmask: %v %s", err, out)
		}
		for _, u := range []string{"reboot.target", "poweroff.target"} {
			if got, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "LoadState", "--value", u).Output(); err != nil || strings.TrimSpace(string(got)) == "masked" {
				t.Errorf("CLEANUP FAILED: %s is still masked (%q, %v)", u, got, err)
			}
		}
		// An immediate request logind refused at the masked target leaves its
		// ScheduledShutdown at (reboot, 0) (systemd 259: the action is set
		// before the target is checked, and nothing resets it on failure).
		// CancelScheduledShutdown resets it, so the runner's logind is left as
		// it was found.
		if out, err := exec.CommandContext(ctx, "busctl", "get-property", "org.freedesktop.login1", "/org/freedesktop/login1",
			"org.freedesktop.login1.Manager", "ScheduledShutdown").Output(); err == nil && !strings.Contains(string(out), `"" 0`) {
			_ = exec.CommandContext(ctx, "busctl", "call", "org.freedesktop.login1", "/org/freedesktop/login1",
				"org.freedesktop.login1.Manager", "CancelScheduledShutdown").Run()
		}
	})
	for _, u := range []string{"reboot.target", "poweroff.target"} {
		if got := show(t, u, "LoadState"); got != "masked" {
			t.Fatalf("%s LoadState=%q after masking: refusing to send any power request", u, got)
		}
	}
}

// recordFree reports whether nobody holds the package operation record (no
// package operation and no waiting power action). flock(1) would create a
// missing file with the wrong mode, so a missing record is checked first.
func recordFree(t *testing.T) bool {
	t.Helper()
	if _, err := os.Stat(pkgRecordPath); errors.Is(err, os.ErrNotExist) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "flock", "-n", "-s", pkgRecordPath, "true").Run() == nil
}

// drainPower cancels a waiting power action through the gate (outside the
// test's context, which a cleanup no longer has) and waits, at most 90 s,
// for the record to be released.
func drainPower(t *testing.T) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req := fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"read","op":"priv_power_cancel","args":{},"timeout_ms":30000}`+"\n", newID())
	cmd := exec.CommandContext(ctx, gateBin, "serve", "--policy", gatePolicy, "--principal", "e2e")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.Stdin = strings.NewReader(req)
	_ = cmd.Run()
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if recordFree(t) {
			return true
		}
	}
	return false
}

type powerPreviewData struct {
	Action        string `json:"action"`
	Target        string `json:"target"`
	DelayS        int64  `json:"delay_s"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type powerResultData struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	ScheduledAt string `json:"scheduled_at"`
	DelayS      int64  `json:"delay_s"`
	Cancel      string `json:"cancel"`
}

func powerPreview(t *testing.T) powerPreviewData {
	t.Helper()
	var p powerPreviewData
	mustGate(t, "priv_power_preview", map[string]any{"action": "reboot"}, &p)
	if p.Action != "reboot" || p.Target != "reboot.target" || p.DelayS != 60 || len(p.PreviewSHA256) != 64 {
		t.Fatalf("preview %+v", p)
	}
	return p
}

// schedule sends an approved-equivalent priv_power through the gate and
// returns its answer, its request id and the scheduled time.
func schedule(t *testing.T) (powerResultData, string, time.Time) {
	t.Helper()
	p := powerPreview(t)
	sent := time.Now()
	var d powerResultData
	_, id := mustGate(t, "priv_power", map[string]any{"action": "reboot", "expected_preview_sha256": p.PreviewSHA256}, &d)
	at, err := time.Parse(time.RFC3339Nano, d.ScheduledAt)
	if err != nil || d.Action != "reboot" || d.Target != "reboot.target" || d.DelayS != 60 ||
		at.Before(sent.Add(55*time.Second)) || at.After(time.Now().Add(65*time.Second)) || !strings.Contains(d.Cancel, "priv_power_cancel") {
		t.Fatalf("answer %+v (sent %s)", d, sent.UTC().Format(time.RFC3339Nano))
	}
	return d, id, at
}

// waitingInstance is the one active broad helper instance: the waiting
// power action's.
func waitingInstance(t *testing.T) string {
	t.Helper()
	var units []string
	for _, l := range strings.Split(run(t, "systemctl", "list-units", "--type=service", "--state=active", "--plain", "--no-legend", "shell-mcp-privd-broad@*"), "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			units = append(units, f[0])
		}
	}
	if len(units) != 1 {
		t.Fatalf("active broad instances %q, want exactly the waiting power action's", units)
	}
	return units[0]
}

// inhibit takes a logind inhibitor lock on shutdown as root until the test
// ends, and waits until logind lists it.
func inhibit(t *testing.T, who, mode string) {
	t.Helper()
	c := exec.CommandContext(t.Context(), "systemd-inhibit", "--what=shutdown", "--mode="+mode, "--who="+who, "--why=e2e test lock", "sleep", "300") //nolint:gosec // G204: a fixed test command; mode and who are the tests' own constants
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if strings.Contains(run(t, "systemd-inhibit", "--list", "--no-pager"), who) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("logind does not list the inhibitor %s", who)
		}
	}
}

// logindRefused lists systemd-logind's "refusing operation" lines since
// start: what logind logs when it refuses a request for a masked target.
func logindRefused(t *testing.T, since time.Time) []string {
	t.Helper()
	var out []string
	for _, e := range journal(t, "systemd-logind", since) {
		if strings.Contains(e.Message, "refusing operation") {
			out = append(out, e.Message)
		}
	}
	return out
}

// TestPowerPreviewOnHost: the preview names the action, the target and the
// delay; a power-off the policy does not list is refused; a block
// inhibitor on shutdown is refused, naming its holder, and a delay one is
// not.
func TestPowerPreviewOnHost(t *testing.T) {
	maskPower(t)
	powerPreview(t)
	wantGate(t, svcShell, "priv_power_preview", map[string]any{"action": "poweroff"}, "policy_denied")
	wantGate(t, svcShell, "priv_power", map[string]any{"action": "poweroff", "expected_preview_sha256": strings.Repeat("a", 64)}, "policy_denied")
	t.Run("delay inhibitor", func(t *testing.T) {
		inhibit(t, "e2e-power-delay", "delay")
		powerPreview(t)
	})
	t.Run("block inhibitor", func(t *testing.T) {
		inhibit(t, "e2e-power-block", "block")
		r, _ := gate(t, svcShell, "priv_power_preview", map[string]any{"action": "reboot"})
		if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "e2e-power-block") {
			t.Fatalf("preview with a block inhibitor: %s %+v", r.code(), r.Error)
		}
	})
}

// TestPowerScheduleAndCancel: the action is answered with its time and how
// to cancel it; until then systemd shows the waiting instance, the record
// is held, and previews of power and packages say a reboot is already scheduled;
// the cancel stops the instance (systemd shows it ended) and releases the
// record, and the journal says cancelled.
func TestPowerScheduleAndCancel(t *testing.T) {
	maskPower(t)
	start := time.Now()
	d, id, _ := schedule(t)
	unit := waitingInstance(t)
	if !strings.Contains(d.Cancel, "systemctl stop "+unit) {
		t.Fatalf("cancel %q does not name the waiting instance %s", d.Cancel, unit)
	}
	if recordFree(t) {
		t.Fatal("the record is free while the action waits")
	}
	for op, args := range map[string]map[string]any{"priv_power_preview": {"action": "reboot"}, "priv_pkg_install_preview": {"packages": []string{"example-hello"}}} {
		r, _ := gate(t, svcShell, op, args)
		if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "reboot is already scheduled for "+d.ScheduledAt) {
			t.Fatalf("%s while scheduled: %s %+v", op, r.code(), r.Error)
		}
	}
	var c struct {
		Cancelled   bool   `json:"cancelled"`
		RequestID   string `json:"request_id"`
		ScheduledAt string `json:"scheduled_at"`
	}
	r, _ := gateAt(t, svcShell, "read", "priv_power_cancel", map[string]any{})
	if !r.OK || json.Unmarshal(r.Data, &c) != nil || !c.Cancelled || c.RequestID != id || c.ScheduledAt != d.ScheduledAt {
		t.Fatalf("cancel %s %+v %s", r.code(), r.Error, r.Data)
	}
	for deadline := time.Now().Add(5 * time.Second); show(t, unit, "ActiveState") == "active"; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s is still active after the cancel", unit)
		}
	}
	if !recordFree(t) {
		t.Fatal("the record is still held after the cancel")
	}
	e := findJournal(t, "shell-mcp-privd", start, `"id":"`+id+`"`, `"op":"priv_power"`, `"power":"cancelled"`, `"answered_early":true`)
	if e.Priority != "4" || e.Unit != unit {
		t.Fatalf("journal line at %s by %s", e.Priority, e.Unit)
	}
	wantGate(t, svcShell, "priv_power_cancel", map[string]any{}, "not_found")
	powerPreview(t)
}

// TestPowerInstanceKilled (the maintainer's condition 2): an instance that
// dies during the wait requests nothing: past the scheduled time logind
// has logged no request, and the record is free.
func TestPowerInstanceKilled(t *testing.T) {
	maskPower(t)
	start := time.Now()
	_, id, at := schedule(t)
	unit := waitingInstance(t)
	run(t, "systemctl", "kill", "--signal=SIGKILL", unit)
	time.Sleep(time.Until(at.Add(10 * time.Second)))
	if got := logindRefused(t, start); len(got) != 0 {
		t.Fatalf("logind received a request: %q", got)
	}
	for _, e := range journal(t, "shell-mcp-privd", start) {
		if strings.Contains(e.Message, `"id":"`+id+`"`) {
			t.Fatalf("the killed instance logged %s", e.Message)
		}
	}
	if !recordFree(t) {
		t.Fatal("the record is held after the instance died")
	}
	powerPreview(t)
}

// TestPowerLogindRefusals (the maintainer's condition 4): an inhibitor
// taken during the wait makes logind refuse the request with its own
// inhibitor error, and logind never reaches the target (no "refusing
// operation" line); the control, without an inhibitor, is refused by the
// mask instead, which looks different: AccessDenied and logind's "Unit
// reboot.target is masked, refusing operation".
func TestPowerLogindRefusals(t *testing.T) {
	t.Run("inhibitor", func(t *testing.T) {
		maskPower(t)
		start := time.Now()
		_, id, at := schedule(t)
		inhibit(t, "e2e-power-late", "block")
		time.Sleep(time.Until(at.Add(3 * time.Second)))
		findJournal(t, "shell-mcp-privd", start, `"id":"`+id+`"`, `"power":"refused"`, "org.freedesktop.login1.BlockedByInhibitorLock")
		if got := logindRefused(t, start); len(got) != 0 {
			t.Fatalf("logind looked at the target although an inhibitor blocked the request: %q", got)
		}
	})
	t.Run("masked control", func(t *testing.T) {
		maskPower(t)
		start := time.Now()
		_, id, at := schedule(t)
		time.Sleep(time.Until(at.Add(3 * time.Second)))
		e := findJournal(t, "shell-mcp-privd", start, `"id":"`+id+`"`, `"power":"refused"`, "org.freedesktop.DBus.Error.AccessDenied")
		if strings.Contains(e.Message, "BlockedByInhibitorLock") {
			t.Fatalf("the control was refused as inhibited: %s", e.Message)
		}
		findJournal(t, "systemd-logind", start, "reboot.target is masked, refusing operation")
	})
}

// TestPowerNotDelivered (the maintainer's condition 5): a client that sends
// priv_power and closes without reading the answer schedules nothing: the
// instance ends at once, the record is free, the journal says
// not_delivered, and the next preview shows nothing scheduled.
func TestPowerNotDelivered(t *testing.T) {
	maskPower(t)
	start := time.Now()
	p := powerPreview(t)
	id := newID()
	line := fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"destructive","op":"priv_power","args":{"action":"reboot","expected_preview_sha256":%q},"timeout_ms":30000}`+"\n", id, p.PreviewSHA256)
	cl, _ := hangupClient(t, "drop", broadSocket, line, 3*time.Second)
	_ = cl.Wait()
	findJournal(t, "shell-mcp-privd", start, `"id":"`+id+`"`, `"power":"not_delivered"`, `"answered_early":true`)
	if !recordFree(t) {
		t.Fatal("the record is held after an undelivered answer")
	}
	powerPreview(t)
}

// TestPowerToolApproval: through the real server, shell_priv_reboot_host
// previews, is approved, and is answered with its time; a second re-call is
// approval_invalid; shell_priv_cancel_power, never gated, cancels it.
func TestPowerToolApproval(t *testing.T) {
	maskPower(t)
	start := time.Now()
	srv, h := privWriteServer(t)
	args := map[string]any{"action": "reboot"}
	id := pendingID(t, srv.callTool(t, "shell_priv_reboot_host", args))
	if !recordFree(t) {
		t.Fatal("scheduled before approval")
	}
	srv.decide(t, h, id, "approve")
	d := okDataAs(t, srv.callTool(t, "shell_priv_reboot_host", withApproval(args, id)), "e2e-ssh")
	if d["action"] != "reboot" || d["target_unit"] != "reboot.target" || d["delay_seconds"] != float64(60) || d["scheduled_at"] == nil {
		t.Fatalf("data %v", d)
	}
	refusal(t, srv.callTool(t, "shell_priv_reboot_host", withApproval(args, id)), "approval_invalid", "")
	c := okDataAs(t, srv.callTool(t, "shell_priv_cancel_power", map[string]any{}), "e2e-ssh")
	if c["cancelled"] != true || c["scheduled_at"] != d["scheduled_at"] {
		t.Fatalf("cancel %v", c)
	}
	findJournal(t, "shell-mcp-privd", start, `"op":"priv_power"`, `"power":"cancelled"`)
}
