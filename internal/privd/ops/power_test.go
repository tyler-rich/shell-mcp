//go:build linux

package ops_test

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus/dbustest"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
)

// The power operations (PRIVILEGED §6, "Power"; handoff S4c-8, design B2):
// priv_power_preview reports the action, the unit logind will start, the
// delay and a hash, and refuses whatever would block the action;
// priv_power answers first, confirms the gate read the answer, waits the
// delay holding the package operation record, checks again, and only then
// asks logind (RebootWithFlags or PowerOffWithFlags with
// SD_LOGIND_ROOT_CHECK_INHIBITORS); priv_power_cancel stops a waiting
// action. logind here is a fake behind the fake bus; every name, uid and
// pid is invented. The delay is 1 s instead of 60 s (Options.PowerDelay,
// tests only).

// logind is the fake logind: its inhibitor locks, its scheduled shutdown
// and preparing state, and the shutdown requests it received.
type logind struct {
	mu         sync.Mutex
	inhibitors []dbustest.Inhibitor
	scheduled  string
	preparing  bool
	// refuse is the error name a request is answered with ("" accepts it).
	refuse string
	// hold, when set, makes a request wait for it to be closed before
	// logind answers; pending counts requests waiting.
	hold    chan struct{}
	pending int
	reqs    []logindRequest
}

type logindRequest struct {
	member string
	flags  any
	at     time.Time
}

func (l *logind) answer(m *dbus.Message) []byte {
	o := binary.LittleEndian
	l.mu.Lock()
	switch {
	case m.Member == "ListInhibitors" && m.Interface == "org.freedesktop.login1.Manager":
		list := append([]dbustest.Inhibitor(nil), l.inhibitors...)
		l.mu.Unlock()
		return dbustest.Inhibitors(o, m.Serial, list)
	case m.Member == "Get" && m.Interface == "org.freedesktop.DBus.Properties":
		args, _ := m.Strings()
		scheduled, preparing := l.scheduled, l.preparing
		l.mu.Unlock()
		if len(args) == 2 && args[0] == "org.freedesktop.login1.Manager" {
			switch args[1] {
			case "ScheduledShutdown":
				at := uint64(0)
				if scheduled != "" {
					at = 1_790_000_000_000_000
				}
				return dbustest.Property(o, m.Serial, "(st)", dbustest.ST(o, scheduled, at))
			case "PreparingForShutdown":
				return dbustest.Property(o, m.Serial, "b", dbustest.Bool(o, preparing))
			}
		}
		return dbustest.ErrorReply(o, m.Serial, "org.freedesktop.DBus.Error.UnknownProperty", "unknown property")
	case (m.Member == "RebootWithFlags" || m.Member == "PowerOffWithFlags") && m.Interface == "org.freedesktop.login1.Manager":
		var flags any
		if v, err := m.Values(); err == nil && len(v) == 1 {
			flags = v[0]
		}
		l.reqs = append(l.reqs, logindRequest{member: m.Member, flags: flags, at: time.Now()})
		hold, refuse := l.hold, l.refuse
		l.pending++
		l.mu.Unlock()
		if hold != nil {
			<-hold
		}
		if refuse != "" {
			return dbustest.ErrorReply(o, m.Serial, refuse, "Operation denied due to active block inhibitor.")
		}
		return dbustest.Empty(o, m.Serial)
	}
	l.mu.Unlock()
	return dbustest.ErrorReply(o, m.Serial, "org.freedesktop.DBus.Error.UnknownMethod", "unknown method")
}

func (l *logind) requests() []logindRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]logindRequest(nil), l.reqs...)
}

func (l *logind) set(f func(l *logind)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f(l)
}

// bothActions lists reboot and poweroff in the policy's power section.
func bothActions() opt { return replace("  allowed: [reboot]\n", "  allowed: [reboot, poweroff]\n") }

// longLimit raises limits.max_timeout_s to 60, which priv_power needs.
func longLimit() opt { return replace("  max_timeout_s: 10\n", "  max_timeout_s: 60\n") }

// powerFixture is the broad unit's helper with power allowed, the apt-get
// stand-in and a fake logind.
func powerFixture(t *testing.T, l *logind, opts ...opt) *fixture {
	t.Helper()
	f := modelFixture(t, &pkgModel{}, nil, append([]opt{longLimit()}, opts...)...)
	b := dbustest.Start(t, l.answer)
	f.opts.SystemBus = b.Path
	f.opts.PowerDelay = time.Second
	f.opts.PowerConfirmWait = 2 * time.Second
	f.opts.PowerDecision = filepath.Join(filepath.Dir(f.record), "shell-mcp-privd-power")
	return f
}

type powerPreview struct {
	Action        string `json:"action"`
	Target        string `json:"target"`
	DelayS        int    `json:"delay_s"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type powerResult struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	ScheduledAt string `json:"scheduled_at"`
	DelayS      int    `json:"delay_s"`
	Cancel      string `json:"cancel"`
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (f *fixture) powerPreview(action string) powerPreview {
	f.t.Helper()
	var p powerPreview
	f.ok("priv_power_preview", m{"action": action}, &p)
	return p
}

func powerArgs(action, hash string) m {
	return m{"action": action, "expected_preview_sha256": hash}
}

// auditOf decodes the audit line of the request with this op.
func (f *fixture) auditOf(op string) map[string]any {
	f.t.Helper()
	for _, l := range slicesReverse(f.auditLines()) {
		var a map[string]any
		if json.Unmarshal([]byte(l[3:]), &a) == nil && a["op"] == op {
			a["_priority"] = l[:3]
			return a
		}
	}
	f.t.Fatalf("no audit line for %s in %q", op, f.auditLines())
	return nil
}

func slicesReverse(s []string) []string {
	out := make([]string, 0, len(s))
	for i := len(s) - 1; i >= 0; i-- {
		out = append(out, s[i])
	}
	return out
}

// TestPowerPreview: the preview names the action, the target unit logind
// will start, the delay and this policy's hash; its hash is stable and
// covers the action, the delay and the policy. It requests nothing.
func TestPowerPreview(t *testing.T) {
	t.Parallel()
	l := &logind{}
	f := powerFixture(t, l, bothActions())
	p := f.powerPreview("reboot")
	if p.Action != "reboot" || p.Target != "reboot.target" || p.DelayS != 1 || p.PolicySHA256 != f.opts.ExpectedSHA256 || !sha256RE.MatchString(p.PreviewSHA256) {
		t.Fatalf("preview %+v", p)
	}
	if again := f.powerPreview("reboot"); again.PreviewSHA256 != p.PreviewSHA256 {
		t.Fatal("the preview hash is not stable")
	}
	off := f.powerPreview("poweroff")
	if off.Target != "poweroff.target" || off.PreviewSHA256 == p.PreviewSHA256 {
		t.Fatalf("poweroff preview %+v", off)
	}
	f.opts.PowerDelay = 2 * time.Second
	if d := f.powerPreview("reboot"); d.DelayS != 2 || d.PreviewSHA256 == p.PreviewSHA256 {
		t.Fatalf("a longer delay: %+v", d)
	}
	if a := f.auditOf("priv_power_preview"); a["_priority"] != "<4>" || a["outcome"] != "ok" || a["args"].(map[string]any)["action"] != "reboot" {
		t.Fatalf("audit %v", a)
	}
	if len(l.requests()) != 0 {
		t.Fatal("a preview requested an action")
	}
}

// TestPowerPreviewRefusals: whatever would block the action is refused at
// the preview, naming it, so no approval is requested; a delay inhibitor,
// or an inhibitor of something other than shutdown, does not block.
func TestPowerPreviewRefusals(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		opts   []opt
		setup  func(f *fixture, l *logind)
		action string
		code   string
		want   string
	}{
		"poweroff not listed": {nil, nil, "poweroff", "policy_denied", "poweroff"},
		"unknown action":      {nil, nil, "halt", "bad_request", ""},
		"no power section":    {[]opt{replace("power:\n  allowed: [reboot]\n  acknowledge: \"invented test policy\"\n", "")}, nil, "reboot", "policy_denied", "power"},
		"short limit":         {[]opt{replace("  max_timeout_s: 60\n", "  max_timeout_s: 59\n")}, nil, "reboot", "policy_denied", "max_timeout_s"},
		"below max_tier":      {[]opt{maxTier("operator")}, nil, "reboot", "tier_denied", ""},
		"package operation": {nil, func(f *fixture, _ *logind) {
			f.holdRecord(`{"request_id":"0b5c0000-0000-4000-8000-0000000000aa","started":"2026-09-29T12:00:00Z","until":"2026-09-29T12:15:00Z"}`)
		}, "reboot", "exec_failed", "package operation in progress"},
		"dpkg lock": {nil, func(f *fixture, _ *logind) {
			_, release := f.holdDpkgLock()
			f.t.Cleanup(release)
		}, "reboot", "exec_failed", "apt-get (pid"},
		"unfinished": {nil, func(f *fixture, _ *logind) {
			gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "status"), dpkgStatus("example-hello=half:1.0"), 0o644)
		}, "reboot", "exec_failed", "dpkg --configure -a"},
		"block inhibitor": {nil, func(_ *fixture, l *logind) {
			l.set(func(l *logind) {
				l.inhibitors = []dbustest.Inhibitor{{What: "shutdown:sleep", Who: "example-backup", Why: "nightly copy", Mode: "block", UID: 1001, PID: 4242}}
			})
		}, "reboot", "exec_failed", "example-backup"},
		"block-weak inhibitor": {nil, func(_ *fixture, l *logind) {
			l.set(func(l *logind) {
				l.inhibitors = []dbustest.Inhibitor{{What: "shutdown", Who: "example-session", Why: "unsaved work", Mode: "block-weak", UID: 1002, PID: 4343}}
			})
		}, "reboot", "exec_failed", "unsaved work"},
		"scheduled": {nil, func(_ *fixture, l *logind) { l.set(func(l *logind) { l.scheduled = "poweroff" }) }, "reboot", "exec_failed", "scheduled"},
		"preparing": {nil, func(_ *fixture, l *logind) { l.set(func(l *logind) { l.preparing = true }) }, "reboot", "exec_failed", "shutting down"},
		"no bus":    {nil, func(f *fixture, _ *logind) { f.opts.SystemBus = filepath.Join(f.d, "no-bus") }, "reboot", "exec_failed", "system bus"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := &logind{}
			f := powerFixture(t, l, c.opts...)
			if c.setup != nil {
				c.setup(f, l)
			}
			r := f.serve("priv_power_preview", m{"action": c.action})
			if r.OK || r.Error == nil || r.Error.Code != c.code || !strings.Contains(r.Error.Message, c.want) {
				t.Fatalf("got %+v, want %s naming %q", r.Error, c.code, c.want)
			}
			if len(l.requests()) != 0 {
				t.Fatal("a refused preview requested an action")
			}
		})
	}
	for name, inh := range map[string]dbustest.Inhibitor{
		"delay":      {What: "shutdown", Who: "example-updater", Why: "finishing", Mode: "delay", UID: 0, PID: 77},
		"sleep only": {What: "sleep:idle", Who: "example-player", Why: "playing", Mode: "block", UID: 1001, PID: 78},
	} {
		l := &logind{inhibitors: []dbustest.Inhibitor{inh}}
		f := powerFixture(t, l)
		if p := f.powerPreview("reboot"); !sha256RE.MatchString(p.PreviewSHA256) {
			t.Fatalf("%s inhibitor: %+v", name, p)
		}
	}
}

// TestPowerAnswersFirst: the answer (action, target, the UTC time, the
// delay and how to cancel) is written and read before anything is asked of
// logind; the action is requested once, after the delay, with
// SD_LOGIND_ROOT_CHECK_INHIBITORS and nothing else; the journal line says
// so.
func TestPowerAnswersFirst(t *testing.T) {
	t.Parallel()
	for action, member := range map[string]string{"reboot": "RebootWithFlags", "poweroff": "PowerOffWithFlags"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			l := &logind{}
			f := powerFixture(t, l, bothActions())
			p := f.powerPreview(action)
			a := f.serveAsync(pkgLine("priv_power", powerArgs(action, p.PreviewSHA256), 5000))
			r, answered := a.answer(5 * time.Second)
			if n := len(l.requests()); n != 0 {
				t.Fatalf("logind was asked %d times before the answer", n)
			}
			var d powerResult
			if !r.OK || json.Unmarshal(r.Data, &d) != nil {
				t.Fatalf("answer %+v", r)
			}
			at, err := time.Parse(time.RFC3339Nano, d.ScheduledAt)
			if err != nil || d.Action != action || d.Target != action+".target" || d.DelayS != 1 || !strings.Contains(d.Cancel, "priv_power_cancel") ||
				!strings.HasSuffix(d.ScheduledAt, "Z") || at.Before(answered.Add(500*time.Millisecond)) || at.After(answered.Add(1500*time.Millisecond)) {
				t.Fatalf("result %+v (answered at %s)", d, answered.UTC().Format(time.RFC3339Nano))
			}
			a.ended(10 * time.Second)
			reqs := l.requests()
			if len(reqs) != 1 || reqs[0].member != member || reqs[0].flags != uint64(1) {
				t.Fatalf("logind requests %+v, want one %s with flags 1", reqs, member)
			}
			if reqs[0].at.Before(answered.Add(900 * time.Millisecond)) {
				t.Fatalf("requested %v after the answer, before the delay", reqs[0].at.Sub(answered))
			}
			au := f.auditOf("priv_power")
			if au["_priority"] != "<4>" || au["outcome"] != "ok" || au["power"] != "requested" || au["answered_early"] != true || au["scheduled_at"] != d.ScheduledAt {
				t.Fatalf("audit %v", au)
			}
			if strings.Contains(strings.Join(f.auditLines(), "\n"), p.PreviewSHA256) {
				t.Fatal("the preview hash reached the journal")
			}
		})
	}
}

// TestPowerBoundToPreview: the operation requires the preview's hash, and
// anything that changed since the preview — the action, the delay, the
// policy, a new blocker — is refused before the answer, with nothing
// scheduled and nothing requested.
func TestPowerBoundToPreview(t *testing.T) {
	t.Parallel()
	l := &logind{}
	f := powerFixture(t, l, bothActions())
	p := f.powerPreview("reboot")
	f.fail("priv_power", m{"action": "reboot"}, "bad_request")
	f.fail("priv_power", powerArgs("reboot", "ABC"), "bad_request")
	f.fail("priv_power", m{"action": "reboot", "expected_preview_sha256": p.PreviewSHA256, "force": true}, "bad_request")
	// An approved reboot never becomes a power-off.
	f.fail("priv_power", powerArgs("poweroff", p.PreviewSHA256), "exists")
	// Another delay.
	f.opts.PowerDelay = 2 * time.Second
	f.fail("priv_power", powerArgs("reboot", p.PreviewSHA256), "exists")
	f.opts.PowerDelay = time.Second
	// A new blocker: refused by its own check, naming it.
	l.set(func(l *logind) {
		l.inhibitors = []dbustest.Inhibitor{{What: "shutdown", Who: "example-backup", Why: "nightly copy", Mode: "block", UID: 1001, PID: 4242}}
	})
	if r := f.serve("priv_power", powerArgs("reboot", p.PreviewSHA256)); r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "example-backup") {
		t.Fatalf("new inhibitor: %+v", r.Error)
	}
	l.set(func(l *logind) { l.inhibitors = nil })
	// Another policy.
	gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), "invented test policy", "invented test policy, edited", 1), 0o600)
	f.rehash()
	f.fail("priv_power", powerArgs("reboot", p.PreviewSHA256), "exists")
	if len(l.requests()) != 0 {
		t.Fatalf("logind requests %+v", l.requests())
	}
	// Nothing was scheduled: a preview is not refused.
	f.powerPreview("reboot")
	// And the policy must list the action itself: reboot alone never allows
	// a power-off.
	only := powerFixture(t, &logind{})
	only.fail("priv_power", powerArgs("poweroff", strings.Repeat("a", 64)), "policy_denied")
	low := powerFixture(t, &logind{}, maxTier("operator"))
	low.fail("priv_power", powerArgs("reboot", strings.Repeat("a", 64)), "tier_denied")
}

// waitQueued waits until the helper has written its answer to the gate's
// end (the gate has not read it).
func waitQueued(t *testing.T, fd int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if unreadBytes(t, fd) > 0 {
			return
		}
	}
	t.Fatal("no answer was written")
}

// TestPowerNotDelivered: if the gate does not read the answer — it never
// reads it, it closes with the answer unread (the kernel resets the
// connection), or it is gone before the answer is written — nothing is
// scheduled: logind is never asked, the record is released at once, the
// journal says not_delivered, and the next preview shows nothing
// scheduled.
func TestPowerNotDelivered(t *testing.T) {
	t.Parallel()
	for name, gate := range map[string]func(t *testing.T, fd int){
		"never read":    func(*testing.T, int) {},
		"closed unread": func(t *testing.T, fd int) { waitQueued(t, fd) },
		"gone before":   func(*testing.T, int) {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := &logind{}
			f := powerFixture(t, l)
			f.opts.PowerConfirmWait = 500 * time.Millisecond
			p := f.powerPreview("reboot")
			line := pkgLine("priv_power", powerArgs("reboot", p.PreviewSHA256), 5000)
			if name == "gone before" {
				// The request is queued, then the gate's end is closed before
				// the helper answers.
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := unix.Write(fds[1], []byte(line)); err != nil {
					t.Fatal(err)
				}
				_ = unix.Close(fds[1])
				conn := os.NewFile(uintptr(fds[0]), "conn")
				o := f.opts
				o.Conn = conn
				ops.Serve(&o)
				_ = conn.Close()
			} else {
				a := f.serveAsync(line)
				gate(t, a.gate)
				if name == "closed unread" {
					a.closeGate()
				}
				a.ended(5 * time.Second)
			}
			time.Sleep(1500 * time.Millisecond) // past the delay
			if reqs := l.requests(); len(reqs) != 0 {
				t.Fatalf("logind was asked %+v", reqs)
			}
			au := f.auditOf("priv_power")
			if au["power"] != "not_delivered" || au["outcome"] == "ok" {
				t.Fatalf("audit %v", au)
			}
			if p2 := f.powerPreview("reboot"); p2.PreviewSHA256 != p.PreviewSHA256 {
				t.Fatalf("preview after %+v", p2)
			}
		})
	}
}

// TestPowerHangupAfterAnswer (must-fix (a)'s second exception): once the
// gate has read the answer, its hang-up does not cancel the action.
func TestPowerHangupAfterAnswer(t *testing.T) {
	t.Parallel()
	l := &logind{}
	f := powerFixture(t, l)
	p := f.powerPreview("reboot")
	a := f.serveAsync(pkgLine("priv_power", powerArgs("reboot", p.PreviewSHA256), 5000))
	a.answer(5 * time.Second)
	_ = unix.Shutdown(a.gate, unix.SHUT_RDWR)
	a.ended(10 * time.Second)
	if reqs := l.requests(); len(reqs) != 1 || reqs[0].member != "RebootWithFlags" {
		t.Fatalf("logind requests %+v", reqs)
	}
	if au := f.auditOf("priv_power"); au["power"] != "requested" {
		t.Fatalf("audit %v", au)
	}
}

// TestPowerCancel: priv_power_cancel stops the action this helper
// scheduled, identified by the record; logind is never asked. While it
// waits, package operations and their previews say a reboot is
// scheduled. With nothing scheduled, or a package operation holding the
// record, there is nothing to cancel.
func TestPowerCancel(t *testing.T) {
	t.Parallel()
	l := &logind{}
	f := powerFixture(t, l)
	f.opts.PowerDelay = 3 * time.Second
	f.fail("priv_power_cancel", m{}, "not_found")
	f.fail("priv_power_cancel", m{"request_id": reqID}, "bad_request")
	p := f.powerPreview("reboot")
	a := f.serveAsync(pkgLine("priv_power", powerArgs("reboot", p.PreviewSHA256), 5000))
	r, _ := a.answer(5 * time.Second)
	var d powerResult
	if !r.OK || json.Unmarshal(r.Data, &d) != nil {
		t.Fatalf("answer %+v", r)
	}
	pr := f.serve("priv_pkg_install_preview", hello)
	if pr.OK || pr.Error.Code != "exec_failed" || !strings.Contains(pr.Error.Message, "reboot is scheduled") || !strings.Contains(pr.Error.Message, d.ScheduledAt) {
		t.Fatalf("package preview while scheduled: %+v", pr.Error)
	}
	f.fail("priv_power_preview", m{"action": "reboot"}, "exec_failed")
	var c struct {
		Cancelled   bool   `json:"cancelled"`
		RequestID   string `json:"request_id"`
		Action      string `json:"action"`
		ScheduledAt string `json:"scheduled_at"`
	}
	f.ok("priv_power_cancel", m{}, &c)
	if !c.Cancelled || c.RequestID != reqID || c.Action != "reboot" || c.ScheduledAt != d.ScheduledAt {
		t.Fatalf("cancel %+v", c)
	}
	if took := a.ended(10 * time.Second); took > 2500*time.Millisecond {
		t.Fatalf("the waiting instance ended %v after the request, not at the cancel", took)
	}
	time.Sleep(time.Second)
	if reqs := l.requests(); len(reqs) != 0 {
		t.Fatalf("logind was asked %+v", reqs)
	}
	if au := f.auditOf("priv_power"); au["power"] != "cancelled" {
		t.Fatalf("audit %v", au)
	}
	f.fail("priv_power_cancel", m{}, "not_found")
	f.powerPreview("reboot")
	// A package operation holds the record: nothing to cancel.
	release := f.holdRecord(`{"request_id":"0b5c0000-0000-4000-8000-0000000000aa","started":"2026-09-29T12:00:00Z","until":"2026-09-29T12:15:00Z"}`)
	f.fail("priv_power_cancel", m{}, "not_found")
	release()
}

// TestPowerCancelTooLate: a cancel after the waiting instance committed
// (it is asking logind) is refused as too late.
func TestPowerCancelTooLate(t *testing.T) {
	t.Parallel()
	hold := make(chan struct{})
	l := &logind{hold: hold}
	f := powerFixture(t, l)
	p := f.powerPreview("reboot")
	a := f.serveAsync(pkgLine("priv_power", powerArgs("reboot", p.PreviewSHA256), 5000))
	a.answer(5 * time.Second)
	for deadline := time.Now().Add(5 * time.Second); len(l.requests()) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("logind was never asked")
		}
	}
	if r := f.serve("priv_power_cancel", m{}); r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "too late") {
		t.Fatalf("cancel %+v", r.Error)
	}
	close(hold)
	a.ended(10 * time.Second)
	if au := f.auditOf("priv_power"); au["power"] != "requested" {
		t.Fatalf("audit %v", au)
	}
}

// TestPowerFinalChecks (the maintainer's condition 3): immediately before
// the logind call the helper checks again that it holds the record, that
// the dpkg lock is free and that dpkg left nothing unfinished; if anything
// fails, logind is never asked and the journal says why.
func TestPowerFinalChecks(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		during func(f *fixture)
		want   string
	}{
		"dpkg lock": {func(f *fixture) {
			_, release := f.holdDpkgLock()
			f.t.Cleanup(release)
		}, "apt-get (pid"},
		"unfinished": {func(f *fixture) {
			gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "status"), dpkgStatus("example-hello=half:1.0"), 0o644)
		}, "dpkg --configure -a"},
		"record replaced": {func(f *fixture) {
			if err := os.Remove(f.record); err != nil {
				f.t.Fatal(err)
			}
			gatetest.WriteFile(f.t, f.record, "", 0o600)
		}, "record"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := &logind{}
			f := powerFixture(t, l)
			f.opts.PowerDelay = 2 * time.Second
			p := f.powerPreview("reboot")
			a := f.serveAsync(pkgLine("priv_power", powerArgs("reboot", p.PreviewSHA256), 5000))
			a.answer(5 * time.Second)
			c.during(f)
			a.ended(10 * time.Second)
			if reqs := l.requests(); len(reqs) != 0 {
				t.Fatalf("logind was asked %+v", reqs)
			}
			au := f.auditOf("priv_power")
			if detail, _ := au["detail"].(string); au["power"] != "refused" || au["outcome"] == "ok" || !strings.Contains(detail, c.want) {
				t.Fatalf("audit %v, want refused naming %q", au, c.want)
			}
		})
	}
}

// TestPowerLogindRefusal: logind's refusal at the time of the request (an
// inhibitor taken during the delay) is journalled with its error name.
func TestPowerLogindRefusal(t *testing.T) {
	t.Parallel()
	l := &logind{refuse: "org.freedesktop.login1.BlockedByInhibitorLock"}
	f := powerFixture(t, l)
	p := f.powerPreview("reboot")
	a := f.serveAsync(pkgLine("priv_power", powerArgs("reboot", p.PreviewSHA256), 5000))
	a.answer(5 * time.Second)
	a.ended(10 * time.Second)
	au := f.auditOf("priv_power")
	if detail, _ := au["detail"].(string); au["power"] != "refused" || au["outcome"] == "ok" || !strings.Contains(detail, "org.freedesktop.login1.BlockedByInhibitorLock") {
		t.Fatalf("audit %v", au)
	}
	if len(l.requests()) != 1 {
		t.Fatalf("requests %+v", l.requests())
	}
}
