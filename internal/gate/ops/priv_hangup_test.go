//go:build linux

package ops_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The gate's side of the timeout and lost-answer fixes (handoff
// docs/handoff/S4C-PRIVILEGED.md, must-fix (a) and (b), recorded by
// S4c-2): before it gives up on a helper it tells the helper so (it shuts
// down its sending side, which the helper reads as a hang-up and kills its
// command) and waits for the helper to confirm; and an answer lost after
// the request was sent, for a request that can change the host, is a
// timeout whose outcome is unknown, never a refusal. Every value is an
// invented fixture.

// idOf is the request id of a forwarded request line.
func idOf(req string) string {
	var r struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(req), &r)
	return r.ID
}

// waitHangup blocks until the gate hangs up (EOF on the connection) or the
// bound passes, and reports whether it did.
func waitHangup(c net.Conn, bound time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(bound))
	_, err := c.Read(make([]byte, 1))
	return errors.Is(err, io.EOF)
}

// TestForwardSignalsHangupAndWaits: a helper whose command outlives the
// gate's wait (an instance that started late) gets the gate's hang-up
// before the gate's deadline, and the gate's answer comes only after the
// helper has ended the command and answered: it is the helper's.
func TestForwardSignalsHangupAndWaits(t *testing.T) {
	f := newFixture(t, "destructive")
	var mu sync.Mutex
	var hungUp, ended time.Time
	startHelper(t, f, func(req string, c net.Conn) {
		// The command runs on until the gate hangs up; stopping it takes a
		// moment (SIGTERM ignored, SIGKILL after the grace).
		if !waitHangup(c, 10*time.Second) {
			return
		}
		mu.Lock()
		hungUp = time.Now()
		mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		mu.Lock()
		ended = time.Now()
		mu.Unlock()
		_, _ = c.Write([]byte(`{"v":1,"id":"` + idOf(req) + `","ok":false,"error":{"code":"timeout","message":"the command was stopped"},"warnings":[],` +
			`"gate":{"version":"h1","principal":"shell-mcp-privd","policy_sha256":"beef","max_tier":"destructive","unit":"core","duration_ms":1}}` + "\n"))
	})
	f.opts.HelperGrace = 2 * time.Second
	start := time.Now()
	r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"operator","op":"priv_exec","args":{"command_id":"probe-sleep"},"timeout_ms":300}` + "\n")
	answered := time.Now()
	mu.Lock()
	h, e := hungUp, ended
	mu.Unlock()
	if h.IsZero() {
		t.Fatalf("the helper never saw the gate hang up; the gate answered %+v after %v", r.Error, answered.Sub(start))
	}
	if h.Sub(start) >= 2300*time.Millisecond {
		t.Fatalf("the gate hung up %v after the request, at or after its own deadline", h.Sub(start))
	}
	if answered.Before(e) {
		t.Fatalf("the gate answered (%+v) before the helper had ended the command", r.Error)
	}
	if r.OK || r.Error == nil || r.Error.Code != "timeout" || r.Error.Message != "the command was stopped" || r.Helper == nil {
		t.Fatalf("not the helper's answer: %+v helper %+v", r.Error, r.Helper)
	}
}

// TestForwardOutcomeUnknown (must-fix (b)): when no answer comes back after
// the request was sent — the helper never answers, closes without a byte,
// or answers something unreadable — a request that can change the host (an
// operator or destructive op, or priv_exec above ceiling read) is a
// timeout saying it may have run, never a refusal; a read request keeps
// its codes.
func TestForwardOutcomeUnknown(t *testing.T) {
	answers := map[string]func(string, net.Conn){
		"silent":      func(_ string, c net.Conn) { waitHangup(c, 5*time.Second); time.Sleep(3 * time.Second) },
		"closed":      func(string, net.Conn) {},
		"unreadable":  reply("nope\n"),
		"another id":  reply(`{"v":1,"id":"0b5c0000-0000-4000-8000-00000000000f","ok":true,"warnings":[]}` + "\n"),
		"no id on ok": reply(`{"v":1,"id":"","ok":true,"warnings":[]}` + "\n"),
	}
	readCodes := map[string]string{"silent": "timeout", "closed": "helper_refused", "unreadable": "helper_unavailable", "another id": "helper_unavailable", "no id on ok": "helper_unavailable"}
	for _, c := range []struct {
		op, ceiling, args string
		mayChange         bool
	}{
		{"priv_write_file", "operator", `{"path":"/etc/example-app/x","content_b64":"eA=="}`, true},
		{"priv_delete", "destructive", `{"path":"/etc/example-app/x","expected_preview_sha256":"` + strings.Repeat("a", 64) + `"}`, true},
		{"priv_exec", "operator", `{"command_id":"probe-op","args":[]}`, true},
		{"priv_exec", "read", `{"command_id":"probe-echo","args":[]}`, false},
		{"priv_stat", "destructive", `{"path":"/etc/example-app"}`, false},
	} {
		if protocol.PrivMayChange(c.op, c.ceiling) != c.mayChange {
			t.Errorf("PrivMayChange(%s, %s) = %v", c.op, c.ceiling, !c.mayChange)
		}
		for name, answer := range answers {
			t.Run(c.op+"/"+c.ceiling+"/"+name, func(t *testing.T) {
				f := newFixture(t, "destructive")
				startHelper(t, f, answer)
				f.opts.HelperGrace = 600 * time.Millisecond
				r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"` + c.ceiling + `","op":"` + c.op + `","args":` + c.args + `,"timeout_ms":300}` + "\n")
				want := readCodes[name]
				if c.mayChange {
					want = "timeout"
				}
				if r.OK || r.Error == nil || r.Error.Code != want {
					t.Fatalf("got %+v, want %s", r.Error, want)
				}
				if c.mayChange && !strings.Contains(r.Error.Message, "on the host") {
					t.Fatalf("the message does not say the operation may have run on the host: %q", r.Error.Message)
				}
			})
		}
	}
}

// TestPrivMayChangeMatchesTiers: every privileged op the gate knows is a
// may-change request exactly when its tier is above read; priv_exec, whose
// tier is its command's, exactly above ceiling read.
func TestPrivMayChangeMatchesTiers(t *testing.T) {
	for _, op := range protocol.PrivOps {
		f := newFixture(t, "read")
		f.writePolicy("read", "privileged:\n  enabled: true\n  socket: /run/shell-mcp/privd.sock\n  max_tier: read\n")
		r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"` + op + `","args":{},"timeout_ms":300}` + "\n")
		readTier := r.Error == nil || r.Error.Code != "tier_denied"
		if op == protocol.OpPrivExec {
			if protocol.PrivMayChange(op, "read") || !protocol.PrivMayChange(op, "operator") || !protocol.PrivMayChange(op, "destructive") {
				t.Errorf("PrivMayChange(priv_exec) does not follow the ceiling")
			}
			continue
		}
		for _, ceiling := range protocol.Ceilings {
			if got := protocol.PrivMayChange(op, ceiling); got == readTier {
				t.Errorf("PrivMayChange(%s, %s) = %v, but the gate's tier for it is read: %v", op, ceiling, got, readTier)
			}
		}
	}
	if !protocol.PrivMayChange("priv_some_future_op", "read") {
		t.Error("an op PrivMayChange does not know must count as one that can change the host")
	}
}
