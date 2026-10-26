//go:build linux

package ops_test

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The helper block and the clamped timeout on forwarded requests (handoff
// docs/handoff/S4C-PRIVILEGED.md P-1, P-7). Every path and value is an
// invented fixture.

// helperBlock answers ok for the request's id with the helper's own block.
func helperBlock(unit string) func(string, net.Conn) {
	return func(req string, c net.Conn) {
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(req), &r)
		_, _ = c.Write([]byte(`{"v":2,"id":"` + r.ID + `","ok":true,"data":{"from":"helper"},"warnings":[],` +
			`"gate":{"version":"h1","principal":"shell-mcp-privd","policy_sha256":"beef","max_tier":"operator","unit":"` + unit + `","duration_ms":1}}` + "\n"))
	}
}

// setLimits rewrites the fixture's policy with the given timeout limits.
func (f *fixture) setLimits(maxS, defaultS int) {
	f.t.Helper()
	b, err := os.ReadFile(f.policyFile)
	if err != nil {
		f.t.Fatal(err)
	}
	y := strings.Replace(string(b), "limits:\n  max_stdin_bytes: 16\n",
		"limits:\n  max_stdin_bytes: 16\n  max_timeout_s: "+strconv.Itoa(maxS)+"\n  default_timeout_s: "+strconv.Itoa(defaultS)+"\n", 1)
	if y == string(b) {
		f.t.Fatal("the fixture policy has no limits section to extend")
	}
	if err := os.WriteFile(f.policyFile, []byte(y), 0o644); err != nil { //nolint:gosec // G306: the gate's policy is world-readable by design
		f.t.Fatal(err)
	}
}

// TestForwardHelperBlock: the helper's own block reaches the server as
// `helper`, beside the gate's own `gate` block, on success and on a helper
// error; a response the gate answers itself has none.
func TestForwardHelperBlock(t *testing.T) {
	for _, unit := range []string{"core", "broad"} {
		t.Run(unit, func(t *testing.T) {
			f := newFixture(t, "destructive")
			startHelper(t, f, helperBlock(unit))
			r := f.call("priv_stat", m{"path": "/etc/example-app"})
			if !r.OK || r.Gate == nil || r.Gate.Principal != "readonly-key" || r.Gate.Version != "test" {
				t.Fatalf("gate block %+v (error %+v)", r.Gate, r.Error)
			}
			h := r.Helper
			if h == nil || h.Principal != "shell-mcp-privd" || h.Version != "h1" || h.PolicySHA256 != "beef" || h.MaxTier != "operator" || h.Unit != unit {
				t.Fatalf("helper block %+v", h)
			}
		})
	}
	t.Run("helper error", func(t *testing.T) {
		f := newFixture(t, "destructive")
		startHelper(t, f, func(req string, c net.Conn) {
			var r struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(req), &r)
			_, _ = c.Write([]byte(`{"v":2,"id":"` + r.ID + `","ok":false,"error":{"code":"path_denied","message":"m"},"warnings":[],` +
				`"gate":{"version":"h1","principal":"shell-mcp-privd","policy_sha256":"beef","max_tier":"operator","unit":"core","duration_ms":1}}` + "\n"))
		})
		r := f.call("priv_stat", m{"path": "/etc/example-app"})
		if r.OK || r.Error == nil || r.Error.Code != "path_denied" || r.Helper == nil || r.Helper.PolicySHA256 != "beef" {
			t.Fatalf("error %+v helper %+v", r.Error, r.Helper)
		}
	})
	t.Run("gate's own answer", func(t *testing.T) {
		f := newFixture(t, "destructive")
		startHelper(t, f, helperBlock("core"))
		if r := f.call("stat", m{"path": f.read}); !r.OK || r.Helper != nil {
			t.Fatalf("a gate op carries a helper block: %+v", r.Helper)
		}
		// Refused at the gate: nothing was forwarded.
		f.writePolicy("destructive", "privileged:\n  enabled: false\n  socket: /run/shell-mcp/privd.sock\n")
		if r := f.call("priv_stat", m{"path": "/etc/example-app"}); r.OK || r.Helper != nil {
			t.Fatalf("a refusal at the gate carries a helper block: %+v", r.Helper)
		}
	})
}

// TestForwardClampsTimeout: the gate forwards the timeout it waits for —
// timeout_ms clamped to its max_timeout_s, or its default_timeout_s when
// the request has none — and everything else exactly as received.
func TestForwardClampsTimeout(t *testing.T) {
	const args = `{"path":"/etc/example-app"}`
	for name, c := range map[string]struct {
		field string
		want  int64
	}{
		"above the limit": {`,"timeout_ms":900000`, 2000},
		"within it":       {`,"timeout_ms":1500`, 1500},
		"none":            {``, 1000},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "destructive")
			h := startHelper(t, f, helperBlock("core"))
			f.setLimits(2, 1)
			if r, _ := f.serveRaw(`{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"operator","op":"priv_stat","args":` + args + c.field + `}` + "\n"); !r.OK {
				t.Fatalf("%+v", r.Error)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			var got struct {
				V         int             `json:"v"`
				ID        string          `json:"id"`
				Ceiling   string          `json:"ceiling"`
				Op        string          `json:"op"`
				Args      json.RawMessage `json:"args"`
				TimeoutMS int64           `json:"timeout_ms"`
			}
			if len(h.got) != 1 || json.Unmarshal([]byte(h.got[0]), &got) != nil {
				t.Fatalf("forwarded %q", h.got)
			}
			if got.TimeoutMS != c.want {
				t.Fatalf("forwarded timeout_ms %d, want %d", got.TimeoutMS, c.want)
			}
			if got.V != 2 || got.ID != "0b5c0000-0000-4000-8000-000000000001" || got.Ceiling != "operator" || got.Op != "priv_stat" || string(got.Args) != args {
				t.Fatalf("forwarded request changed beyond timeout_ms: %q", h.got[0])
			}
		})
	}
}

// TestForwardAnswerAfterHelperRun: a request whose timeout is above the
// gate's limit. The fake helper runs its "command" for the timeout it was
// forwarded, as the real helper does before it kills the command, and only
// then answers (timed_out). The gate's answer must come after that run has
// ended, and be the helper's; it must never be the gate's own timeout while
// the helper is still running.
func TestForwardAnswerAfterHelperRun(t *testing.T) {
	f := newFixture(t, "destructive")
	var mu sync.Mutex
	var ended time.Time
	startHelper(t, f, func(req string, c net.Conn) {
		var r struct {
			ID        string `json:"id"`
			TimeoutMS int64  `json:"timeout_ms"`
		}
		_ = json.Unmarshal([]byte(req), &r)
		// Bounded, so the test ends either way.
		time.Sleep(min(time.Duration(r.TimeoutMS)*time.Millisecond, 6*time.Second))
		mu.Lock()
		ended = time.Now()
		mu.Unlock()
		_, _ = c.Write([]byte(`{"v":2,"id":"` + r.ID + `","ok":true,"data":{"timed_out":true},"warnings":[],` +
			`"gate":{"version":"h1","principal":"shell-mcp-privd","policy_sha256":"beef","max_tier":"destructive","unit":"core","duration_ms":1}}` + "\n"))
	})
	f.setLimits(1, 1)
	f.opts.HelperGrace = 2 * time.Second
	r, _ := f.serveRaw(`{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"priv_exec","args":{"command_id":"probe-sleep"},"timeout_ms":30000}` + "\n")
	answered := time.Now()
	mu.Lock()
	e := ended
	mu.Unlock()
	if e.IsZero() || answered.Before(e) {
		t.Fatalf("the gate answered (%+v) while the helper was still running", r.Error)
	}
	if !r.OK || string(r.Data) != `{"timed_out":true}` {
		t.Fatalf("not the helper's answer: %+v %s", r.Error, r.Data)
	}
}
