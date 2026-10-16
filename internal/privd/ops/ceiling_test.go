//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The request's tier ceiling (ARCHITECTURE §4.1, PRIVILEGED §6): the helper
// refuses any operation or command whose tier is above min(its policy's
// max_tier, the ceiling), whatever the gate already checked.

// requestAt is request with the given ceiling ("" leaves the field out).
func requestAt(ceiling, op string, args any) string {
	a, _ := json.Marshal(args)
	field := ""
	if ceiling != "" {
		field = fmt.Sprintf(`"ceiling":%q,`, ceiling)
	}
	return fmt.Sprintf(`{"v":1,"id":%q,%s"op":%q,"args":%s,"timeout_ms":5000}`+"\n", reqID, field, op, a)
}

func (f *fixture) serveAt(ceiling, op string, args any) response {
	f.t.Helper()
	out, code := f.serveRaw(requestAt(ceiling, op, args))
	var r response
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		f.t.Fatalf("%s: response %q (exit %d) is not JSON: %v", op, out, code, err)
	}
	return r
}

// deniedAt asserts a tier_denied refusal whose message contains want.
func (f *fixture) deniedAt(ceiling, op string, args any, want string) {
	f.t.Helper()
	r := f.serveAt(ceiling, op, args)
	if r.OK || r.Error == nil || r.Error.Code != "tier_denied" || !strings.Contains(r.Error.Message, want) {
		f.t.Fatalf("%s at ceiling %q: %+v, want tier_denied naming %q", op, ceiling, r.Error, want)
	}
}

func notThere(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("%s exists (%v): a refused request changed the host", p, err)
	}
}

// A request without a ceiling, or with an unknown one, is bad_request, and
// nothing runs.
func TestCeilingRequired(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(f.write, "marker")
	for _, c := range []string{"", "admin", "excluded", "READ", "read-only"} {
		r := f.serveAt(c, "priv_exec", m{"command_id": "probe-op", "args": []string{"write", marker}})
		if r.OK || r.Error == nil || r.Error.Code != "bad_request" || !strings.Contains(r.Error.Message, "ceiling") {
			t.Fatalf("ceiling %q: %+v, want bad_request naming the ceiling", c, r.Error)
		}
		r = f.serveAt(c, "priv_stat", m{"path": f.read})
		if r.OK || r.Error == nil || r.Error.Code != "bad_request" {
			t.Fatalf("priv_stat at ceiling %q: %+v", c, r.Error)
		}
	}
	notThere(t, marker)
}

// Operations: the lower of max_tier and the ceiling applies.
func TestCeilingBoundsOps(t *testing.T) {
	f := newFixture(t)
	conf := filepath.Join(f.write, "app.conf")
	write := m{"path": conf, "content_b64": b64("changed\n")}
	for _, c := range []string{"read", "operator", "destructive"} {
		if r := f.serveAt(c, "priv_stat", m{"path": f.read}); !r.OK {
			t.Fatalf("priv_stat at ceiling %s: %+v", c, r.Error)
		}
	}
	f.deniedAt("read", "priv_write_file", write, "ceiling read")
	f.deniedAt("read", "priv_mkdir", m{"path": filepath.Join(f.write, "d")}, "ceiling read")
	f.deniedAt("operator", "priv_delete", m{"path": conf}, "ceiling operator")
	if readFile(t, conf) != "key: value\n" {
		t.Fatal("an operation above its ceiling changed the file")
	}
	notThere(t, filepath.Join(f.write, "d"))
	// Control: the same write under ceiling operator runs.
	if r := f.serveAt("operator", "priv_write_file", write); !r.OK {
		t.Fatalf("priv_write_file at ceiling operator: %+v", r.Error)
	}
	if readFile(t, conf) != "changed\n" {
		t.Fatal("control write did not land")
	}
	// The ceiling never lifts the policy's max_tier.
	g := newFixture(t, maxTier("read"))
	g.deniedAt("destructive", "priv_write_file", m{"path": filepath.Join(g.write, "app.conf"), "content_b64": b64("x")}, "max_tier read")
}

// priv_exec: the command's tier is checked against the same minimum. The
// policy allows operator, so only the ceiling stops the operator command,
// and the marker it would write proves that nothing ran.
func TestCeilingBoundsExec(t *testing.T) {
	f := newFixture(t, maxTier("operator"))
	marker := filepath.Join(f.write, "marker")
	args := m{"command_id": "probe-op", "args": []string{"write", marker}}
	f.deniedAt("read", "priv_exec", args, "ceiling read")
	notThere(t, marker)
	// A read command runs under ceiling read.
	if r := f.serveAt("read", "priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "hello"}}); !r.OK {
		t.Fatalf("read command at ceiling read: %+v", r.Error)
	}
	// Control: under ceiling operator the same command runs and writes.
	if r := f.serveAt("operator", "priv_exec", args); !r.OK {
		t.Fatalf("operator command at ceiling operator: %+v", r.Error)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control run: %v", err)
	}
	g := newFixture(t, maxTier("read"))
	g.deniedAt("destructive", "priv_exec", m{"command_id": "probe-op", "args": []string{"echo", "operator"}}, "max_tier read")
}

// TestAuditLineCarriesCeiling: the helper's audit line records the
// request's tier ceiling, for an operation that ran and for one the
// ceiling refused.
func TestAuditLineCarriesCeiling(t *testing.T) {
	f := newFixture(t)
	f.ok("priv_stat", m{"path": f.write}, nil)
	if l := f.lastAudit(); !strings.Contains(l, `"ceiling":"destructive"`) {
		t.Errorf("line lacks the request's ceiling: %q", l)
	}
	if r := f.serveAt("operator", "priv_stat", m{"path": f.write}); !r.OK {
		t.Fatalf("priv_stat at ceiling operator: %+v", r.Error)
	}
	if l := f.lastAudit(); !strings.Contains(l, `"ceiling":"operator"`) || !strings.Contains(l, `"outcome":"ok"`) {
		t.Errorf("line lacks ceiling operator: %q", l)
	}
	f.deniedAt("read", "priv_mkdir", m{"path": filepath.Join(f.write, "d")}, "ceiling read")
	if l := f.lastAudit(); !strings.Contains(l, `"ceiling":"read"`) || !strings.Contains(l, `"outcome":"tier_denied"`) {
		t.Errorf("refusal line lacks ceiling read: %q", l)
	}
}
