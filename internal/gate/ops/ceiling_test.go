//go:build linux

package ops_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The request's tier ceiling (ARCHITECTURE §4.1, POLICY §2): every request
// names one, and the gate refuses any op or command whose tier is above
// min(max_tier, ceiling) before doing anything else.

// callAt sends op with args under the given ceiling ("" leaves the field
// out).
func (f *fixture) callAt(ceiling, op string, args any) response {
	f.t.Helper()
	a, _ := json.Marshal(args)
	field := ""
	if ceiling != "" {
		field = fmt.Sprintf(`"ceiling":%q,`, ceiling)
	}
	resp, _ := f.serveRaw(fmt.Sprintf(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001",%s"op":%q,"args":%s,"timeout_ms":5000}`+"\n", field, op, a))
	return resp
}

// deniedAt asserts a tier_denied refusal whose message contains want.
func (f *fixture) deniedAt(ceiling, op string, args any, want string) {
	f.t.Helper()
	r := f.callAt(ceiling, op, args)
	if r.OK || r.Error == nil || r.Error.Code != "tier_denied" || !strings.Contains(r.Error.Message, want) {
		f.t.Fatalf("%s at ceiling %q = %+v %s, want tier_denied naming %q", op, ceiling, r.Error, r.Data, want)
	}
}

func absent(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("%s exists (%v): a refused request changed the host", p, err)
	}
}

// A request without a ceiling, or with an unknown one, is bad_request, and
// nothing runs: the op-level checks never see it.
func TestCeilingRequired(t *testing.T) {
	f := newFixture(t, "operator")
	marker := filepath.Join(f.write, "marker")
	write := m{"command_id": "probe-op", "args": []string{"write", marker}}
	for _, c := range []string{"", "admin", "excluded", "READ", "read-only", " read"} {
		for _, op := range []string{"hello", "exec"} {
			r := f.callAt(c, op, map[string]m{"hello": {}, "exec": write}[op])
			if r.OK || r.Error == nil || r.Error.Code != "bad_request" || !strings.Contains(r.Error.Message, "ceiling") || r.ID != "" {
				t.Fatalf("%s at ceiling %q: %+v, want bad_request naming the ceiling, without an id", op, c, r.Error)
			}
		}
	}
	for _, raw := range []string{
		`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":null,"op":"exec","args":{"command_id":"probe-op","args":["write","` + marker + `"]}}`,
		`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":3,"op":"exec","args":{"command_id":"probe-op","args":["write","` + marker + `"]}}`,
	} {
		if r, _ := f.serveRaw(raw + "\n"); r.OK || r.Error == nil || r.Error.Code != "bad_request" {
			t.Fatalf("%s: %+v", raw, r.Error)
		}
	}
	absent(t, marker)
}

// Built-in ops: the lower of max_tier and the ceiling applies, and the
// refusal names the limit that applied.
func TestCeilingBoundsOps(t *testing.T) {
	f := newFixture(t, "destructive")
	target := filepath.Join(f.write, "x")
	writeArgs := m{"path": target, "content_b64": base64.StdEncoding.EncodeToString([]byte("x"))}

	// Read ops pass under every ceiling.
	for _, c := range []string{"read", "operator", "destructive"} {
		if r := f.callAt(c, "hello", m{}); !r.OK {
			t.Fatalf("hello at ceiling %s: %+v", c, r.Error)
		}
	}
	// max_tier is destructive; the ceiling is the limit that applies.
	f.deniedAt("read", "write_file", writeArgs, "ceiling read")
	f.deniedAt("read", "mkdir", m{"path": filepath.Join(f.write, "d")}, "ceiling read")
	f.deniedAt("read", "service_control", m{}, "ceiling read")
	f.deniedAt("operator", "delete", m{"path": filepath.Join(f.write, "y")}, "ceiling operator")
	f.deniedAt("operator", "git_discard", m{}, "ceiling operator")
	// Before argument validation, as the max_tier check.
	f.deniedAt("read", "write_file", m{"bogus": true}, "ceiling read")
	absent(t, target)
	absent(t, filepath.Join(f.write, "d"))

	// Control: the same write under ceiling operator runs.
	if r := f.callAt("operator", "write_file", writeArgs); !r.OK {
		t.Fatalf("write_file at ceiling operator: %+v", r.Error)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("control write: %v", err)
	}

	// max_tier read, ceiling destructive: the policy is the limit.
	f.writePolicy("read", "")
	f.deniedAt("destructive", "write_file", writeArgs, "max_tier read")
}

// exec: the command's own tier is checked against the same minimum. Here
// max_tier is operator, so only the ceiling stops the operator command,
// and the marker it would create proves that nothing ran.
func TestCeilingBoundsExec(t *testing.T) {
	f := newFixture(t, "operator")
	marker := filepath.Join(f.write, "marker")
	args := m{"command_id": "probe-op", "args": []string{"write", marker}}
	f.deniedAt("read", "exec", args, "ceiling read")
	absent(t, marker)

	// A read command still runs under ceiling read.
	var d struct {
		Stdout string `json:"stdout"`
	}
	r := f.callAt("read", "exec", m{"command_id": "probe-echo", "args": []string{"echo", "hello"}})
	if !r.OK || json.Unmarshal(r.Data, &d) != nil || strings.TrimSpace(d.Stdout) != "hello" {
		t.Fatalf("read command at ceiling read: %+v %s", r.Error, r.Data)
	}
	// Control: under ceiling operator the same command runs and writes.
	if r := f.callAt("operator", "exec", args); !r.OK {
		t.Fatalf("operator command at ceiling operator: %+v", r.Error)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control run: %v", err)
	}
	// Ceiling destructive does not lift max_tier: the policy still applies.
	f.writePolicy("read", "")
	f.deniedAt("destructive", "exec", args, "max_tier read")
}

// priv_*: the gate checks the op's tier against min(privileged.max_tier,
// max_tier, ceiling) before it connects, and forwards the ceiling
// unchanged, so the helper applies it too (priv_exec's tier is the
// command's, known only to the helper).
func TestCeilingBoundsPriv(t *testing.T) {
	f := newFixture(t, "destructive")
	h := startHelper(t, f, echoID(""))
	f.deniedAt("read", "priv_write_file", m{"path": "/etc/example-app/x", "content_b64": "eA=="}, "ceiling read")
	f.deniedAt("operator", "priv_delete", m{"path": "/etc/example-app/x"}, "ceiling operator")
	if h.dials() != 0 {
		t.Fatalf("a request above its ceiling reached the helper (%d connections)", h.dials())
	}
	for _, c := range []struct{ ceiling, op string }{
		{"read", "priv_exec"}, {"read", "priv_stat"}, {"operator", "priv_write_file"}, {"destructive", "priv_delete"},
	} {
		if r := f.callAt(c.ceiling, c.op, m{"command_id": "probe-op", "args": []string{}}); !r.OK {
			t.Fatalf("%s at ceiling %s: %+v", c.op, c.ceiling, r.Error)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.got) != 4 {
		t.Fatalf("helper got %d requests, want 4", len(h.got))
	}
	for i, want := range []string{"read", "read", "operator", "destructive"} {
		var got struct {
			Ceiling *string `json:"ceiling"`
		}
		if err := json.Unmarshal([]byte(h.got[i]), &got); err != nil || got.Ceiling == nil || *got.Ceiling != want {
			t.Fatalf("forwarded %q: ceiling is not %q unchanged", h.got[i], want)
		}
	}
}
