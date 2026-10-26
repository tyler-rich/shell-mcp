//go:build linux

package ops_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type execData struct {
	CommandID string   `json:"command_id"`
	Argv      []string `json:"argv"`
	ExitCode  *int     `json:"exit_code"`
	Stdout    string   `json:"stdout"`
	TimedOut  bool     `json:"timed_out"`
}

func TestExec(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var d execData
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "canary"}}, &d)
	if d.CommandID != "probe-echo" || d.ExitCode == nil || *d.ExitCode != 0 || d.Stdout != "canary\n" || d.Argv[0] != f.probe {
		t.Fatalf("exec %+v", d)
	}
	// {path:write} resolves against the privileged write roots.
	out := filepath.Join(f.write, "probe-out")
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"write", out, "written"}}, &d)
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"write", filepath.Join(f.read, "x"), "written"}}, "path_denied")
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "-rf"}}, "template_mismatch")
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "UPPER"}}, "template_mismatch")
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"env"}}, "template_mismatch")
	f.fail("priv_exec", m{"command_id": "no-such-command", "args": []string{}}, "policy_denied")
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "x"}, "stdin_b64": "eA=="}, "bad_request")
	// The audit line has the command id and the argument count, never the
	// arguments or the output.
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "secretcanary"}}, &d)
	l := f.lastAudit()
	if !strings.Contains(l, `"command_id":"probe-echo"`) || !strings.Contains(l, `"arg_count":2`) || strings.Contains(l, "secretcanary") {
		t.Fatalf("audit %q", l)
	}
}

// TestAuditNeverContent: across every write-class op, no audit line holds
// file content, base64 content or command arguments.
func TestAuditNeverContent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	canary := "AUDIT-CANARY-CONTENT"
	f.ok("priv_write_file", m{"path": filepath.Join(f.write, "app.conf"), "content_b64": b64(canary), "owner": "tester", "mode": "0640"}, nil)
	f.ok("priv_read_file", m{"path": filepath.Join(f.write, "app.conf")}, nil)
	f.deleteBound(filepath.Join(f.write, "app.conf"), false)
	lines := f.auditLines()
	if len(lines) != 4 {
		t.Fatalf("%d audit lines for 4 requests: %q", len(lines), lines)
	}
	for _, l := range lines {
		if strings.Contains(l, canary) || strings.Contains(l, b64(canary)) {
			t.Fatalf("audit leaks content: %q", l)
		}
	}
	if !strings.Contains(lines[0], `"owner":"tester"`) || !strings.Contains(lines[0], `"mode":"0640"`) ||
		!strings.Contains(lines[0], `"path":"`+filepath.Join(f.write, "app.conf")+`"`) {
		t.Fatalf("write audit lacks path, owner or mode: %q", lines[0])
	}
}

// TestExecBoundedByOwnTimeout: whatever timeout_ms a request carries, the
// helper runs a command for at most its own max_timeout_s, then SIGTERM and,
// for a command that ignores it, SIGKILL after the kill grace; it answers
// only once the command has ended (timed_out). The gate forwards the
// timeout it waits for (handoff P-7); this is the helper's own bound behind
// it. Not parallel: it bounds the run's wall-clock time.
func TestExecBoundedByOwnTimeout(t *testing.T) {
	f := newFixture(t,
		replace("  default_timeout_s: 5\n  max_timeout_s: 10\n", "  default_timeout_s: 1\n  max_timeout_s: 1\n"),
		func(f *fixture, s *string) {
			*s = strings.Replace(*s, "  - id: probe-op\n", "  - id: probe-sleep\n    path: "+f.probe+"\n    tier: read\n    templates: [[\"ignore-term\", \"30s\"]]\n  - id: probe-op\n", 1)
		})
	start := time.Now()
	out, _ := f.serveRaw(`{"v":2,"id":"` + reqID + `","ceiling":"read","op":"priv_exec","args":{"command_id":"probe-sleep","args":["ignore-term","30s"]},"timeout_ms":600000}` + "\n")
	took := time.Since(start)
	var r struct {
		OK   bool `json:"ok"`
		Data struct {
			TimedOut bool    `json:"timed_out"`
			Signal   *string `json:"signal"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || !r.OK || !r.Data.TimedOut || r.Data.Signal == nil || *r.Data.Signal != "SIGKILL" {
		t.Fatalf("answer %q", out)
	}
	if took > 8*time.Second {
		t.Fatalf("the helper ran %v under max_timeout_s 1", took)
	}
}
