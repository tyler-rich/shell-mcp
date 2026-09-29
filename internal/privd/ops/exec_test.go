//go:build linux

package ops_test

import (
	"path/filepath"
	"strings"
	"testing"
)

type execData struct {
	CommandID string   `json:"command_id"`
	Argv      []string `json:"argv"`
	ExitCode  *int     `json:"exit_code"`
	Stdout    string   `json:"stdout"`
	TimedOut  bool     `json:"timed_out"`
}

func TestExec(t *testing.T) {
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
	f := newFixture(t)
	canary := "AUDIT-CANARY-CONTENT"
	f.ok("priv_write_file", m{"path": filepath.Join(f.write, "app.conf"), "content_b64": b64(canary), "owner": "tester", "mode": "0640"}, nil)
	f.ok("priv_read_file", m{"path": filepath.Join(f.write, "app.conf")}, nil)
	f.ok("priv_delete", m{"path": filepath.Join(f.write, "app.conf")}, nil)
	lines := f.auditLines()
	if len(lines) != 3 {
		t.Fatalf("%d audit lines for 3 requests: %q", len(lines), lines)
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
