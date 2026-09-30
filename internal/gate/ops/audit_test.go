//go:build linux

package ops_test

import (
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/audit"
)

// auditTo points the fixture's audit sink at a fake syslog socket and
// returns a function that reads the next line.
func (f *fixture) auditTo(t *testing.T) func() string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "log")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	f.opts.Audit = audit.NewSyslog(p)
	conn := "192.0.2.10 50000 192.0.2.1 22"
	f.opts.SSHConnection = &conn
	return func() string {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64<<10)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("no audit line: %v", err)
		}
		return string(buf[:n])
	}
}

// TestAuditLines: one line per request with principal, client, op,
// sanitized args, outcome and duration — and never content, stdin, output
// or command arguments.
func TestAuditLines(t *testing.T) {
	f := newFixture(t, "operator")
	next := f.auditTo(t)

	content := "AUDIT-CANARY-CONTENT"
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	f.ok("write_file", m{"path": filepath.Join(f.write, "a.txt"), "content_b64": b64}, nil)
	line := next()
	for _, want := range []string{`"principal":"readonly-key"`, `"client":"192.0.2.10:50000"`, `"op":"write_file"`,
		`"outcome":"ok"`, `"duration_ms":`, filepath.Join(f.write, "a.txt")} {
		if !strings.Contains(line, want) {
			t.Errorf("line lacks %s: %q", want, line)
		}
	}
	f.ok("read_file", m{"path": filepath.Join(f.write, "a.txt")}, nil)
	stdin := base64.StdEncoding.EncodeToString([]byte("STDIN-CANARY")) // within the fixture's 16-byte stdin limit
	f.ok("exec", m{"command_id": "probe-io", "args": []string{"stdin"}, "stdin_b64": stdin}, nil)
	f.ok("exec", m{"command_id": "probe-echo", "args": []string{"echo", "ARG-CANARY"}}, nil)
	f.fail("write_file", m{"path": filepath.Join(f.read, "x"), "content_b64": b64}, "path_denied")
	lines := []string{line, next(), next(), next(), next()}
	for i, l := range lines {
		for _, leak := range []string{content, b64, "ARG-CANARY", "STDIN-CANARY", stdin} {
			if strings.Contains(l, leak) {
				t.Errorf("line %d leaks %q: %q", i, leak, l)
			}
		}
	}
	if !strings.Contains(lines[3], `"command_id":"probe-echo"`) || !strings.Contains(lines[3], `"arg_count":2`) {
		t.Errorf("exec line %q", lines[3])
	}
	if !strings.Contains(lines[4], `"outcome":"path_denied"`) {
		t.Errorf("failure line %q", lines[4])
	}
	// Refusals before the request is read are audited too.
	f.opts.Identity.UID = 0
	f.fail("hello", m{}, "install_insecure")
	if l := next(); !strings.Contains(l, `"outcome":"install_insecure"`) || !strings.Contains(l, `"op":""`) {
		t.Errorf("install failure line %q", l)
	}
}

// TestAuditLineCarriesRequestID: the gate's audit line carries the request
// id (a validated UUID v4), which is how it joins the privileged helper's
// line for the same forwarded request (PRIVILEGED §8). A request refused
// before its id is known logs an empty id.
func TestAuditLineCarriesRequestID(t *testing.T) {
	f := newFixture(t, "operator")
	next := f.auditTo(t)
	f.ok("hello", m{}, nil)
	if l := next(); !strings.Contains(l, `"id":"0b5c0000-0000-4000-8000-000000000001"`) {
		t.Errorf("line lacks the request id: %q", l)
	}
	f.opts.Identity.UID = 0
	f.fail("hello", m{}, "install_insecure")
	if l := next(); !strings.Contains(l, `"id":""`) {
		t.Errorf("refusal line lacks an empty id: %q", l)
	}
}
