//go:build linux

package audit

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLine(t *testing.T) {
	r := &Record{Principal: "readonly-key", Client: "192.0.2.10:50000", Op: "read_file",
		Args: map[string]any{"path": "/srv/app/a\nb"}, Outcome: "ok", DurationMS: 12}
	line := Line(r)
	if strings.ContainsAny(line, "\n\r") {
		t.Fatalf("line breaks in %q", line)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("not JSON: %q", line)
	}
	args, _ := got["args"].(map[string]any)
	if got["principal"] != "readonly-key" || got["client"] != "192.0.2.10:50000" || got["op"] != "read_file" ||
		got["outcome"] != "ok" || got["duration_ms"] != float64(12) || args["path"] != "/srv/app/a\nb" {
		t.Fatalf("line %q", line)
	}
	// Free text is truncated to 512 characters.
	r.Args = map[string]any{"path": "/" + strings.Repeat("x", 2000)}
	r.Op = strings.Repeat("o", 2000)
	if l := Line(r); len(l) > 1400 {
		t.Fatalf("line not bounded: %d bytes", len(l))
	}
}

func TestClient(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		in   *string
		want string
	}{
		{s("192.0.2.10 50000 192.0.2.1 22"), "192.0.2.10:50000"},
		{s("2001:db8::1 50000 2001:db8::2 22"), "[2001:db8::1]:50000"},
		{s("not-an-ip 1 2 3"), "invalid"},
		{s("192.0.2.10 port 192.0.2.1 22"), "invalid"},
		{s(""), "invalid"},
		{nil, "local"},
	}
	for _, c := range cases {
		if got := Client(c.in); got != c.want {
			t.Errorf("Client(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeArgs(t *testing.T) {
	got := SanitizeArgs("write_file", []byte(`{"path":"/srv/app/config/x","content_b64":"U0VDUkVU","mode":"0640","expected_sha256":"ab"}`))
	if got["path"] != "/srv/app/config/x" || got["mode"] != "0640" || got["content_b64"] != nil {
		t.Fatalf("write_file %v", got)
	}
	got = SanitizeArgs("exec", []byte(`{"command_id":"probe","args":["--token","abc"],"stdin_b64":"cGluZw==","cwd":"/srv/app"}`))
	if got["command_id"] != "probe" || got["arg_count"] != 2 || got["args"] != nil || got["stdin_b64"] != nil || got["cwd"] != "/srv/app" {
		t.Fatalf("exec %v", got)
	}
	// Non-scalar or unknown values are dropped; strings are bounded.
	got = SanitizeArgs("read_file", []byte(`{"path":{"x":1},"weird":"v","max_bytes":10}`))
	if got["path"] != nil || got["weird"] != nil || got["max_bytes"] != float64(10) {
		t.Fatalf("read_file %v", got)
	}
	got = SanitizeArgs("stat", []byte(`{"path":"/`+strings.Repeat("y", 3000)+`"}`))
	if s, _ := got["path"].(string); len(s) > 512+3 {
		t.Fatalf("path not truncated: %d", len(s))
	}
	if got := SanitizeArgs("hello", []byte(`not json`)); len(got) != 0 {
		t.Fatalf("garbage %v", got)
	}
}

func listen(t *testing.T) (conn *net.UnixConn, path string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "log")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, p
}

func TestSyslogSink(t *testing.T) {
	c, p := listen(t)
	NewSyslog(p).Log(&Record{Principal: "p", Client: "local", Op: "hello", Args: map[string]any{}, Outcome: "ok", DurationMS: 1})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	// <authpriv.info>timestamp tag[pid]: {json}
	tag := " shell-mcp-gate[" + strconv.Itoa(os.Getpid()) + "]: {"
	if !strings.HasPrefix(msg, "<86>") || !strings.Contains(msg, tag) || !strings.HasSuffix(msg, "}\n") {
		t.Fatalf("datagram %q", msg)
	}
	// A failure is logged at notice.
	NewSyslog(p).Log(&Record{Op: "hello", Outcome: "tier_denied"})
	n, _ = c.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "<85>") {
		t.Fatalf("failure priority %q", buf[:n])
	}
}

// TestSyslogNeverBlocks: a missing socket and a socket whose queue is full
// both return promptly; the request is never held up by syslog.
func TestSyslogNeverBlocks(t *testing.T) {
	start := time.Now()
	NewSyslog(filepath.Join(t.TempDir(), "missing")).Log(&Record{Op: "hello", Outcome: "ok"})
	if d := time.Since(start); d > time.Second {
		t.Fatalf("missing socket took %v", d)
	}
	_, p := listen(t)
	// Fill the receiver's queue with a non-blocking sender until EAGAIN.
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Connect(fd, &syscall.SockaddrUnix{Name: p}); err != nil {
		t.Fatal(err)
	}
	filled := false
	for i := 0; i < 1<<16; i++ {
		if err := syscall.Sendto(fd, make([]byte, 1024), 0, nil); err != nil {
			if !errors.Is(err, syscall.EAGAIN) {
				t.Fatal(err)
			}
			filled = true
			break
		}
	}
	if !filled {
		t.Fatal("could not fill the socket queue; the test would be vacuous")
	}
	start = time.Now()
	NewSyslog(p).Log(&Record{Op: "hello", Outcome: "ok"})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("full socket blocked for %v", d)
	}
}
