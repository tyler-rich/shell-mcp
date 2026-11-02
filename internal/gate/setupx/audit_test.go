//go:build linux

package setupx_test

import (
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// TestLineGolden: the install record's exact JSON, field order fixed, empty
// fields left out (handoff §3.5).
func TestLineGolden(t *testing.T) {
	for _, c := range []struct {
		r    setupx.Record
		want string
	}{
		{setupx.Record{Component: "gate", Action: "create", Object: "file", Path: "/etc/ssh/sshd_config.d/60-shell-mcp.conf",
			SHA256: strings.Repeat("ab", 32), Mode: "0644", Owner: "root:root"},
			`{"event":"install","component":"gate","action":"create","object":"file","path":"/etc/ssh/sshd_config.d/60-shell-mcp.conf",` +
				`"sha256":"` + strings.Repeat("ab", 32) + `","mode":"0644","owner":"root:root"}`},
		{setupx.Record{Component: "gate", Action: "create", Object: "key", User: "svc-shell", Fingerprint: "SHA256:invented",
			Principal: "readonly", Policy: "/etc/shell-mcp/read-only.yaml"},
			`{"event":"install","component":"gate","action":"create","object":"key","user":"svc-shell","fingerprint":"SHA256:invented",` +
				`"principal":"readonly","policy":"/etc/shell-mcp/read-only.yaml"}`},
		{setupx.Record{Component: "gate", Action: "refuse", Object: "key", Reason: "from_too_wide", Detail: "192.0.2.0/16"},
			`{"event":"install","component":"gate","action":"refuse","object":"key","reason":"from_too_wide","detail":"192.0.2.0/16"}`},
		{setupx.Record{Component: "gate", Action: "run", Object: "owner_scan", OwnerScan: "narrowed", Paths: []string{"/srv", "/var/lib"}},
			`{"event":"install","component":"gate","action":"run","object":"owner_scan","owner_scan":"narrowed","paths":["/srv","/var/lib"]}`},
		{setupx.Record{Component: "gate", Action: "create", Object: "policy", Path: "/etc/shell-mcp/operator.yaml", SHA256: strings.Repeat("cd", 32),
			Mode: "0644", Owner: "root:root", Preset: "operator"},
			`{"event":"install","component":"gate","action":"create","object":"policy","path":"/etc/shell-mcp/operator.yaml",` +
				`"sha256":"` + strings.Repeat("cd", 32) + `","mode":"0644","owner":"root:root","preset":"operator"}`},
	} {
		if got := setupx.Line(&c.r); got != c.want {
			t.Errorf("line\n%s\nwant\n%s", got, c.want)
		}
	}
	long := setupx.Line(&setupx.Record{Action: "refuse", Object: "file", Detail: strings.Repeat("x", 5000) + "\n", Paths: make([]string, 200)})
	if len(long) > 2000 || strings.Contains(long, "\n") {
		t.Fatalf("line not bounded: %d bytes", len(long))
	}
}

// TestAuditorSinks: a change goes to stderr and to syslog at authpriv
// notice, a refusal at authpriv warning, tagged; a dry run writes nothing.
func TestAuditorSinks(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "log")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var stderr bytes.Buffer
	a := &setupx.Auditor{Stderr: &stderr, Syslog: sock, Tag: "shell-mcp-gate", Component: "gate"}
	read := func() string {
		buf := make([]byte, 4096)
		_ = l.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := l.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n])
	}
	a.Log(&setupx.Record{Action: "create", Object: "file", Path: "/etc/x"})
	if m := read(); !strings.HasPrefix(m, "<85>") || !strings.Contains(m, " shell-mcp-gate[") || !strings.Contains(m, `"component":"gate"`) {
		t.Fatalf("change datagram %q", m)
	}
	a.Log(&setupx.Record{Action: "refuse", Object: "key", Reason: "from_too_wide"})
	if m := read(); !strings.HasPrefix(m, "<84>") {
		t.Fatalf("refusal datagram %q", m)
	}
	if n := strings.Count(stderr.String(), "\n"); n != 2 {
		t.Fatalf("stderr %q", stderr.String())
	}
	stderr.Reset()
	(&setupx.Auditor{Stderr: &stderr, Syslog: sock, DryRun: true}).Log(&setupx.Record{Action: "create"})
	if stderr.Len() != 0 {
		t.Fatalf("a dry run wrote %q", stderr.String())
	}
	// A missing socket never blocks or fails the run.
	(&setupx.Auditor{Stderr: &stderr, Syslog: filepath.Join(t.TempDir(), "none")}).Log(&setupx.Record{Action: "create"})
}
