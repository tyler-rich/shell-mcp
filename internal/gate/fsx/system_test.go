//go:build linux

package fsx

import (
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

func TestSystemFiles(t *testing.T) {
	for _, p := range []string{"/proc/uptime", "/etc/os-release", "/proc/self/mountinfo", "/proc/1/stat", "/proc/4194304/cmdline"} {
		if !allowedSystemFile(p) {
			t.Errorf("%s refused", p)
		}
	}
	for _, p := range []string{"/etc/shadow", "/proc/1/environ", "/proc/1/mem", "/proc/self/stat", "/proc/01/stat", "/proc/1/../1/stat",
		"/proc/1/stat/x", "/proc//stat", "/proc/12345678901/stat", "/proc/uptime/", "proc/uptime", "/proc/1/task/1/stat"} {
		if allowedSystemFile(p) {
			t.Errorf("%s allowed", p)
		}
	}
	if _, _, err := ReadSystemFile("/proc/self/environ", 10); err == nil {
		t.Fatal("environ read")
	}
	b, cut, err := ReadSystemFile("/proc/self/mountinfo", 16)
	if err != nil || len(b) != 16 || !cut {
		t.Fatalf("bounded read: %q %v %v", b, cut, err)
	}
	pids, _, err := ListPIDs(1 << 20)
	if err != nil || len(pids) == 0 {
		t.Fatalf("pids %v %v", pids, err)
	}
	if pids, trunc, _ := ListPIDs(1); len(pids) != 1 || (!trunc && len(pids) > 1) {
		t.Fatalf("limit: %v", pids)
	}
	if _, err := Statfs("/", time.Second); err != nil {
		t.Fatalf("statfs /: %v", err)
	}
	if _, err := Statfs("relative", time.Second); err == nil {
		t.Fatal("relative statfs")
	}
	_, _, err = ReadSystemFile("/proc/999999999/stat", 10)
	wantCode(t, err, protocol.CodeNotFound)
}

func FuzzSystemFile(f *testing.F) {
	f.Add("/proc/1/stat")
	f.Add("/proc/uptime")
	f.Add("/proc/1/environ")
	f.Fuzz(func(t *testing.T, p string) {
		if !allowedSystemFile(p) {
			return
		}
		if strings.Contains(p, "..") || strings.Contains(p, "//") || strings.ContainsRune(p, 0) {
			t.Fatalf("unclean path allowed: %q", p)
		}
		if !strings.HasPrefix(p, "/proc/") && p != "/etc/os-release" && p != "/usr/lib/os-release" {
			t.Fatalf("path outside the fixed set allowed: %q", p)
		}
		if strings.HasPrefix(p, "/proc/") && !strings.HasSuffix(p, "/stat") && !strings.HasSuffix(p, "/status") &&
			!strings.HasSuffix(p, "/cmdline") && !strings.HasSuffix(p, "/mountinfo") && p != "/proc/uptime" &&
			p != "/proc/loadavg" && p != "/proc/meminfo" {
			t.Fatalf("unexpected /proc file allowed: %q", p)
		}
	})
}
