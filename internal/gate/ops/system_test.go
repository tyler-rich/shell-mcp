//go:build linux

package ops_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// rawPolicy replaces the fixture's policy with y (same placeholders).
func (f *fixture) rawPolicy(y string) {
	f.t.Helper()
	gatetest.WriteFile(f.t, f.policyFile, strings.NewReplacer("{R}", f.read, "{W}", f.write, "{BIN}", f.bin).Replace(y), 0o644)
}

func TestSysinfo(t *testing.T) {
	f := newFixture(t, "read")
	var d struct {
		OS struct {
			ID string `json:"id"`
		} `json:"os"`
		Kernel struct {
			Sysname string `json:"sysname"`
			Release string `json:"release"`
			Machine string `json:"machine"`
		} `json:"kernel"`
		Hostname string  `json:"hostname"`
		UptimeS  float64 `json:"uptime_s"`
		BootTime string  `json:"boot_time"`
		Load     struct {
			Total int `json:"total"`
		} `json:"load"`
		Memory struct {
			TotalBytes uint64 `json:"total_bytes"`
		} `json:"memory"`
		CPU struct {
			Online int `json:"online"`
			Usable int `json:"usable"`
		} `json:"cpu"`
	}
	f.ok("sysinfo", m{}, &d)
	if d.Kernel.Sysname != "Linux" || d.Kernel.Release == "" || d.Kernel.Machine == "" || d.Hostname == "" {
		t.Fatalf("kernel %+v host %q", d.Kernel, d.Hostname)
	}
	if d.UptimeS <= 0 || d.BootTime == "" || d.Load.Total < 1 || d.Memory.TotalBytes == 0 || d.CPU.Online < 1 || d.CPU.Usable < 1 {
		t.Fatalf("sysinfo %+v", d)
	}
	if _, err := os.Stat("/etc/os-release"); err == nil && d.OS.ID == "" {
		t.Fatalf("os-release present but not reported: %+v", d.OS)
	}
	f.fail("sysinfo", m{"extra": true}, "bad_request")
}

func TestDisk(t *testing.T) {
	f := newFixture(t, "read")
	type mount struct {
		MountPoint string `json:"mount_point"`
		FSType     string `json:"fs_type"`
		Pseudo     bool   `json:"pseudo"`
		SizeBytes  uint64 `json:"size_bytes"`
		Inodes     uint64 `json:"inodes"`
	}
	var d struct {
		Mounts         []mount `json:"mounts"`
		PseudoFiltered int     `json:"pseudo_filtered"`
	}
	f.ok("disk", m{}, &d)
	root := false
	for _, mt := range d.Mounts {
		if mt.Pseudo || mt.FSType == "proc" {
			t.Fatalf("pseudo filesystem listed without include_pseudo: %+v", mt)
		}
		if mt.MountPoint == "/" {
			root = true
		}
	}
	if !root || d.PseudoFiltered == 0 {
		t.Fatalf("disk %+v", d)
	}
	f.ok("disk", m{"include_pseudo": true}, &d)
	proc := false
	for _, mt := range d.Mounts {
		if mt.MountPoint == "/proc" && mt.FSType == "proc" && mt.Pseudo {
			proc = true
		}
	}
	if !proc || d.PseudoFiltered != 0 {
		t.Fatalf("include_pseudo: %+v", d)
	}
}

type procEntry struct {
	PID      int     `json:"pid"`
	PPID     int     `json:"ppid"`
	UID      uint32  `json:"uid"`
	User     string  `json:"user"`
	State    string  `json:"state"`
	RSSBytes int64   `json:"rss_bytes"`
	CPUTimeS float64 `json:"cpu_time_s"`
	Start    string  `json:"start_time"`
	Comm     string  `json:"comm"`
	Cmdline  string  `json:"cmdline"`
}

type procData struct {
	Processes []procEntry `json:"processes"`
	Scanned   int         `json:"scanned"`
	Matched   int         `json:"matched"`
	Truncated bool        `json:"truncated"`
	HidePID   struct {
		Active bool   `json:"active"`
		Mode   string `json:"mode"`
	} `json:"hidepid"`
}

func TestProcesses(t *testing.T) {
	f := newFixture(t, "read")
	child := exec.CommandContext(t.Context(), f.probe, "sleep", "30s", "--password", "hunter2", "--token=abc123", "-p", "s3cret", //nolint:gosec // G204: test child built by this test
		"https://user:pw@host.example.test/x", strings.Repeat("a", 700))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()

	var d procData
	f.ok("processes", m{"name_contains": "probe", "sort_by": "pid", "limit": 1000}, &d)
	var me *procEntry
	for i := range d.Processes {
		if d.Processes[i].PID == child.Process.Pid {
			me = &d.Processes[i]
		}
	}
	if me == nil {
		t.Fatalf("child %d not listed: %+v", child.Process.Pid, d)
	}
	if me.PPID != os.Getpid() || me.Comm != "probe" || me.UID != uint32(os.Getuid()) || me.Start == "" || me.State == "" { //nolint:gosec // G115: test uid
		t.Fatalf("entry %+v", me)
	}
	for _, leak := range []string{"hunter2", "abc123", "s3cret", "user:pw"} {
		if strings.Contains(me.Cmdline, leak) {
			t.Fatalf("cmdline leaks %q: %q", leak, me.Cmdline)
		}
	}
	if !strings.Contains(me.Cmdline, "--password") || len([]rune(me.Cmdline)) > 512 {
		t.Fatalf("cmdline %q (%d runes)", me.Cmdline, len([]rune(me.Cmdline)))
	}
	// Sorting and limits.
	f.ok("processes", m{"sort_by": "rss", "limit": 5}, &d)
	if len(d.Processes) > 5 || d.Matched < len(d.Processes) {
		t.Fatalf("limit %+v", d)
	}
	for i := 1; i < len(d.Processes); i++ {
		if d.Processes[i-1].RSSBytes < d.Processes[i].RSSBytes {
			t.Fatalf("not sorted by rss: %+v", d.Processes)
		}
	}
	f.fail("processes", m{"limit": 1001}, "bad_request")
	f.fail("processes", m{"limit": -1}, "bad_request")
	f.fail("processes", m{"sort_by": "name"}, "bad_request")
	f.fail("processes", m{"user": strings.Repeat("u", 300)}, "bad_request")

	// limits.max_processes bounds the /proc walk itself.
	f.rawPolicy("version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\nlimits:\n  max_processes: 2\n")
	f.ok("processes", m{"sort_by": "pid"}, &d)
	if d.Scanned != 2 || !d.Truncated || len(d.Processes) > 2 {
		t.Fatalf("max_processes: %+v", d)
	}
}
