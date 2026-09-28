package procfs

import (
	"slices"
	"strings"
	"testing"
)

// All inputs below are invented and only mimic the kernel's formats
// (proc(5), os-release(5)).

func TestParseOSRelease(t *testing.T) {
	in := `# comment
PRETTY_NAME="Example Linux 13 (codename)"
NAME="Example Linux"
VERSION_ID="13"
VERSION='13 (codename)'
VERSION_CODENAME=codename
ID=example
ESCAPED="a \"quoted\" \$value \\ end"
BROKEN LINE
=novalue
LOWER=x
`
	r := ParseOSRelease([]byte(in))
	want := OSRelease{Name: "Example Linux", Version: "13 (codename)", ID: "example", VersionID: "13",
		PrettyName: "Example Linux 13 (codename)", VersionCodename: "codename"}
	if r != want {
		t.Fatalf("got %+v", r)
	}
	if v, ok := unquoteOSRelease(`"a \"quoted\" \$value \\ end"`); !ok || v != `a "quoted" $value \ end` {
		t.Fatalf("unquote %q %v", v, ok)
	}
	for _, bad := range []string{`"unterminated`, `'x`, `"a"b`, "a b"} {
		if _, ok := unquoteOSRelease(bad); ok {
			t.Fatalf("unquote accepted %q", bad)
		}
	}
	if r := ParseOSRelease([]byte("NAME=\"x\nID=y\n")); r.ID != "y" || r.Name != "" {
		t.Fatalf("a malformed value must be skipped, not merged: %+v", r)
	}
}

func TestParseMeminfoUptimeLoadavgStat(t *testing.T) {
	m, err := ParseMeminfo([]byte("MemTotal:        2048 kB\nMemFree:  1024 kB\nMemAvailable: 1536 kB\nBuffers: 1 kB\nCached: 2 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\nHugePages_Total: 0\n"))
	if err != nil || m.TotalBytes != 2048*1024 || m.AvailableBytes != 1536*1024 || m.CachedBytes != 2048 {
		t.Fatalf("meminfo %+v %v", m, err)
	}
	if _, err := ParseMeminfo([]byte("MemFree: 1 kB\n")); err == nil {
		t.Fatal("meminfo without MemTotal accepted")
	}
	if _, err := ParseMeminfo([]byte("MemTotal: x kB\n")); err == nil {
		t.Fatal("non-numeric meminfo accepted")
	}
	up, err := ParseUptime([]byte("12345.67 54321.00\n"))
	if err != nil || up != 12345.67 {
		t.Fatalf("uptime %v %v", up, err)
	}
	for _, bad := range []string{"", "x 1", "-1 2", "NaN 1", "+Inf 1"} {
		if _, err := ParseUptime([]byte(bad)); err == nil {
			t.Fatalf("uptime accepted %q", bad)
		}
	}
	la, err := ParseLoadavg([]byte("0.50 0.25 0.10 2/345 6789\n"))
	if err != nil || la.Load1 != 0.5 || la.Load15 != 0.1 || la.Running != 2 || la.Total != 345 {
		t.Fatalf("loadavg %+v %v", la, err)
	}
	if _, err := ParseLoadavg([]byte("0.5 0.2\n")); err == nil {
		t.Fatal("short loadavg accepted")
	}
	st, err := ParseStat([]byte("cpu  1 2 3\ncpu0 1 2 3\ncpu1 1 2 3\nintr 1\nbtime 1700000000\nprocesses 5\n"))
	if err != nil || st.BootTime != 1700000000 || st.CPUs != 2 {
		t.Fatalf("stat %+v %v", st, err)
	}
	if _, err := ParseStat([]byte("cpu0 1\n")); err == nil {
		t.Fatal("stat without btime accepted")
	}
}

const mountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw,hidepid=invisible
24 22 0:22 / /sys rw,nosuid shared:2 - sysfs sysfs rw
25 22 0:23 / /mnt/with\040space ro,relatime - xfs /dev/sdb1 ro
26 22 0:24 / /run rw - tmpfs tmpfs rw,size=1024k
`

func TestParseMountinfo(t *testing.T) {
	ms, err := ParseMountinfo([]byte(mountinfo), 100)
	if err != nil || len(ms) != 5 {
		t.Fatalf("mountinfo %+v %v", ms, err)
	}
	if ms[0].MountPoint != "/" || ms[0].FSType != "ext4" || ms[0].Source != "/dev/sda1" || ms[0].ReadOnly() {
		t.Fatalf("root mount %+v", ms[0])
	}
	if ms[3].MountPoint != "/mnt/with space" || !ms[3].ReadOnly() || ms[3].FSType != "xfs" {
		t.Fatalf("escaped mount point %+v", ms[3])
	}
	if !IsPseudoFS("proc") || !IsPseudoFS("tmpfs") || IsPseudoFS("ext4") || IsPseudoFS("xfs") {
		t.Fatal("pseudo classification")
	}
	if on, mode := HidePID(ms); !on || mode != "invisible" {
		t.Fatalf("hidepid %v %q", on, mode)
	}
	plain, _ := ParseMountinfo([]byte(strings.Replace(mountinfo, ",hidepid=invisible", "", 1)), 100)
	if on, _ := HidePID(plain); on {
		t.Fatal("hidepid reported without the option")
	}
	zero, _ := ParseMountinfo([]byte(strings.Replace(mountinfo, "hidepid=invisible", "hidepid=0", 1)), 100)
	if on, _ := HidePID(zero); on {
		t.Fatal("hidepid=0 is not hiding")
	}
	if _, err := ParseMountinfo([]byte(mountinfo), 3); err == nil {
		t.Fatal("mount limit not enforced")
	}
	for _, bad := range []string{"22 1 8:1 / / rw shared:1 ext4 /dev/sda1 rw\n", "x 1 8:1 / / rw - ext4 a b\n", "22 1 8:1 / relative rw - ext4 a b\n"} {
		if _, err := ParseMountinfo([]byte(bad), 10); err == nil {
			t.Fatalf("malformed mountinfo accepted: %q", bad)
		}
	}
}

func TestParsePIDStat(t *testing.T) {
	// comm may contain spaces and parentheses; the last ')' ends it.
	line := "4242 (we ird) (x)) S 1 4242 4242 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 1 0 12345 1000000 300 18446744073709551615\n"
	s, err := ParsePIDStat([]byte(line))
	if err != nil || s.PID != 4242 || s.Comm != "we ird) (x)" || s.State != "S" || s.PPID != 1 || s.UTime != 150 || s.STime != 50 ||
		s.StartTime != 12345 || s.RSSPages != 300 {
		t.Fatalf("stat %+v %v", s, err)
	}
	for _, bad := range []string{"", "1 (x S 1", "1 (x) S", "a (x) S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1"} {
		if _, err := ParsePIDStat([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	uid, err := ParseStatusUID([]byte("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1\n"))
	if err != nil || uid != 1000 {
		t.Fatalf("uid %d %v", uid, err)
	}
	if _, err := ParseStatusUID([]byte("Name:\tx\n")); err == nil {
		t.Fatal("status without Uid accepted")
	}
}

func TestCmdline(t *testing.T) {
	raw := []byte("/usr/bin/example\x00--password\x00hunter2\x00--token=abc123\x00-p\x00s3cret\x00-pX9\x00--port\x0022\x00--api-key\x00k1\x00https://user:pw@host.example.test/x\x00--Secret-File=/run/x\x00plain\x00")
	args := SplitCmdline(raw)
	got := strings.Join(RedactArgs(args), " ")
	for _, leak := range []string{"hunter2", "abc123", "s3cret", "X9", "k1", "user:pw", "/run/x"} {
		if strings.Contains(got, leak) {
			t.Fatalf("leaked %q in %q", leak, got)
		}
	}
	for _, keep := range []string{"/usr/bin/example", "--password", "--token=", "--port 22", "plain", "host.example.test"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("lost %q in %q", keep, got)
		}
	}
	// A flag followed by another flag has no value to redact.
	if got := RedactArgs([]string{"x", "--password", "--verbose"}); !slices.Equal(got, []string{"x", "--password", "--verbose"}) {
		t.Fatalf("got %q", got)
	}
	if got := SplitCmdline([]byte("a\x00\x00b")); !slices.Equal(got, []string{"a", "", "b"}) {
		t.Fatalf("split %q", got)
	}
	s, cut := Truncate(strings.Repeat("é", 600), 512)
	if !cut || len([]rune(s)) != 512 {
		t.Fatalf("truncate: %d runes, cut=%v", len([]rune(s)), cut)
	}
	if s, cut := Truncate("short", 512); cut || s != "short" {
		t.Fatal("short string changed")
	}
}
