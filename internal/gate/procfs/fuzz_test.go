package procfs

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The parsers read kernel- and host-provided bytes; none may panic, loop or
// return values that break their documented invariants, whatever the input.

func FuzzOSRelease(f *testing.F) {
	f.Add([]byte("NAME=\"Example\"\nID=example\nVERSION='1 (x)'\n"))
	f.Add([]byte("PRETTY_NAME=\"a \\\"b\\\" \\\\\"\n# c\n\n=x\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := ParseOSRelease(b)
		for _, v := range []string{r.Name, r.Version, r.ID, r.VersionID, r.PrettyName, r.VersionCodename} {
			if strings.ContainsAny(v, "\n\x00") || len(v) > maxOSReleaseValue {
				t.Fatalf("value %q", v)
			}
		}
	})
}

func FuzzMountinfo(f *testing.F) {
	f.Add([]byte(mountinfo))
	f.Add([]byte("1 2 3:4 / /a\\040b rw - x y z\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ms, err := ParseMountinfo(b, 64)
		if err != nil {
			return
		}
		if len(ms) > 64 {
			t.Fatalf("%d mounts", len(ms))
		}
		for _, m := range ms {
			if !strings.HasPrefix(m.MountPoint, "/") || m.FSType == "" {
				t.Fatalf("mount %+v", m)
			}
		}
		HidePID(ms)
	})
}

func FuzzPIDStat(f *testing.F) {
	f.Add([]byte("4242 (we ird) (x)) S 1 4242 4242 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 1 0 12345 1000000 300 18446744073709551615\n"))
	f.Add([]byte("1 () R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParsePIDStat(b)
		if err == nil && (s.PID < 0 || s.PPID < 0 || s.RSSPages < 0 || len(s.State) != 1) {
			t.Fatalf("stat %+v", s)
		}
		_, _ = ParseStatusUID(b)
	})
}

func FuzzProcMisc(f *testing.F) {
	f.Add([]byte("MemTotal: 1 kB\nMemAvailable: 1 kB\n"))
	f.Add([]byte("1.5 2.5\n"))
	f.Add([]byte("0.1 0.2 0.3 1/2 3\n"))
	f.Add([]byte("cpu0 1\nbtime 5\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := ParseMeminfo(b); err == nil && m.TotalBytes == 0 && !strings.Contains(string(b), "MemTotal") {
			t.Fatal("MemTotal missing but accepted")
		}
		if u, err := ParseUptime(b); err == nil && (u < 0 || u != u) {
			t.Fatalf("uptime %v", u)
		}
		if l, err := ParseLoadavg(b); err == nil && (l.Load1 < 0 || l.Running < 0 || l.Total < 0) {
			t.Fatalf("loadavg %+v", l)
		}
		if s, err := ParseStat(b); err == nil && s.CPUs < 0 {
			t.Fatalf("stat %+v", s)
		}
	})
}

func FuzzCmdline(f *testing.F) {
	f.Add([]byte("/bin/x\x00--password\x00p\x00-pz\x00https://u:p@h/\x00"), 512)
	f.Fuzz(func(t *testing.T, raw []byte, n int) {
		if n < 0 || n > 4096 {
			return
		}
		args := RedactArgs(SplitCmdline(raw))
		s, _ := Truncate(strings.Join(args, " "), n)
		if utf8.RuneCountInString(s) > n {
			t.Fatalf("%d runes > %d", utf8.RuneCountInString(s), n)
		}
	})
}
