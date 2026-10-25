// Package procfs parses the host files the gate's native system operations
// read (docs/ARCHITECTURE.md §4.3): os-release(5) and the proc(5) files
// /proc/uptime, /proc/loadavg, /proc/meminfo, /proc/stat,
// /proc/self/mountinfo and /proc/<pid>/{stat,status,cmdline}. It only
// parses bytes; reading them is fsx's job. Every parser is bounded, never
// panics, and is fuzzed.
package procfs

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Bounds.
const (
	maxOSReleaseValue = 256
	maxLines          = 1 << 16
)

var errFormat = errors.New("unexpected format")

func formatErr(what string) error { return fmt.Errorf("%s: %w", what, errFormat) }

// lines splits b into at most maxLines lines without their terminators.
func lines(b []byte) []string {
	out := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(out) > maxLines {
		out = out[:maxLines]
	}
	return out
}

// OSRelease holds the os-release fields the gate reports.
type OSRelease struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ID              string `json:"id"`
	VersionID       string `json:"version_id"`
	PrettyName      string `json:"pretty_name"`
	VersionCodename string `json:"version_codename"`
}

// ParseOSRelease parses os-release(5): newline-separated KEY=VALUE lines,
// values optionally in single or double quotes with shell-style backslash
// escapes inside double quotes. Comments, blank lines, malformed lines and
// unknown keys are ignored, as the format requires. Values are bounded.
func ParseOSRelease(b []byte) OSRelease {
	var r OSRelease
	for _, line := range lines(b) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, raw, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			continue
		}
		v, ok := unquoteOSRelease(raw)
		if !ok || len(v) > maxOSReleaseValue || strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			continue
		}
		switch k {
		case "NAME":
			r.Name = v
		case "VERSION":
			r.Version = v
		case "ID":
			r.ID = v
		case "VERSION_ID":
			r.VersionID = v
		case "PRETTY_NAME":
			r.PrettyName = v
		case "VERSION_CODENAME":
			r.VersionCodename = v
		}
	}
	return r
}

// unquoteOSRelease decodes one value: bare (no whitespace or quotes),
// 'single quoted' (literal), or "double quoted" with \" \\ \$ \` escapes.
func unquoteOSRelease(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	switch s[0] {
	case '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' || strings.ContainsRune(s[1:len(s)-1], '\'') {
			return "", false
		}
		return s[1 : len(s)-1], true
	case '"':
		var sb strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			switch c {
			case '\\':
				if i+1 >= len(s) {
					return "", false
				}
				i++
				switch n := s[i]; n {
				case '"', '\\', '$', '`':
					sb.WriteByte(n)
				default:
					sb.WriteByte('\\')
					sb.WriteByte(n)
				}
			case '"':
				if i != len(s)-1 {
					return "", false
				}
				return sb.String(), true
			default:
				sb.WriteByte(c)
			}
		}
		return "", false
	}
	if strings.ContainsAny(s, " \t\"'\\$`") {
		return "", false
	}
	return s, true
}

// Meminfo is the subset of /proc/meminfo the gate reports, in bytes.
type Meminfo struct {
	TotalBytes     uint64 `json:"total_bytes"`
	FreeBytes      uint64 `json:"free_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	BuffersBytes   uint64 `json:"buffers_bytes"`
	CachedBytes    uint64 `json:"cached_bytes"`
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	SwapFreeBytes  uint64 `json:"swap_free_bytes"`
}

// ParseMeminfo parses /proc/meminfo ("Key:   <n> kB" lines). MemTotal is
// required; the fields it reports must be numeric with a kB unit.
func ParseMeminfo(b []byte) (Meminfo, error) {
	var m Meminfo
	dst := map[string]*uint64{
		"MemTotal": &m.TotalBytes, "MemFree": &m.FreeBytes, "MemAvailable": &m.AvailableBytes,
		"Buffers": &m.BuffersBytes, "Cached": &m.CachedBytes, "SwapTotal": &m.SwapTotalBytes, "SwapFree": &m.SwapFreeBytes,
	}
	total := false
	for _, line := range lines(b) {
		k, v, ok := strings.Cut(line, ":")
		p, want := dst[k]
		if !ok || !want {
			continue
		}
		f := strings.Fields(v)
		if len(f) != 2 || f[1] != "kB" {
			return Meminfo{}, formatErr("meminfo " + k)
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil || n > math.MaxUint64/1024 {
			return Meminfo{}, formatErr("meminfo " + k)
		}
		*p = n * 1024
		if k == "MemTotal" {
			total = true
		}
	}
	if !total {
		return Meminfo{}, formatErr("meminfo has no MemTotal")
	}
	return m, nil
}

// nonNegFloat parses a finite, non-negative decimal.
func nonNegFloat(s string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false
	}
	return v, true
}

// ParseUptime parses /proc/uptime ("<uptime> <idle>") and returns the
// uptime in seconds.
func ParseUptime(b []byte) (float64, error) {
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, formatErr("uptime")
	}
	v, ok := nonNegFloat(f[0])
	if !ok {
		return 0, formatErr("uptime")
	}
	return v, nil
}

// Loadavg is /proc/loadavg.
type Loadavg struct {
	Load1   float64 `json:"load_1m"`
	Load5   float64 `json:"load_5m"`
	Load15  float64 `json:"load_15m"`
	Running int     `json:"running"`
	Total   int     `json:"total"`
}

// ParseLoadavg parses /proc/loadavg ("l1 l5 l15 running/total lastpid").
func ParseLoadavg(b []byte) (Loadavg, error) {
	f := strings.Fields(string(b))
	if len(f) != 5 {
		return Loadavg{}, formatErr("loadavg")
	}
	var l Loadavg
	var ok bool
	for i, dst := range []*float64{&l.Load1, &l.Load5, &l.Load15} {
		if *dst, ok = nonNegFloat(f[i]); !ok {
			return Loadavg{}, formatErr("loadavg")
		}
	}
	r, t, found := strings.Cut(f[3], "/")
	var err1, err2 error
	l.Running, err1 = strconv.Atoi(r)
	l.Total, err2 = strconv.Atoi(t)
	if !found || err1 != nil || err2 != nil || l.Running < 0 || l.Total < 0 {
		return Loadavg{}, formatErr("loadavg")
	}
	return l, nil
}

// Stat is the subset of /proc/stat the gate needs.
type Stat struct {
	BootTime int64 // seconds since the epoch
	CPUs     int   // online CPUs (cpuN lines)
}

// ParseStat parses /proc/stat. btime is required.
func ParseStat(b []byte) (Stat, error) {
	var s Stat
	boot := false
	for _, line := range lines(b) {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "btime":
			if len(f) != 2 {
				return Stat{}, formatErr("stat btime")
			}
			v, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil || v < 0 {
				return Stat{}, formatErr("stat btime")
			}
			s.BootTime, boot = v, true
		case strings.HasPrefix(f[0], "cpu") && len(f[0]) > 3:
			if _, err := strconv.Atoi(f[0][3:]); err == nil {
				s.CPUs++
			}
		}
	}
	if !boot {
		return Stat{}, formatErr("stat has no btime")
	}
	return s, nil
}

// Mount is one line of /proc/self/mountinfo (proc(5)).
type Mount struct {
	MountPoint   string
	Options      string // per-mount options
	FSType       string
	Source       string
	SuperOptions string
}

// ReadOnly reports whether the mount is read-only.
func (m *Mount) ReadOnly() bool {
	for _, o := range strings.Split(m.Options, ",") {
		if o == "ro" {
			return true
		}
	}
	return false
}

// unescapeMount decodes the octal escapes (\040 space, \011 tab, \012
// newline, \134 backslash) the kernel uses in mountinfo fields.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// ParseMountinfo parses /proc/self/mountinfo:
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//
// Fields: mount id, parent id, major:minor, root, mount point, mount
// options, zero or more optional fields, "-", fs type, source, super
// options. More than limit mounts is an error.
func ParseMountinfo(b []byte, limit int) ([]Mount, error) {
	var out []Mount
	for _, line := range lines(b) {
		if line == "" {
			continue
		}
		if len(out) == limit {
			return nil, fmt.Errorf("more than %d mounts: %w", limit, errFormat)
		}
		f := strings.Fields(line)
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 10 || sep < 0 || len(f) != sep+4 {
			return nil, formatErr("mountinfo line")
		}
		for _, n := range f[:2] {
			if _, err := strconv.ParseUint(n, 10, 32); err != nil {
				return nil, formatErr("mountinfo id")
			}
		}
		mp := unescapeMount(f[4])
		if !strings.HasPrefix(mp, "/") || f[sep+1] == "" {
			return nil, formatErr("mountinfo mount point")
		}
		out = append(out, Mount{
			MountPoint: mp, Options: f[5], FSType: f[sep+1],
			Source: unescapeMount(f[sep+2]), SuperOptions: f[sep+3],
		})
	}
	return out, nil
}

// pseudoFS are filesystems with no backing storage (or read-only images
// such as snaps) that the disk op filters unless asked; df-like output.
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "ramfs": true,
	"cgroup": true, "cgroup2": true, "mqueue": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "pstore": true, "bpf": true, "configfs": true, "fusectl": true,
	"hugetlbfs": true, "autofs": true, "binfmt_misc": true, "efivarfs": true, "rpc_pipefs": true,
	"nsfs": true, "selinuxfs": true, "squashfs": true, "fuse.gvfsd-fuse": true, "fuse.portal": true,
}

// IsPseudoFS reports whether fstype is a pseudo filesystem.
func IsPseudoFS(fstype string) bool { return pseudoFS[fstype] }

// HidePID reports whether a proc mount has a hidepid option that hides
// other users' processes (hidepid=1|2|noaccess|invisible|ptraceable;
// hidepid=0|off does not), with the option's value.
func HidePID(mounts []Mount) (hidden bool, mode string) {
	for i := range mounts {
		m := &mounts[i]
		if m.FSType != "proc" {
			continue
		}
		for _, o := range strings.Split(m.SuperOptions, ",") {
			if v, ok := strings.CutPrefix(o, "hidepid="); ok && v != "0" && v != "off" {
				return true, v
			}
		}
	}
	return false, ""
}

// PIDStat is the subset of /proc/<pid>/stat the gate reports.
type PIDStat struct {
	PID       int
	Comm      string
	State     string
	PPID      int
	UTime     uint64 // clock ticks
	STime     uint64 // clock ticks
	StartTime uint64 // clock ticks after boot
	RSSPages  int64
}

// ParsePIDStat parses /proc/<pid>/stat. comm is in parentheses and may
// itself contain spaces and parentheses, so it ends at the last ')'.
func ParsePIDStat(b []byte) (PIDStat, error) {
	s := string(bytes.TrimRight(b, "\n"))
	open := strings.IndexByte(s, '(')
	closing := strings.LastIndexByte(s, ')')
	if open < 1 || closing < open {
		return PIDStat{}, formatErr("stat comm")
	}
	var st PIDStat
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil || pid < 0 {
		return PIDStat{}, formatErr("stat pid")
	}
	st.PID, st.Comm = pid, s[open+1:closing]
	// Fields after comm: 3 state, 4 ppid, ..., 14 utime, 15 stime, ...,
	// 22 starttime, 23 vsize, 24 rss (proc(5) numbering).
	f := strings.Fields(s[closing+1:])
	if len(f) < 22 || len(f[0]) != 1 {
		return PIDStat{}, formatErr("stat fields")
	}
	st.State = f[0]
	ppid, err := strconv.Atoi(f[1])
	if err != nil || ppid < 0 {
		return PIDStat{}, formatErr("stat ppid")
	}
	st.PPID = ppid
	u := func(i int) (uint64, error) { return strconv.ParseUint(f[i], 10, 64) }
	var e1, e2, e3, e4 error
	st.UTime, e1 = u(11)
	st.STime, e2 = u(12)
	st.StartTime, e3 = u(19)
	st.RSSPages, e4 = strconv.ParseInt(f[21], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || st.RSSPages < 0 {
		return PIDStat{}, formatErr("stat numbers")
	}
	return st, nil
}

// ParseStatusUID returns the real uid from /proc/<pid>/status ("Uid:
// real effective saved fs").
func ParseStatusUID(b []byte) (uint32, error) {
	for _, line := range lines(b) {
		v, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) != 4 {
			return 0, formatErr("status Uid")
		}
		uid, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			return 0, formatErr("status Uid")
		}
		return uint32(uid), nil
	}
	return 0, formatErr("status has no Uid")
}

// maxArgs bounds how many cmdline arguments are considered.
const maxArgs = 4096

// SplitCmdline splits /proc/<pid>/cmdline (NUL-separated, usually
// NUL-terminated) into at most maxArgs arguments.
func SplitCmdline(raw []byte) []string {
	raw = bytes.TrimSuffix(raw, []byte{0})
	if len(raw) == 0 {
		return nil
	}
	parts := bytes.SplitN(raw, []byte{0}, maxArgs+1)
	if len(parts) > maxArgs {
		parts = parts[:maxArgs]
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}

// Mask replaces a redacted argument value.
const Mask = "[REDACTED]"

var (
	// A flag whose name looks secret: --password, --token, --secret,
	// --api-key, --auth…, --credential…, --private-key, --passwd, --pass.
	secretFlag = regexp.MustCompile(`(?i)^--?[a-z0-9_.-]*(pass(word|wd|phrase)?|token|secret|api[-_]?key|auth|credential|private[-_]?key)[a-z0-9_.-]*$`)
	// user:password@ in a URL.
	urlUserinfo = regexp.MustCompile(`(://)[^/@\s]+@`)
)

// RedactArgs masks the values of secret-looking flags — "--flag value",
// "--flag=value", "-p value" and "-pvalue" — and URL userinfo, and
// returns a new slice.
func RedactArgs(args []string) []string {
	out := make([]string, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		out[i] = urlUserinfo.ReplaceAllString(a, "${1}"+Mask+"@")
		if i == 0 {
			continue // the program itself
		}
		name, _, hasValue := strings.Cut(a, "=")
		switch {
		case a == "-p" || (hasValue && secretFlag.MatchString(name)) || (!hasValue && secretFlag.MatchString(a)):
			if hasValue {
				out[i] = name + "=" + Mask
				continue
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				out[i+1] = Mask
				i++
			}
		case strings.HasPrefix(a, "-p") && !strings.HasPrefix(a, "--") && len(a) > 2:
			out[i] = "-p" + Mask
		}
	}
	return out
}

// Truncate cuts s to at most n runes (invalid UTF-8 counts one rune per
// byte) and reports whether it cut.
func Truncate(s string, n int) (string, bool) {
	if n < 0 {
		n = 0
	}
	if utf8.RuneCountInString(s) <= n {
		return s, false
	}
	i, count := 0, 0
	for i < len(s) && count < n {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		count++
	}
	return s[:i], true
}
