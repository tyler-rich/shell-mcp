// Package procfs parses the host files the gate's native system operations
// read (docs/ARCHITECTURE.md §4.3): os-release(5) and the proc(5) files
// /proc/uptime, /proc/loadavg, /proc/meminfo, /proc/stat,
// /proc/self/mountinfo and /proc/<pid>/{stat,status,cmdline}. It only
// parses bytes; reading them is fsx's job. Every parser is bounded, never
// panics, and is fuzzed.
package procfs

import "errors"

// maxOSReleaseValue bounds one os-release value.
const maxOSReleaseValue = 256

var errTODO = errors.New("not implemented")

// OSRelease holds the os-release fields the gate reports.
type OSRelease struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ID              string `json:"id"`
	VersionID       string `json:"version_id"`
	PrettyName      string `json:"pretty_name"`
	VersionCodename string `json:"version_codename"`
}

// ParseOSRelease parses os-release(5).
func ParseOSRelease(_ []byte) OSRelease { return OSRelease{} }

func unquoteOSRelease(_ string) (string, bool) { return "", false }

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

// ParseMeminfo parses /proc/meminfo.
func ParseMeminfo(_ []byte) (Meminfo, error) { return Meminfo{}, errTODO }

// ParseUptime parses /proc/uptime.
func ParseUptime(_ []byte) (float64, error) { return 0, errTODO }

// Loadavg is /proc/loadavg.
type Loadavg struct {
	Load1   float64 `json:"load_1m"`
	Load5   float64 `json:"load_5m"`
	Load15  float64 `json:"load_15m"`
	Running int     `json:"running"`
	Total   int     `json:"total"`
}

// ParseLoadavg parses /proc/loadavg.
func ParseLoadavg(_ []byte) (Loadavg, error) { return Loadavg{}, errTODO }

// Stat is the subset of /proc/stat the gate needs.
type Stat struct {
	BootTime int64
	CPUs     int
}

// ParseStat parses /proc/stat.
func ParseStat(_ []byte) (Stat, error) { return Stat{}, errTODO }

// Mount is one line of /proc/self/mountinfo.
type Mount struct {
	MountPoint   string
	Options      string
	FSType       string
	Source       string
	SuperOptions string
}

// ReadOnly reports whether the mount is read-only.
func (m *Mount) ReadOnly() bool { return false }

// ParseMountinfo parses at most limit mounts.
func ParseMountinfo(_ []byte, _ int) ([]Mount, error) { return nil, errTODO }

// IsPseudoFS reports whether fstype is a pseudo filesystem.
func IsPseudoFS(_ string) bool { return false }

// HidePID reports whether /proc is mounted with an effective hidepid.
func HidePID(_ []Mount) (hidden bool, mode string) { return false, "" }

// PIDStat is the subset of /proc/<pid>/stat the gate reports.
type PIDStat struct {
	PID       int
	Comm      string
	State     string
	PPID      int
	UTime     uint64
	STime     uint64
	StartTime uint64
	RSSPages  int64
}

// ParsePIDStat parses /proc/<pid>/stat.
func ParsePIDStat(_ []byte) (PIDStat, error) { return PIDStat{}, errTODO }

// ParseStatusUID returns the real uid from /proc/<pid>/status.
func ParseStatusUID(_ []byte) (uint32, error) { return 0, errTODO }

// SplitCmdline splits /proc/<pid>/cmdline.
func SplitCmdline(_ []byte) []string { return nil }

// RedactArgs masks values after secret-looking flags.
func RedactArgs(a []string) []string { return a }

// Truncate cuts s to at most n runes.
func Truncate(s string, _ int) (string, bool) { return s, false }
