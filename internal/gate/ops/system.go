//go:build linux

package ops

import (
	"cmp"
	"encoding/json/jsontext"
	"errors"
	"os"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/procfs"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Native system operations (ARCHITECTURE §4.3). They read fixed host files
// through fsx.ReadSystemFile and never start a process.

const (
	smallFileLimit   = 64 << 10 // os-release, uptime, loadavg, meminfo, pid stat/status
	statFileLimit    = 1 << 20  // /proc/stat grows with CPUs and interrupts
	mountinfoLimit   = 4 << 20
	maxMounts        = 4096
	cmdlineReadLimit = 64 << 10
	cmdlineMaxRunes  = 512
	statfsTimeout    = 2 * time.Second
	// clockTicks is USER_HZ, the unit of /proc/<pid>/stat times. It is 100
	// on every Linux architecture the gate targets (amd64, arm64); Go has
	// no sysconf(_SC_CLK_TCK) without cgo.
	clockTicks = 100
)

func readSys(p string, limit int) ([]byte, error) {
	b, _, err := fsx.ReadSystemFile(p, limit)
	return b, err
}

type kernelInfo struct {
	Sysname string `json:"sysname"`
	Release string `json:"release"`
	Version string `json:"version"`
	Machine string `json:"machine"`
}

type cpuInfo struct {
	Online int `json:"online"`
	Usable int `json:"usable"`
}

type sysinfoData struct {
	OS       procfs.OSRelease `json:"os"`
	Kernel   kernelInfo       `json:"kernel"`
	Hostname string           `json:"hostname"`
	UptimeS  float64          `json:"uptime_s"`
	BootTime string           `json:"boot_time"`
	Load     procfs.Loadavg   `json:"load"`
	Memory   procfs.Meminfo   `json:"memory"`
	CPU      cpuInfo          `json:"cpu"`
}

func cstr(b []byte) string {
	if i := slices.Index(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func (s *server) sysinfo(raw jsontext.Value) (data any, warns []string, failure error) {
	var a noArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	var d sysinfoData
	var warnings []string
	osr, err := readSys("/etc/os-release", smallFileLimit)
	if err != nil {
		osr, err = readSys("/usr/lib/os-release", smallFileLimit)
	}
	if err == nil {
		d.OS = procfs.ParseOSRelease(osr)
	} else {
		warnings = append(warnings, "os-release could not be read")
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return nil, nil, errf(protocol.CodeInternal, "uname failed")
	}
	d.Kernel = kernelInfo{Sysname: cstr(u.Sysname[:]), Release: cstr(u.Release[:]), Version: cstr(u.Version[:]), Machine: cstr(u.Machine[:])}
	d.Hostname = cstr(u.Nodename[:])

	fail := func(what string) error { return errf(protocol.CodeInternal, "%s could not be read or parsed", what) }
	b, err := readSys("/proc/uptime", smallFileLimit)
	if err != nil {
		return nil, nil, fail("/proc/uptime")
	}
	if d.UptimeS, err = procfs.ParseUptime(b); err != nil {
		return nil, nil, fail("/proc/uptime")
	}
	if b, err = readSys("/proc/loadavg", smallFileLimit); err != nil {
		return nil, nil, fail("/proc/loadavg")
	}
	if d.Load, err = procfs.ParseLoadavg(b); err != nil {
		return nil, nil, fail("/proc/loadavg")
	}
	if b, err = readSys("/proc/meminfo", smallFileLimit); err != nil {
		return nil, nil, fail("/proc/meminfo")
	}
	if d.Memory, err = procfs.ParseMeminfo(b); err != nil {
		return nil, nil, fail("/proc/meminfo")
	}
	st, err := procStat()
	if err != nil {
		return nil, nil, fail("/proc/stat")
	}
	d.BootTime = time.Unix(st.BootTime, 0).UTC().Format(time.RFC3339)
	d.CPU = cpuInfo{Online: st.CPUs, Usable: runtime.NumCPU()}
	return d, warnings, nil
}

func procStat() (procfs.Stat, error) {
	b, err := readSys("/proc/stat", statFileLimit)
	if err != nil {
		return procfs.Stat{}, err
	}
	return procfs.ParseStat(b)
}

func mounts() ([]procfs.Mount, error) {
	b, truncated, err := fsx.ReadSystemFile("/proc/self/mountinfo", mountinfoLimit)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, errors.New("mountinfo exceeds its bound")
	}
	return procfs.ParseMountinfo(b, maxMounts)
}

type diskArgs struct {
	IncludePseudo bool `json:"include_pseudo"`
}

type mountData struct {
	MountPoint  string  `json:"mount_point"`
	Source      string  `json:"source"`
	FSType      string  `json:"fs_type"`
	Pseudo      bool    `json:"pseudo"`
	ReadOnly    bool    `json:"read_only"`
	SizeBytes   uint64  `json:"size_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	AvailBytes  uint64  `json:"avail_bytes"`
	Inodes      uint64  `json:"inodes"`
	InodesUsed  uint64  `json:"inodes_used"`
	InodesFree  uint64  `json:"inodes_free"`
	Unavailable *string `json:"unavailable,omitempty"`
}

type diskData struct {
	Mounts         []mountData `json:"mounts"`
	PseudoFiltered int         `json:"pseudo_filtered"`
}

func (s *server) disk(raw jsontext.Value) (data any, warns []string, failure error) {
	var a diskArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	ms, err := mounts()
	if err != nil {
		return nil, nil, errf(protocol.CodeInternal, "/proc/self/mountinfo could not be read or parsed")
	}
	d := diskData{Mounts: []mountData{}}
	for i := range ms {
		mt := &ms[i]
		pseudo := procfs.IsPseudoFS(mt.FSType)
		if pseudo && !a.IncludePseudo {
			d.PseudoFiltered++
			continue
		}
		md := mountData{MountPoint: mt.MountPoint, Source: mt.Source, FSType: mt.FSType, Pseudo: pseudo, ReadOnly: mt.ReadOnly()}
		st, err := fsx.Statfs(mt.MountPoint, statfsTimeout)
		if err != nil {
			reason := "statfs failed"
			if errors.Is(err, fsx.ErrStatfsTimeout) {
				reason = "statfs timed out"
			}
			md.Unavailable = &reason
			d.Mounts = append(d.Mounts, md)
			continue
		}
		bs := uint64(st.Frsize) //nolint:gosec // G115: fragment size is positive
		if bs == 0 {
			bs = uint64(st.Bsize) //nolint:gosec // G115: block size is positive
		}
		md.SizeBytes = st.Blocks * bs
		md.UsedBytes = (st.Blocks - min(st.Bfree, st.Blocks)) * bs
		md.AvailBytes = st.Bavail * bs
		md.Inodes = st.Files
		md.InodesFree = st.Ffree
		md.InodesUsed = st.Files - min(st.Ffree, st.Files)
		d.Mounts = append(d.Mounts, md)
	}
	return d, nil, nil
}

type processesArgs struct {
	User         string `json:"user"`
	NameContains string `json:"name_contains"`
	SortBy       string `json:"sort_by"`
	Limit        int    `json:"limit"`
}

type processEntry struct {
	PID              int     `json:"pid"`
	PPID             int     `json:"ppid"`
	UID              uint32  `json:"uid"`
	User             string  `json:"user"`
	State            string  `json:"state"`
	RSSBytes         int64   `json:"rss_bytes"`
	CPUTimeS         float64 `json:"cpu_time_s"`
	StartTime        string  `json:"start_time"`
	Comm             string  `json:"comm"`
	Cmdline          string  `json:"cmdline"`
	CmdlineTruncated bool    `json:"cmdline_truncated"`
}

type hidePIDInfo struct {
	Active bool   `json:"active"`
	Mode   string `json:"mode"`
}

type processesData struct {
	Processes []processEntry `json:"processes"`
	Scanned   int            `json:"scanned"`
	Skipped   int            `json:"skipped"`
	Matched   int            `json:"matched"`
	Truncated bool           `json:"truncated"`
	HidePID   hidePIDInfo    `json:"hidepid"`
}

const (
	defaultProcessLimit = 100
	maxProcessLimit     = 1000
	maxFilterLen        = 256
)

func (s *server) processes(raw jsontext.Value) (data any, warns []string, failure error) {
	var a processesArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	switch {
	case a.Limit == 0:
		a.Limit = defaultProcessLimit
	case a.Limit < 1 || a.Limit > maxProcessLimit:
		return nil, nil, errf(protocol.CodeBadRequest, "limit must be 1..%d", maxProcessLimit)
	}
	if a.SortBy == "" {
		a.SortBy = "rss"
	}
	if a.SortBy != "rss" && a.SortBy != "cpu" && a.SortBy != "pid" {
		return nil, nil, errf(protocol.CodeBadRequest, "sort_by must be rss, cpu or pid")
	}
	if len(a.User) > maxFilterLen || len(a.NameContains) > maxFilterLen {
		return nil, nil, errf(protocol.CodeBadRequest, "user and name_contains are at most %d bytes", maxFilterLen)
	}
	st, err := procStat()
	if err != nil {
		return nil, nil, errf(protocol.CodeInternal, "/proc/stat could not be read or parsed")
	}
	d := processesData{Processes: []processEntry{}}
	var warnings []string
	if ms, err := mounts(); err == nil {
		if on, mode := procfs.HidePID(ms); on {
			d.HidePID = hidePIDInfo{Active: true, Mode: mode}
			warnings = append(warnings, "/proc is mounted with hidepid="+mode+": other users' processes are hidden, so this list is partial")
		}
	}
	pids, truncated, err := fsx.ListPIDs(s.p.Limits.MaxProcesses)
	if err != nil {
		return nil, nil, errf(protocol.CodeInternal, "/proc could not be listed")
	}
	d.Truncated = truncated
	if truncated {
		warnings = append(warnings, "more processes exist than limits.max_processes; only the lowest pids were examined")
	}
	pageSize := int64(os.Getpagesize())
	users := map[uint32]string{}
	for _, pid := range pids {
		d.Scanned++
		e, ok := s.process(pid, st.BootTime, pageSize, users)
		if !ok {
			d.Skipped++ // exited, or not readable
			continue
		}
		if a.NameContains != "" && !strings.Contains(e.Comm, a.NameContains) {
			continue
		}
		if a.User != "" && a.User != e.User && a.User != strconv.FormatUint(uint64(e.UID), 10) {
			continue
		}
		d.Processes = append(d.Processes, e)
	}
	d.Matched = len(d.Processes)
	slices.SortStableFunc(d.Processes, func(x, y processEntry) int {
		switch a.SortBy {
		case "rss":
			return cmp.Or(cmp.Compare(y.RSSBytes, x.RSSBytes), cmp.Compare(x.PID, y.PID))
		case "cpu":
			return cmp.Or(cmp.Compare(y.CPUTimeS, x.CPUTimeS), cmp.Compare(x.PID, y.PID))
		}
		return cmp.Compare(x.PID, y.PID)
	})
	if len(d.Processes) > a.Limit {
		d.Processes = d.Processes[:a.Limit]
	}
	return d, warnings, nil
}

// process reads one /proc/<pid> entry. Command lines are redacted (secret
// flags, URL userinfo, the redaction patterns) before they are cut to
// cmdlineMaxRunes.
func (s *server) process(pid int, bootTime, pageSize int64, users map[uint32]string) (processEntry, bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	b, err := readSys(dir+"/stat", smallFileLimit)
	if err != nil {
		return processEntry{}, false
	}
	ps, err := procfs.ParsePIDStat(b)
	if err != nil || ps.PID != pid {
		return processEntry{}, false
	}
	b, err = readSys(dir+"/status", smallFileLimit)
	if err != nil {
		return processEntry{}, false
	}
	uid, err := procfs.ParseStatusUID(b)
	if err != nil {
		return processEntry{}, false
	}
	name, ok := users[uid]
	if !ok {
		if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
			name = u.Username
		}
		users[uid] = name
	}
	e := processEntry{
		PID: ps.PID, PPID: ps.PPID, UID: uid, User: name, State: ps.State,
		RSSBytes:  ps.RSSPages * pageSize,
		CPUTimeS:  float64(ps.UTime+ps.STime) / clockTicks,
		StartTime: time.Unix(bootTime+int64(ps.StartTime/clockTicks), 0).UTC().Format(time.RFC3339), //nolint:gosec // G115: start ticks since boot fit int64
		Comm:      s.red.String(ps.Comm),
	}
	// Kernel threads and zombies have an empty cmdline.
	if raw, cut, err := fsx.ReadSystemFile(dir+"/cmdline", cmdlineReadLimit); err == nil {
		line := s.red.String(strings.Join(procfs.RedactArgs(procfs.SplitCmdline(raw)), " "))
		e.Cmdline, e.CmdlineTruncated = procfs.Truncate(line, cmdlineMaxRunes)
		e.CmdlineTruncated = e.CmdlineTruncated || cut
	}
	return e, true
}
