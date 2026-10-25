package tools

import (
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// System tools: the gate's native sysinfo, disk and processes ops. The
// data types are the gate's wire shapes (internal/gate/ops/system.go),
// decoded strictly.

// SysInfo is shell_get_system_info's data.
type SysInfo struct {
	OS       OSRelease `json:"os" jsonschema:"Fields of the host's os-release file."`
	Kernel   Kernel    `json:"kernel" jsonschema:"The running kernel (uname)."`
	Hostname string    `json:"hostname" jsonschema:"The host's node name."`
	UptimeS  float64   `json:"uptime_s" jsonschema:"Seconds since boot."`
	BootTime string    `json:"boot_time" jsonschema:"Boot time, RFC 3339 UTC."`
	Load     Load      `json:"load" jsonschema:"Load averages and task counts."`
	Memory   Memory    `json:"memory" jsonschema:"Memory and swap in bytes."`
	CPU      CPU       `json:"cpu" jsonschema:"CPU counts."`
}

// OSRelease is the parsed os-release.
type OSRelease struct {
	Name            string `json:"name" jsonschema:"NAME."`
	Version         string `json:"version" jsonschema:"VERSION."`
	ID              string `json:"id" jsonschema:"ID."`
	VersionID       string `json:"version_id" jsonschema:"VERSION_ID."`
	PrettyName      string `json:"pretty_name" jsonschema:"PRETTY_NAME."`
	VersionCodename string `json:"version_codename" jsonschema:"VERSION_CODENAME."`
}

// Kernel is uname's answer.
type Kernel struct {
	Sysname string `json:"sysname" jsonschema:"Kernel name."`
	Release string `json:"release" jsonschema:"Kernel release."`
	Version string `json:"version" jsonschema:"Kernel build version."`
	Machine string `json:"machine" jsonschema:"Hardware architecture."`
}

// Load is /proc/loadavg.
type Load struct {
	Load1   float64 `json:"load_1m" jsonschema:"One-minute load average."`
	Load5   float64 `json:"load_5m" jsonschema:"Five-minute load average."`
	Load15  float64 `json:"load_15m" jsonschema:"Fifteen-minute load average."`
	Running int     `json:"running" jsonschema:"Runnable tasks."`
	Total   int     `json:"total" jsonschema:"Total tasks."`
}

// Memory is /proc/meminfo in bytes.
type Memory struct {
	TotalBytes     uint64 `json:"total_bytes" jsonschema:"MemTotal."`
	FreeBytes      uint64 `json:"free_bytes" jsonschema:"MemFree."`
	AvailableBytes uint64 `json:"available_bytes" jsonschema:"MemAvailable."`
	BuffersBytes   uint64 `json:"buffers_bytes" jsonschema:"Buffers."`
	CachedBytes    uint64 `json:"cached_bytes" jsonschema:"Cached."`
	SwapTotalBytes uint64 `json:"swap_total_bytes" jsonschema:"SwapTotal."`
	SwapFreeBytes  uint64 `json:"swap_free_bytes" jsonschema:"SwapFree."`
}

// CPU counts.
type CPU struct {
	Online int `json:"online" jsonschema:"CPUs the kernel lists."`
	Usable int `json:"usable" jsonschema:"CPUs the gate may run on."`
}

func getSystemInfo(d *Deps) Tool {
	return define(d, spec[targetArg, SysInfo]{
		name:        "shell_get_system_info",
		title:       "Get system info",
		description: "Returns the target's OS release, kernel, hostname, uptime, load averages, memory and CPU count.",
		tier:        TierRead,
		schema:      boundCommon,
		audit:       func(in targetArg) map[string]any { return map[string]any{"target": in.Target} },
		summary: func(s *SysInfo) string {
			return fmt.Sprintf("%s, up %.0f s", plural(s.CPU.Online, "CPU", "CPUs"), s.UptimeS)
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in targetArg) envelope.Envelope[SysInfo] {
			return fetch[SysInfo](ctx, d, in.Target, protocol.OpSysinfo, struct{}{}, d.budget())
		},
	})
}

type diskIn struct {
	targetArg
	IncludePseudo bool `json:"include_pseudo,omitzero" jsonschema:"Include pseudo filesystems (proc, sysfs, tmpfs, cgroup and similar). Default false."`
}

// DiskUsage is shell_get_disk_usage's data.
type DiskUsage struct {
	Mounts         []Mount `json:"mounts" jsonschema:"One entry per mount, in mount order."`
	PseudoFiltered int     `json:"pseudo_filtered" jsonschema:"Pseudo filesystems left out."`
	Truncated      bool    `json:"truncated,omitzero" jsonschema:"True when mounts were left out to fit the output size limit."`
}

// Mount is one mounted filesystem.
type Mount struct {
	MountPoint  string  `json:"mount_point" jsonschema:"Mount point."`
	Source      string  `json:"source" jsonschema:"Mount source."`
	FSType      string  `json:"fs_type" jsonschema:"Filesystem type."`
	Pseudo      bool    `json:"pseudo" jsonschema:"Whether it is a pseudo filesystem."`
	ReadOnly    bool    `json:"read_only" jsonschema:"Whether it is mounted read-only."`
	SizeBytes   uint64  `json:"size_bytes" jsonschema:"Size in bytes."`
	UsedBytes   uint64  `json:"used_bytes" jsonschema:"Used bytes."`
	AvailBytes  uint64  `json:"avail_bytes" jsonschema:"Bytes available to unprivileged users."`
	Inodes      uint64  `json:"inodes" jsonschema:"Total inodes."`
	InodesUsed  uint64  `json:"inodes_used" jsonschema:"Used inodes."`
	InodesFree  uint64  `json:"inodes_free" jsonschema:"Free inodes."`
	Unavailable *string `json:"unavailable,omitempty" jsonschema:"Why sizes are missing (statfs failed or timed out after 2 s), when they are."`
}

type diskWire struct {
	IncludePseudo bool `json:"include_pseudo"`
}

func getDiskUsage(d *Deps) Tool {
	return define(d, spec[diskIn, DiskUsage]{
		name:        "shell_get_disk_usage",
		title:       "Get disk usage",
		description: "Returns each mounted filesystem's type, size, used and available bytes and inode counts.",
		tier:        TierRead,
		schema:      boundCommon,
		audit:       func(in diskIn) map[string]any { return map[string]any{"target": in.Target} },
		summary: func(u *DiskUsage) string {
			return plural(len(u.Mounts), "mount", "mounts") + truncated(u.Truncated)
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in diskIn) envelope.Envelope[DiskUsage] {
			env := fetch[DiskUsage](ctx, d, in.Target, protocol.OpDisk, diskWire{IncludePseudo: in.IncludePseudo}, d.budget())
			if env.OK {
				env.Data.Truncated = fitList(env.Data, &env.Data.Mounts, d.maxOutput())
			}
			return env
		},
	})
}

type processesIn struct {
	targetArg
	User         string `json:"user,omitzero" jsonschema:"Only processes of this user name or numeric uid."`
	NameContains string `json:"name_contains,omitzero" jsonschema:"Only processes whose command name contains this text (at most 256 bytes)."`
	SortBy       string `json:"sort_by,omitzero" jsonschema:"Sort order: rss (resident memory, largest first; default), cpu (CPU time, largest first) or pid."`
	Limit        *int   `json:"limit,omitzero" jsonschema:"Most processes returned (1-1000, default 100)."`
}

func (in *processesIn) validate() *envelope.Error {
	switch {
	case in.User != "" && !userRE.MatchString(in.User):
		return invalid("user must be a user name or a numeric uid")
	case in.SortBy != "" && in.SortBy != "rss" && in.SortBy != "cpu" && in.SortBy != "pid":
		return invalid("sort_by must be rss, cpu or pid")
	}
	if e := checkFilter("name_contains", in.NameContains); e != nil {
		return e
	}
	return checkCount("limit", in.Limit, 1000)
}

// ProcessList is shell_list_processes' data.
type ProcessList struct {
	Processes []Process `json:"processes" jsonschema:"Matching processes in the requested order, at most limit."`
	Scanned   int       `json:"scanned" jsonschema:"Process entries examined."`
	Skipped   int       `json:"skipped" jsonschema:"Entries that exited or could not be read."`
	Matched   int       `json:"matched" jsonschema:"Processes that matched the filters."`
	Truncated bool      `json:"truncated" jsonschema:"True when more processes existed than the policy's max_processes, or entries were left out to fit the output size limit."`
	HidePID   HidePID   `json:"hidepid" jsonschema:"Whether /proc hides other users' processes (the list is then partial)."`
}

// Process is one process. Command lines arrive redacted and cut to 512
// characters by the gate, and are redacted again here.
type Process struct {
	PID              int     `json:"pid" jsonschema:"Process id."`
	PPID             int     `json:"ppid" jsonschema:"Parent process id."`
	UID              uint32  `json:"uid" jsonschema:"Real user id."`
	User             string  `json:"user" jsonschema:"User name, empty when unknown."`
	State            string  `json:"state" jsonschema:"Kernel state letter."`
	RSSBytes         int64   `json:"rss_bytes" jsonschema:"Resident memory in bytes."`
	CPUTimeS         float64 `json:"cpu_time_s" jsonschema:"User plus system CPU seconds."`
	StartTime        string  `json:"start_time" jsonschema:"Start time, RFC 3339 UTC."`
	Comm             string  `json:"comm" jsonschema:"Command name."`
	Cmdline          string  `json:"cmdline" jsonschema:"Command line with secret values redacted, at most 512 characters."`
	CmdlineTruncated bool    `json:"cmdline_truncated" jsonschema:"Whether the command line was cut."`
}

// HidePID reports a hidepid mount of /proc.
type HidePID struct {
	Active bool   `json:"active" jsonschema:"Whether hidepid is in effect."`
	Mode   string `json:"mode" jsonschema:"The hidepid mode."`
}

type processesWire struct {
	User         string `json:"user"`
	NameContains string `json:"name_contains"`
	SortBy       string `json:"sort_by"`
	Limit        int    `json:"limit"`
}

func listProcesses(d *Deps) Tool {
	return define(d, spec[processesIn, ProcessList]{
		name:        "shell_list_processes",
		title:       "List processes",
		description: "Lists the target's processes with user, state, memory, CPU time, start time and a redacted command line, filtered and sorted.",
		tier:        TierRead,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "user", userPattern, 32)
			strIn(s, "name_contains", filterPattern, maxFilter)
			enumIn(s, "sort_by", "rss", "cpu", "pid")
			intIn(s, "limit", 1, 1000)
		},
		audit: func(in processesIn) map[string]any { return map[string]any{"target": in.Target} },
		summary: func(p *ProcessList) string {
			s := fmt.Sprintf("%s of %d matched", plural(len(p.Processes), "process", "processes"), p.Matched)
			if p.HidePID.Active {
				s += ", partial (hidepid)"
			}
			return s + truncated(p.Truncated)
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in processesIn) envelope.Envelope[ProcessList] {
			w := processesWire{User: in.User, NameContains: in.NameContains, SortBy: in.SortBy}
			if in.Limit != nil {
				w.Limit = *in.Limit
			}
			env := fetch[ProcessList](ctx, d, in.Target, protocol.OpProcesses, w, d.budget())
			if env.OK && fitList(env.Data, &env.Data.Processes, d.maxOutput()) {
				env.Data.Truncated = true
			}
			return env
		},
	})
}
