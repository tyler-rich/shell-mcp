//go:build linux

// Package units generates the privileged helper's systemd units from its
// policy (docs/PRIVILEGED.md §2, §5.1, §5.2): the socket unit and the
// templated service unit of the core sandbox and — only for a policy that
// uses it (packages, unit: broad commands, power) — of the broad one, each
// pinned to the policy's SHA-256, naming its client_uid and its own unit.
//
// The output is deterministic, and the generator refuses anything a unit
// cannot hold exactly as declared: a core capability outside the policy's
// computed set, a broad unit for a policy that uses none, a directive on
// the forbidden list, or a path or name that a unit file would reinterpret
// (whitespace, quotes, backslashes, "%" specifiers, "$" variables, control
// characters).
package units

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// Fixed paths and names (PRIVILEGED §2).
const (
	SocketPath  = "/run/shell-mcp/privd.sock"
	HelperPath  = "/usr/local/libexec/shell-mcp-privd"
	BackupDir   = "/var/lib/shell-mcp/backups"
	SocketUnit  = "shell-mcp-privd.socket"
	ServiceUnit = "shell-mcp-privd@.service"
	// BroadSocketPath, BroadSocketUnit and BroadServiceUnit are the broad unit's.
	BroadSocketPath  = "/run/shell-mcp/privd-broad.sock"
	BroadSocketUnit  = "shell-mcp-privd-broad.socket"
	BroadServiceUnit = "shell-mcp-privd-broad@.service"
	// HashEnv carries the policy hash into the helper.
	HashEnv = "SHELL_MCP_PRIVD_POLICY_SHA256"
	// ClientUIDEnv carries the policy's client_uid into the helper, so the
	// peer check reads nothing from disk (PRIVILEGED §7).
	ClientUIDEnv = "SHELL_MCP_PRIVD_CLIENT_UID"
	// UnitEnv tells the helper which unit it runs in: core or broad. Each
	// instance refuses operations meant for the other (helper_wrong_unit).
	UnitEnv = "SHELL_MCP_PRIVD_UNIT"
	// MaxConnections bounds concurrent helper instances (and so root
	// processes) started by the socket.
	MaxConnections = 16
	// DirectoryMode is the mode systemd gives the socket's parent directory
	// (/run/shell-mcp) when it creates it. systemd creates it as root:root
	// (SocketUser=/SocketGroup= apply to the socket node only), so the gate
	// needs search permission from "other": 0711 lets it reach the socket
	// by name without listing the directory. The socket node itself is
	// root:<socket group> 0660.
	DirectoryMode = "0711"
	// RuntimeSlackS is added to limits.max_timeout_s for RuntimeMaxSec=.
	RuntimeSlackS = 30
	// StopTimeoutS is both units' TimeoutStopSec=: how long whatever is left
	// in a stopping instance's cgroup has after SIGTERM before SIGKILL.
	StopTimeoutS  = 5
	documentation = "https://github.com/tyler-rich/shell-mcp/blob/main/docs/PRIVILEGED.md"
)

// inaccessible are the never-readable credential paths (PRIVILEGED §5.1,
// §5.3; the built-in read deny list of POLICY §3 without its globs, which
// InaccessiblePaths= does not support). "-" ignores a path that does not
// exist on this host. No read or write root may be inside any of them:
// each is on the never list.
var inaccessible = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d",
	"/etc/security/opasswd", "/etc/ssh", "/root/.ssh",
}

// deniedSyscallGroups are removed from @system-service (PRIVILEGED §5.1).
// A group is kept only when a declared capability needs it (see adjust).
var deniedSyscallGroups = []string{"@mount", "@module", "@reboot", "@swap", "@raw-io", "@debug", "@obsolete"}

// adjust maps a declared capability to the syscall group it needs back.
// CAP_SYS_BOOT is the only declarable capability usable in the core unit
// whose syscalls are in a removed group (reboot(2), kexec_load(2) in
// @reboot). CAP_KILL (kill(2) is in @process) and CAP_SYS_ADMIN need no
// change; CAP_SYS_TIME and the network capabilities are refused for the
// core unit by the policy loader.
var adjust = map[string]string{"CAP_SYS_BOOT": "@reboot"}

// Files are the generated unit files' contents.
type Files struct {
	Socket  string
	Service string
}

// safeRE is what a path or name may contain to appear verbatim in a unit
// file: no whitespace, quotes, backslash, "%" (specifiers), "$"
// (variables in ExecStart=), ";" or control characters.
var safeRE = regexp.MustCompile(`^[A-Za-z0-9._/@+:,=-]+$`)

var (
	groupRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	hashRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func safePath(what, p string) error {
	if err := pathx.CheckClean(p); err != nil {
		return fmt.Errorf("%s %q: %w", what, p, err)
	}
	if !safeRE.MatchString(p) || strings.Contains(p, "/-") {
		return fmt.Errorf("%s %q contains characters the unit generator does not quote (use only letters, digits and ._/@+:,=-, and no component starting with -)", what, p)
	}
	return nil
}

// socket writes a socket unit: one helper instance per connection, the
// socket node root:<socket group> 0660 in a root-owned 0711 directory.
func socket(p *policy.Policy, header, unit, path string) string {
	var b strings.Builder
	b.WriteString(header)
	fmt.Fprintf(&b, "# %s unit socket (PRIVILEGED §2, §3): one helper instance per connection.\n", unitTitle(unit))
	fmt.Fprintf(&b, "[Unit]\nDescription=shell-mcp privileged helper socket (%s unit)\nDocumentation=%s\n\n", unit, documentation)
	fmt.Fprintf(&b, "[Socket]\nListenStream=%s\nAccept=yes\nSocketUser=root\nSocketGroup=%s\nSocketMode=0660\nDirectoryMode=%s\nMaxConnections=%d\n\n",
		path, p.SocketGroup, DirectoryMode, MaxConnections)
	b.WriteString("[Install]\nWantedBy=sockets.target\n")
	return b.String()
}

func unitTitle(unit string) string { return strings.ToUpper(unit[:1]) + unit[1:] }

// runLines are what running the helper needs, the same in both units: the
// policy hash and client uid the unit is pinned to, and which unit it is.
func runLines(p *policy.Policy, unit policy.Unit) [][2]string {
	return [][2]string{
		{"ExecStart", HelperPath + " serve --policy " + p.File},
		{"StandardInput", "socket"},
		{"StandardOutput", "socket"},
		{"StandardError", "journal"},
		{"SyslogIdentifier", "shell-mcp-privd"},
		{"Environment", HashEnv + "=" + p.SHA256},
		{"Environment", ClientUIDEnv + "=" + strconv.FormatUint(uint64(p.ClientUID), 10)},
		{"Environment", UnitEnv + "=" + string(unit)},
	}
}

func header(p *policy.Policy) string {
	return fmt.Sprintf("# Generated by shell-mcp-privd units from %s — do not edit by hand.\n# Policy sha256: %s\n", p.File, p.SHA256)
}

// Core generates the core unit pair for a validated policy.
func Core(p *policy.Policy) (Files, error) {
	if err := check(p); err != nil {
		return Files{}, err
	}
	if err := checkCoreCapabilities(p); err != nil {
		return Files{}, err
	}
	rw := append(p.Paths.WriteRoots(), BackupDir)
	caps := slices.Clone(p.Capabilities)
	var removed []string
	for _, g := range deniedSyscallGroups {
		keep := false
		for _, c := range caps {
			if adjust[c] == g {
				keep = true
			}
		}
		if !keep {
			removed = append(removed, g)
		}
	}
	inacc := make([]string, len(inaccessible))
	for i, pth := range inaccessible {
		inacc[i] = "-" + pth
	}
	h := header(p)

	var svc strings.Builder
	svc.WriteString(h)
	svc.WriteString("# Core unit (PRIVILEGED §5.1): one request per instance, root with a\n# minimal capability set, writes only to the declared paths, no network.\n")
	fmt.Fprintf(&svc, "[Unit]\nDescription=shell-mcp privileged helper (core unit, one request)\nDocumentation=%s\nCollectMode=inactive-or-failed\n\n", documentation)
	svc.WriteString("[Service]\n")
	lines := append(runLines(p, policy.UnitCore), [][2]string{
		{"User", "root"},
		{"NoNewPrivileges", "yes"},
		{"CapabilityBoundingSet", strings.Join(caps, " ")},
		{"ProtectSystem", "strict"},
		{"ReadWritePaths", strings.Join(rw, " ")},
		{"InaccessiblePaths", strings.Join(inacc, " ")},
		{"ProtectHome", "read-only"},
		// /run holds the system bus, systemd's private socket and other
		// sockets that are root-equivalent to a root client; the core unit
		// sees an empty read-only tmpfs there. (Not InaccessiblePaths=:
		// systemd 257 remounts its own /run/systemd/incoming after the
		// namespace is set up, which an inaccessible /run makes fail.)
		{"TemporaryFileSystem", "/run:ro"},
		{"ProtectProc", protectProc(caps)},
		{"ProcSubset", "pid"},
		{"PrivateTmp", "yes"},
		{"PrivateDevices", "yes"},
		{"PrivateNetwork", "yes"},
		{"RestrictAddressFamilies", "AF_UNIX"},
		{"IPAddressDeny", "any"},
		{"ProtectKernelTunables", "yes"},
		{"ProtectKernelModules", "yes"},
		{"ProtectKernelLogs", "yes"},
		{"ProtectControlGroups", "yes"},
		{"ProtectClock", "yes"},
		{"ProtectHostname", "yes"},
		{"RestrictNamespaces", "yes"},
		{"RestrictRealtime", "yes"},
		{"RestrictSUIDSGID", "yes"},
		{"LockPersonality", "yes"},
		{"MemoryDenyWriteExecute", "yes"},
		{"SystemCallArchitectures", "native"},
		{"SystemCallFilter", "@system-service"},
		{"SystemCallFilter", "~" + strings.Join(removed, " ")},
		{"UMask", "0077"},
		{"RuntimeMaxSec", strconv.Itoa(p.Limits.MaxTimeoutS + RuntimeSlackS)},
		{"TasksMax", "64"},
		{"MemoryMax", MemoryMax(p)},
		{"MemorySwapMax", "0"},
		{"OOMPolicy", "continue"},
		// A dead instance leaves nothing running for long: systemd sends
		// SIGTERM to everything left in its cgroup, then SIGKILL after
		// StopTimeoutS. A command that switched user lost its parent-death
		// signal, and its own children never had one.
		{"KillMode", "control-group"},
		{"TimeoutStopSec", strconv.Itoa(StopTimeoutS)},
	}...)
	body, err := Render(lines)
	if err != nil {
		return Files{}, err
	}
	svc.WriteString(body)
	return Files{Socket: socket(p, h, "core", SocketPath), Service: svc.String()}, nil
}

// BroadTasksMax is the broad unit's TasksMax=: apt-get and dpkg with
// maintainer scripts need more tasks than one core-unit request.
const BroadTasksMax = "256"

// HelperMemoryMB is the room MemoryMax= leaves the helper itself above the
// commands' limit: its buffers are bounded by the policy's output, read and
// write caps (at most 4 MiB each) and the 4 MiB answer.
const HelperMemoryMB = 256

// MemoryMax is both units' MemoryMax=: limits.max_memory_mb plus
// HelperMemoryMB (handoff N-30). A command reaches its own RLIMIT_DATA
// (its allocation fails) before the instance reaches this; only a tree of
// processes, each under its limit, can reach it. OOMPolicy=continue then
// leaves the instance running after the kernel kills the process it
// chose, so the helper answers with the command's signal and ends what is
// left, instead of systemd stopping the instance (and the answer).
// MemorySwapMax=0 (both units) makes MemoryMax= bound memory and swap
// together: on a host with swap, the kernel would otherwise push the
// instance's pages into swap past MemoryMax= instead of killing anything,
// slowing the whole host until the request timed out.
func MemoryMax(p *policy.Policy) string {
	return strconv.Itoa(p.Limits.MaxMemoryMB+HelperMemoryMB) + "M"
}

// Broad generates the broad unit pair (PRIVILEGED §5.2) for a policy that
// uses it (packages, unit: broad commands, power); it refuses otherwise.
// It sets no User=: the service runs as root without it, and with User=
// systemd drops CAP_SETUID from a unit that has seccomp filters (its
// keep_seccomp_privileges path in exec-invoke.c, 257 and 259; ProtectClock=
// and ProtectKernelModules= install filters), which apt needs to switch to
// its _apt user.
// Network is allowed, ProtectSystem= and RestrictSUIDSGID= are off and the
// capability bounding set is root's (none of them is written); still
// NoNewPrivileges=, PrivateTmp=, ProtectKernelModules=,
// ProtectKernelTunables=, ProtectClock= (off only when a broad command
// declares CAP_SYS_TIME), RuntimeMaxSec=, TasksMax=, MemoryMax=, KillMode=
// and TimeoutStopSec=.
func Broad(p *policy.Policy) (Files, error) {
	if err := check(p); err != nil {
		return Files{}, err
	}
	if !p.UsesBroad() {
		return Files{}, errors.New("the policy uses no broad unit (no packages, unit: broad command or power)")
	}
	h := header(p)
	var svc strings.Builder
	svc.WriteString(h)
	svc.WriteString("# Broad unit (PRIVILEGED §5.2): one request per instance, for packages,\n# unit: broad commands and power. Network and full root capabilities:\n# ROOT-EQUIVALENT by design.\n")
	fmt.Fprintf(&svc, "[Unit]\nDescription=shell-mcp privileged helper (broad unit, one request)\nDocumentation=%s\nCollectMode=inactive-or-failed\n\n", documentation)
	svc.WriteString("[Service]\n")
	lines := append(runLines(p, policy.UnitBroad), [][2]string{
		{"NoNewPrivileges", "yes"},
		{"PrivateTmp", "yes"},
		{"ProtectKernelModules", "yes"},
		{"ProtectKernelTunables", "yes"},
	}...)
	if p.BroadProtectClock() {
		lines = append(lines, [2]string{"ProtectClock", "yes"})
	}
	lines = append(lines, [][2]string{
		{"RuntimeMaxSec", strconv.Itoa(p.Limits.MaxTimeoutS + RuntimeSlackS)},
		{"TasksMax", BroadTasksMax},
		{"MemoryMax", MemoryMax(p)},
		{"MemorySwapMax", "0"},
		{"OOMPolicy", "continue"},
		{"KillMode", "control-group"},
		{"TimeoutStopSec", strconv.Itoa(StopTimeoutS)},
	}...)
	body, err := Render(lines)
	if err != nil {
		return Files{}, err
	}
	svc.WriteString(body)
	return Files{Socket: socket(p, h, "broad", BroadSocketPath), Service: svc.String()}, nil
}

// protectProc is the core unit's ProtectProc=: ptraceable, which hides every
// process the unit may not ptrace — other users' processes, since it has no
// CAP_SYS_PTRACE, and, under the helper's Landlock domain, every process
// outside that domain, root-owned ones included — or
// default when a core-unit command declares CAP_KILL, because signalling a
// process requires seeing it. Not invisible: the kernel exempts procfs's
// gid= group from that mode's check (has_pid_permissions(), fs/proc/base.c),
// that group is gid 0 when systemd passes no gid=, and the helper runs as
// root:root, so invisible would hide nothing.
func protectProc(caps []string) string {
	if slices.Contains(caps, "CAP_KILL") {
		return "default"
	}
	return "ptraceable"
}

// check refuses a policy whose units could not be written exactly: an odd
// hash, path, group, client uid or timeout.
func check(p *policy.Policy) error {
	if !hashRE.MatchString(p.SHA256) {
		return errors.New("policy hash is not 64 lowercase hex digits")
	}
	if err := safePath("policy path", p.File); err != nil {
		return err
	}
	if !groupRE.MatchString(p.SocketGroup) {
		return fmt.Errorf("socket group %q is not a plain group name", p.SocketGroup)
	}
	if p.ClientUID == 0 || p.ClientUID == math.MaxUint32 {
		return fmt.Errorf("client_uid %d is not in 1..4294967294 (root may never be the client)", p.ClientUID)
	}
	if p.Limits.MaxTimeoutS < 1 || p.Limits.MaxTimeoutS > policy.MaxTimeoutCeiling {
		return fmt.Errorf("limits.max_timeout_s %d is not in 1..%d", p.Limits.MaxTimeoutS, policy.MaxTimeoutCeiling)
	}
	if p.Limits.MaxMemoryMB < gpolicy.MaxMemoryMBMin || p.Limits.MaxMemoryMB > gpolicy.MaxMemoryMBMax {
		return fmt.Errorf("limits.max_memory_mb %d is not in %d..%d", p.Limits.MaxMemoryMB, gpolicy.MaxMemoryMBMin, gpolicy.MaxMemoryMBMax)
	}
	for _, r := range p.Paths.WriteRoots() {
		if err := safePath("write root", r); err != nil {
			return err
		}
	}
	return nil
}

// checkCoreCapabilities refuses a core capability set that is not exactly
// the base set plus what core-unit commands declare, or that holds a
// capability with no effect in the core unit.
func checkCoreCapabilities(p *policy.Policy) error {
	want := slices.Clone(policy.BaseCapabilities)
	for i := range p.Commands {
		c := &p.Commands[i]
		if c.Unit != policy.UnitCore {
			continue
		}
		for _, cp := range c.Capabilities {
			if !slices.Contains(want, cp) {
				want = append(want, cp)
			}
		}
	}
	if len(p.Capabilities) != len(want) {
		return fmt.Errorf("capability set %v does not match the policy's core-unit commands", p.Capabilities)
	}
	for _, cp := range p.Capabilities {
		n, ok := policy.CapabilityNumber(cp)
		switch {
		case !ok || !slices.Contains(want, cp):
			return fmt.Errorf("capability %s is not the base set or declared by a core-unit command", cp)
		case n == 25 || n == 12 || n == 10: // CAP_SYS_TIME, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE
			return fmt.Errorf("capability %s has no effect in the core unit", cp)
		}
	}
	return nil
}

// forbidden are directives the generator never emits, for any unit
// (PRIVILEGED §5.1): a private user namespace (PrivateUsers=) maps real host
// users away, so chown to an owner from the policy's allow-list could not
// work; a separate root filesystem (RootDirectory=, RootImage=) defeats the
// purpose of working on the host's own files.
var forbidden = []string{"privateusers", "rootdirectory", "rootimage"}

// Render writes directive lines as "Key=value" lines, refusing any
// directive in the forbidden set whatever the caller passes.
func Render(lines [][2]string) (string, error) {
	var b strings.Builder
	for _, l := range lines {
		if slices.Contains(forbidden, strings.ToLower(l[0])) {
			return "", fmt.Errorf("directive %s= is never generated (PRIVILEGED §5.1)", l[0])
		}
		fmt.Fprintf(&b, "%s=%s\n", l[0], l[1])
	}
	return b.String(), nil
}
