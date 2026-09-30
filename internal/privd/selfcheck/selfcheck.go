//go:build linux

// Package selfcheck implements the helper's fail-closed startup checks
// (PRIVILEGED §7). Before the peer is authenticated: stdin a connected
// AF_UNIX stream socket and the unit's SHELL_MCP_PRIVD_CLIENT_UID a valid
// uid (the peer's uid itself is checked by internal/privd/peercred). After
// it: uid 0, NoNewPrivs 1, a root-owned and not group/other-writable
// binary, the policy's SHA-256 and client_uid equal to the unit's, and a
// capability bounding set no broader than the unit's. The policy's own
// ownership and validity are checked by internal/privd/policy.Load.
package selfcheck

import (
	"crypto/subtle"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// Check names (the audit line's "check" field).
const (
	CheckUID          = "uid"
	CheckNoNewPrivs   = "no_new_privs"
	CheckCapabilities = "capabilities"
	CheckStdin        = "stdin"
	CheckBinary       = "binary"
	CheckPolicyFile   = "policy_file" // missing, unreadable, or insecure ownership or mode
	CheckPolicy       = "policy"      // does not parse or fails validation
	CheckPolicyHash   = "policy_hash"
	CheckClientUID    = "client_uid" // the policy's client_uid is not the unit's
	CheckPeer         = "peer_uid"
	// CheckUnitClientUID is the unit's SHELL_MCP_PRIVD_CLIENT_UID.
	CheckUnitClientUID = "unit_client_uid"
	// CheckLandlock is the core unit's Landlock sandbox (PRIVILEGED §7 step 3).
	CheckLandlock = "landlock"
	// CheckUnit is the unit's SHELL_MCP_PRIVD_UNIT (core or broad).
	CheckUnit = "unit"
)

// Error is a failed self-check. Check names it for the audit line; Detail
// may name local paths and never reaches the wire.
type Error struct {
	Check  string
	Detail string
}

func (e *Error) Error() string { return e.Check + ": " + e.Detail }

// Status is what the checks read from /proc/self/status.
type Status struct {
	UIDs       [4]uint32 // real, effective, saved, filesystem
	NoNewPrivs bool
	CapBnd     uint64
}

// maxStatusBytes bounds /proc/self/status.
const maxStatusBytes = 64 << 10

// ReadStatus reads and parses /proc/self/status.
func ReadStatus() (Status, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return Status{}, err
	}
	return ParseStatus(b)
}

// ParseStatus parses /proc/self/status (proc_pid_status(5)): "Uid:" holds
// four decimal ids, "CapBnd:" a hexadecimal mask, "NoNewPrivs:" 0 or 1.
// Each must appear exactly once.
func ParseStatus(b []byte) (Status, error) {
	var s Status
	if len(b) > maxStatusBytes {
		return s, fmt.Errorf("status is larger than %d bytes", maxStatusBytes)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "Uid", "CapBnd", "NoNewPrivs":
		default:
			continue
		}
		if seen[k] {
			return s, fmt.Errorf("status field %s is repeated", k)
		}
		seen[k] = true
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			f := strings.Fields(v)
			if len(f) != 4 {
				return s, fmt.Errorf("status Uid has %d fields, want 4", len(f))
			}
			for i, x := range f {
				n, err := strconv.ParseUint(x, 10, 32)
				if err != nil {
					return s, fmt.Errorf("status Uid field %d: %w", i, err)
				}
				s.UIDs[i] = uint32(n)
			}
		case "CapBnd":
			n, err := strconv.ParseUint(v, 16, 64)
			if err != nil {
				return s, fmt.Errorf("status CapBnd: %w", err)
			}
			s.CapBnd = n
		case "NoNewPrivs":
			switch v {
			case "0":
			case "1":
				s.NoNewPrivs = true
			default:
				return s, fmt.Errorf("status NoNewPrivs is %q", v)
			}
		}
	}
	for _, k := range []string{"Uid", "CapBnd", "NoNewPrivs"} {
		if !seen[k] {
			return s, fmt.Errorf("status has no %s field", k)
		}
	}
	return s, nil
}

// Process requires uid 0 (real, effective, saved and filesystem) and
// NoNewPrivs 1 (set by the unit's NoNewPrivileges=yes).
func Process(s *Status) error {
	for _, id := range s.UIDs {
		if id != 0 {
			return &Error{CheckUID, fmt.Sprintf("not running as root (uids %v)", s.UIDs)}
		}
	}
	if !s.NoNewPrivs {
		return &Error{CheckNoNewPrivs, "NoNewPrivs is not 1: the helper runs only under its generated unit"}
	}
	return nil
}

// CapabilityMask returns the bit mask of capability names.
func CapabilityMask(names []string) (uint64, error) {
	var m uint64
	for _, n := range names {
		b, ok := policy.CapabilityNumber(n)
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		m |= 1 << b
	}
	return m, nil
}

// Capabilities requires the bounding set to be a subset of the unit's
// (the policy's computed set; systemd may drop more, never add).
func Capabilities(s *Status, unit []string) error {
	m, err := CapabilityMask(unit)
	if err != nil {
		return &Error{CheckCapabilities, err.Error()}
	}
	if extra := s.CapBnd &^ m; extra != 0 {
		return &Error{CheckCapabilities, fmt.Sprintf("bounding set %016x is broader than the unit's %016x (extra %016x)", s.CapBnd, m, extra)}
	}
	return nil
}

// Stdin requires fd to be a connected AF_UNIX stream socket (the unit's
// StandardInput=socket with Accept=yes).
func Stdin(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &Error{CheckStdin, "stdin cannot be inspected: " + err.Error()}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return &Error{CheckStdin, "stdin is not a socket"}
	}
	dom, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || dom != unix.AF_UNIX {
		return &Error{CheckStdin, "stdin is not an AF_UNIX socket"}
	}
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typ != unix.SOCK_STREAM {
		return &Error{CheckStdin, "stdin is not a stream socket"}
	}
	if _, err := unix.Getpeername(fd); err != nil {
		return &Error{CheckStdin, "stdin is not a connected socket"}
	}
	return nil
}

// Binary requires the helper binary and its directories to be owned by a
// trusted uid (root in production) and not group/other-writable.
func Binary(t gpolicy.Trust, exe string) error {
	rp, err := gpolicy.CheckChain(t, exe)
	if err != nil {
		return &Error{CheckBinary, "helper binary: " + err.Error()}
	}
	fi, err := os.Stat(rp)
	if err != nil {
		return &Error{CheckBinary, "helper binary: " + gpolicy.ErrReason(err)}
	}
	if err := gpolicy.CheckFile(t, rp, fi); err != nil {
		return &Error{CheckBinary, "helper binary: " + err.Error()}
	}
	return nil
}

// Hash requires the policy's SHA-256 to equal the unit's
// SHELL_MCP_PRIVD_POLICY_SHA256 (a policy edited without regenerating the
// units fails closed, PRIVILEGED §2).
func Hash(policySHA256, env string) error {
	if len(policySHA256) != 64 || len(env) != 64 || subtle.ConstantTimeCompare([]byte(policySHA256), []byte(env)) != 1 {
		return &Error{CheckPolicyHash, "the policy's SHA-256 does not match the unit's SHELL_MCP_PRIVD_POLICY_SHA256; regenerate and reinstall the units"}
	}
	return nil
}

// maxUnitValue bounds how much of a malformed unit value reaches the audit.
const maxUnitValue = 32

// UnitClientUID parses the unit's SHELL_MCP_PRIVD_CLIENT_UID, the only
// input to the peer check: exactly one canonical decimal uid in
// 1..4294967294 — no sign, space or leading zero. Root is never the
// client, and 4294967295 is (uid_t)-1.
func UnitClientUID(env string) (uint32, error) {
	ok := env != "" && len(env) <= 10 && env[0] != '0'
	for i := 0; ok && i < len(env); i++ {
		ok = env[i] >= '0' && env[i] <= '9'
	}
	var n uint64
	if ok {
		var err error
		n, err = strconv.ParseUint(env, 10, 32)
		ok = err == nil && n != math.MaxUint32
	}
	if !ok {
		shown := env
		if len(shown) > maxUnitValue {
			shown = shown[:maxUnitValue] + "..."
		}
		return 0, &Error{CheckUnitClientUID, fmt.Sprintf("the unit's SHELL_MCP_PRIVD_CLIENT_UID is %q, not a uid in 1..4294967294; regenerate and reinstall the units (shell-mcp-privd units)", shown)}
	}
	return uint32(n), nil
}

// ClientUID requires the policy's client_uid to be the unit's (the unit is
// generated from the policy; a difference is a hand-edited unit).
func ClientUID(policyUID, unitUID uint32) error {
	if policyUID != unitUID {
		return &Error{CheckClientUID, fmt.Sprintf("the policy's client_uid %d is not the unit's SHELL_MCP_PRIVD_CLIENT_UID %d; regenerate and reinstall the units", policyUID, unitUID)}
	}
	return nil
}

// Unit parses the unit's SHELL_MCP_PRIVD_UNIT: exactly "core" or "broad".
func Unit(env string) (policy.Unit, error) {
	switch u := policy.Unit(env); u {
	case policy.UnitCore, policy.UnitBroad:
		return u, nil
	}
	shown := env
	if len(shown) > maxUnitValue {
		shown = shown[:maxUnitValue] + "..."
	}
	return "", &Error{CheckUnit, fmt.Sprintf("the unit's SHELL_MCP_PRIVD_UNIT is %q, not core or broad; regenerate and reinstall the units (shell-mcp-privd units)", shown)}
}

// Capabilities the broad unit's directives drop from root's bounding set
// (systemd.exec(5)): ProtectKernelModules=yes drops CAP_SYS_MODULE;
// ProtectClock=yes drops CAP_SYS_TIME and CAP_WAKE_ALARM.
const (
	capSysModule  = 16
	capSysTime    = 25
	capWakeAlarm  = 35
	allCapsMask   = ^uint64(0)
	broadDropMask = uint64(1) << capSysModule
	clockDropMask = uint64(1)<<capSysTime | uint64(1)<<capWakeAlarm
)

// BroadCapabilities requires the broad unit's bounding set to be no broader
// than its directives leave: root's full set without CAP_SYS_MODULE, and
// without CAP_SYS_TIME and CAP_WAKE_ALARM while it keeps ProtectClock=yes.
func BroadCapabilities(s *Status, protectClock bool) error {
	m := allCapsMask &^ broadDropMask
	if protectClock {
		m &^= clockDropMask
	}
	if extra := s.CapBnd &^ m; extra != 0 {
		return &Error{CheckCapabilities, fmt.Sprintf("bounding set %016x is broader than the broad unit's %016x (extra %016x)", s.CapBnd, m, extra)}
	}
	return nil
}
