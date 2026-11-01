// Package setup is shell-mcp-gate install and shell-mcp-gate host-key
// (docs/TARGET-SETUP.md §12.1, §12.2): the service account and its groups,
// the slice drop-in, check-policy as the account, the polkit rule, the
// sshd drop-in and the key line, checked by sshd -T -C and rolled back on
// any difference, and the host-key pin. It reads and changes the host only
// through Host, whose only production implementation is the real host
// (NewHost); the unit tests drive Install with a fake. What it shares with
// shell-mcp-privd install is in internal/gate/setupx.
package setup

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Fixed paths (TARGET-SETUP §4, §7, §8).
const (
	GatePath       = "/usr/local/bin/shell-mcp-gate"
	SSHDir         = "/etc/ssh"
	SSHDropInDir   = "/etc/ssh/sshd_config.d"
	SSHDropIn      = "/etc/ssh/sshd_config.d/60-shell-mcp.conf"
	KeysDir        = "/etc/ssh/authorized_keys.d"
	SystemdDir     = "/etc/systemd/system"
	PolkitDir      = "/etc/polkit-1/rules.d"
	PolkitRule     = "/etc/polkit-1/rules.d/60-shell-mcp.rules"
	JournalGroup   = "systemd-journal"
	ServiceShell   = "/bin/sh"
	sliceDropIn    = "50-shell-mcp.conf"
	defaultUser    = "svc-shell"
	maxKeyFile     = 16 << 10
	maxKeysFile    = 1 << 20
	maxManagedFile = 1 << 20
)

// SliceDir is the account slice's drop-in directory.
func SliceDir(uid uint32) string {
	return fmt.Sprintf("%s/user-%d.slice.d", SystemdDir, uid)
}

// KeysFile is the account's keys file.
func KeysFile(user string) string { return KeysDir + "/" + user }

var (
	// nameRE is an account or group name (handoff §3.1).
	nameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// principalRE is --principal: sshd runs the forced command through
	// /bin/sh, so nothing a shell reads specially (handoff F-8).
	principalRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// pathRE is the characters a --policy (or --home) path may hold.
	pathRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// ErrUsage is a malformed flag (exit 2).
var ErrUsage = errors.New("usage")

// ValidName reports whether s is a plain account or group name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ValidPrincipal reports whether s is a --principal label.
func ValidPrincipal(s string) bool { return principalRE.MatchString(s) }

// CheckSafePath refuses a path that is not absolute and clean, holds a
// character outside A-Z a-z 0-9 . _ / -, or has a component starting with
// "-" (it would read as an option in an argv).
func CheckSafePath(what, p string) error {
	switch {
	case p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p:
		return fmt.Errorf("%s %q must be an absolute, clean path", what, p)
	case !pathRE.MatchString(p):
		return fmt.Errorf("%s %q holds characters other than A-Z a-z 0-9 . _ / - (sshd runs the forced command through /bin/sh)", what, p)
	case strings.Contains(p, "/-"):
		return fmt.Errorf("%s %q has a component starting with -", what, p)
	}
	return nil
}

// ParseID parses a decimal uid or gid: digits only, no sign, no leading
// zero, at most 32 bits.
func ParseID(s string) (uint32, error) {
	if s == "" || s[0] < '0' || s[0] > '9' || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%q is not a decimal id", s)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a decimal id", s)
	}
	return uint32(v), nil
}

// idRefusal says why id may not be the account's or a group's (D-020), or
// "": root's, nobody's (65534), below 1000 (distributions' system range),
// systemd's dynamic range 61184–65519, or the overflow id.
func idRefusal(what string, id uint32) string {
	switch {
	case id == 0:
		return fmt.Sprintf("%s 0 is root's", what)
	case id == 65534:
		return fmt.Sprintf("%s 65534 is nobody's", what)
	case id < 1000:
		return fmt.Sprintf("%s %d is in the system range below 1000; choose an explicit id of 1000 or above that nothing uses", what, id)
	case id >= 61184 && id <= 65519:
		return fmt.Sprintf("%s %d is in systemd's dynamic-user range 61184-65519", what, id)
	case id == 4294967295:
		return fmt.Sprintf("%s 4294967295 is the overflow id", what)
	}
	return ""
}
