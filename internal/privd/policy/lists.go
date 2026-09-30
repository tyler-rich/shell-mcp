//go:build linux

package policy

// neverPaths is PRIVILEGED §5.3 list A as paths: never a write root, never
// inside one, never contained by one, never written by any operation, in
// any policy. The helper's running binary and the policy file join it at
// load time. Patterns follow internal/pathx (POLICY §3 glob rules).
var neverPaths = []string{
	// Identity and access: users, groups, passwords, sudoers, PAM, SSH
	// server configuration and keys, any authorized_keys, polkit rules.
	"/etc/passwd", "/etc/passwd-", "/etc/group", "/etc/group-", "/etc/shadow*", "/etc/gshadow*",
	"/etc/subuid*", "/etc/subgid*",
	"/etc/sudoers", "/etc/sudoers.d", "/etc/pam.conf", "/etc/pam.d", "/etc/security",
	"/etc/ssh", "/root/.ssh", "/home/*/.ssh", "**/.ssh", "**/authorized_keys", "**/authorized_keys2",
	"/etc/polkit-1", "/usr/share/polkit-1",
	// This project's trust anchors: policies, binaries (at their documented
	// paths and under any name of theirs), the helper's units, its socket
	// directory, and the backup store.
	"/etc/shell-mcp", "/run/shell-mcp", "/var/lib/shell-mcp",
	"/usr/local/bin/shell-mcp-gate", "/usr/local/libexec/shell-mcp-privd",
	"**/shell-mcp-gate", "**/shell-mcp-privd",
	"/etc/systemd/system/shell-mcp-privd*", "/etc/systemd/system/*.wants/shell-mcp-privd*", "/etc/systemd/system/*.requires/shell-mcp-privd*",
	"/run/systemd/system/shell-mcp-privd*", "/run/systemd/system/*.wants/shell-mcp-privd*", "/run/systemd/system/*.requires/shell-mcp-privd*",
	"/usr/lib/systemd/system/shell-mcp-privd*", "/lib/systemd/system/shell-mcp-privd*",
}

// capabilityNumbers are the capabilities PRIVILEGED §4 lets a command add,
// with their numbers (linux/capability.h), plus the core unit's base set.
var capabilityNumbers = map[string]int{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2, "CAP_FOWNER": 3,
	"CAP_KILL": 5, "CAP_NET_BIND_SERVICE": 10, "CAP_NET_ADMIN": 12, "CAP_SYS_ADMIN": 21,
	"CAP_SYS_BOOT": 22, "CAP_SYS_TIME": 25,
}

// declarable are the capabilities a command may add (PRIVILEGED §4).
var declarable = []string{"CAP_SYS_BOOT", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_SYS_TIME", "CAP_KILL", "CAP_SYS_ADMIN"}

// brokenInCore are declarable capabilities that have no effect in the core
// unit (PRIVILEGED §5.1): ProtectClock=yes removes CAP_SYS_TIME from the
// bounding set and filters @clock, and PrivateNetwork=yes with
// RestrictAddressFamilies=AF_UNIX leaves the network capabilities nothing
// to act on. They are valid only on `unit: broad` commands (S1d).
var brokenInCore = map[string]string{
	"CAP_SYS_TIME":         "ProtectClock=yes removes it from the core unit's bounding set",
	"CAP_NET_ADMIN":        "the core unit has a private network namespace and only AF_UNIX sockets",
	"CAP_NET_BIND_SERVICE": "the core unit has a private network namespace and only AF_UNIX sockets",
}

// CapabilityNumber returns a capability's number, if it is one the helper
// knows (the base set or a declarable one).
func CapabilityNumber(name string) (int, bool) {
	n, ok := capabilityNumbers[name]
	return n, ok
}

// NeverPaths returns list A's path patterns (without the host-specific
// additions made at load time).
func NeverPaths() []string { return append([]string(nil), neverPaths...) }
