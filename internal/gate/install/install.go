//go:build linux

// Package install implements the gate's install checks (docs/SECURITY.md §6,
// D-020): the gate refuses to serve (install_insecure) when it runs as root
// or as a trusted owner, belongs to a privileged group, is started with an
// unexpected SSH_ORIGINAL_COMMAND, or its own binary is not trusted-owned.
package install

import (
	"errors"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// DeniedGroups is the D-020 deny list. Membership in the helper's socket
// group and in systemd-journal is allowed.
var DeniedGroups = []string{"root", "sudo", "wheel", "adm", "docker", "lxd", "incus-admin", "libvirt", "kvm", "disk", "shadow"}

// Identity is the process's credentials as the checks see them.
type Identity struct {
	UID uint32
	// GIDs holds the real and effective group and every supplementary group.
	GIDs []uint32
	// GroupName resolves a gid to its name.
	GroupName func(gid uint32) (string, error)
}

// Current returns the running process's identity. Group names come from
// the system group database (pure Go: /etc/group).
func Current() (Identity, error) {
	return Identity{}, errors.New("not implemented")
}

// Env is everything the install checks look at.
type Env struct {
	Identity Identity
	Trust    policy.Trust
	// Executable is the gate binary's resolved path.
	Executable string
	// SSHOriginalCommand is the variable's value; nil when it is unset.
	SSHOriginalCommand *string
}

// Error is an install-check failure. Detail may name local paths and group
// names and is for local display; Wire is the one-line message for the
// response.
type Error struct {
	Wire   string
	Detail string
}

func (e *Error) Error() string { return e.Detail }

// Check runs every install check except the policy's (policy.Load).
func Check(env Env) error {
	return errors.New("not implemented")
}
