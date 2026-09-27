//go:build linux

// Package install implements the gate's install checks (docs/SECURITY.md §6,
// D-020): the gate refuses to serve (install_insecure) when it runs as root
// or as a trusted owner, belongs to a privileged group, is started with an
// unexpected SSH_ORIGINAL_COMMAND, or its own binary is not trusted-owned.
package install

import (
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
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
// the system group database (pure Go with CGO_ENABLED=0: /etc/group only,
// so the service account's groups must be local, as D-020 requires).
func Current() (Identity, error) {
	sup, err := os.Getgroups()
	if err != nil {
		return Identity{}, fmt.Errorf("getgroups: %w", err)
	}
	gids := []uint32{uint32(os.Getgid()), uint32(os.Getegid())}
	for _, g := range sup {
		gids = append(gids, uint32(g))
	}
	return Identity{
		UID:  uint32(os.Getuid()),
		GIDs: gids,
		GroupName: func(gid uint32) (string, error) {
			g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
			if err != nil {
				return "", err
			}
			return g.Name, nil
		},
	}, nil
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
	id := env.Identity
	if id.UID == 0 {
		return &Error{"gate is running as root", "gate process runs as uid 0"}
	}
	if env.Trust.Owns(id.UID) {
		return &Error{"gate is running as the owner of its policy", fmt.Sprintf("gate process uid %d is a trusted owner of the policy and binaries", id.UID)}
	}
	if id.GroupName == nil {
		return &Error{"gate cannot resolve its groups", "no group resolver"}
	}
	seen := map[uint32]bool{}
	for _, gid := range id.GIDs {
		if seen[gid] {
			continue
		}
		seen[gid] = true
		if gid == 0 {
			return &Error{"gate process belongs to a privileged group", "gate process belongs to gid 0 (root)"}
		}
		name, err := id.GroupName(gid)
		if err != nil {
			return &Error{"gate cannot resolve one of its groups", fmt.Sprintf("group id %d has no name in the group database", gid)}
		}
		if slices.Contains(DeniedGroups, name) {
			return &Error{"gate process belongs to a privileged group", fmt.Sprintf("gate process belongs to group %q (gid %d), which D-020 forbids", name, gid)}
		}
	}
	if env.SSHOriginalCommand != nil && *env.SSHOriginalCommand != protocol.Hello {
		return &Error{"unexpected SSH_ORIGINAL_COMMAND", "SSH_ORIGINAL_COMMAND is set and is not " + protocol.Hello}
	}
	real, err := policy.CheckChain(env.Trust, env.Executable)
	if err != nil {
		return &Error{"gate binary ownership or permissions are insecure", "gate binary: " + err.Error()}
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return &Error{"gate binary is not a regular file", "gate binary " + real + " is not a regular file"}
	}
	return nil
}
