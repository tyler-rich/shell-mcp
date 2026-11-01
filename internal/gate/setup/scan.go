//go:build linux

package setup

import (
	"errors"
)

// Mount is one /proc/self/mountinfo line's mount point and filesystem type.
type Mount struct {
	Point  string
	FSType string
}

// maxMounts bounds mountinfo (a container host can have thousands).
const maxMounts = 1 << 16

// ErrMountinfo is malformed /proc/self/mountinfo.
var ErrMountinfo = errors.New("malformed mountinfo")

// ParseMountinfo parses /proc/self/mountinfo (proc_pid_mountinfo(5)): the
// mount point is field 5 (octal escapes \040 and the like decoded), the
// filesystem type the first field after the " - " separator.
func ParseMountinfo(b []byte) ([]Mount, error) {
	var stub0 []Mount
	var stub1 error
	return stub0, stub1
}

// unescapeMount decodes mountinfo's \ooo octal escapes.
func unescapeMount(s string) (string, error) { var stub0 string; var stub1 error; return stub0, stub1 }

// skippedFS are the pseudo filesystems (no files an account owns) and the
// network ones (another host's files, and a walk that can hang), which the
// owner scan lists and does not walk. Every fuse.* type is skipped too: a
// FUSE filesystem may be remote.
var skippedFS = []string{
	"proc", "sysfs", "cgroup", "cgroup2", "devpts", "devtmpfs", "mqueue", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
	"configfs", "fusectl", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "rpc_pipefs", "nsfs", "selinuxfs",
	"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "afs", "davfs", "lustre", "gfs2", "ocfs2",
}

func skipped(t string) bool { var stub0 bool; return stub0 }

// errHit stops a walk at the first owned entry.
type errHit struct{ path string }

func (e *errHit) Error() string { var stub0 string; return stub0 }

// ownerScan is TARGET-SETUP §4's free-id find: every local filesystem of
// mounts walked on its own device (find -xdev), or only paths when given,
// stopping at the first entry owned by one of uids or gids.
func ownerScan(mounts []Mount, uids, gids []uint32, paths []string) (ScanResult, error) {
	var stub0 ScanResult
	var stub1 error
	return stub0, stub1
}

// A mount point that went away, or that this process cannot
// reach: it is not walked, and says so.

// Entries that vanish or cannot be listed mid-walk are
// skipped, as find does.
