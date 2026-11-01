//go:build linux

package setup

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
	var out []Mount
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "" {
			continue
		}
		left, right, ok := strings.Cut(l, " - ")
		f, r := strings.Fields(left), strings.Fields(right)
		if !ok || len(f) < 5 || len(r) < 1 {
			return nil, fmt.Errorf("%w: %.80q", ErrMountinfo, l)
		}
		p, err := unescapeMount(f[4])
		if err != nil || !filepath.IsAbs(p) {
			return nil, fmt.Errorf("%w: mount point %.80q", ErrMountinfo, f[4])
		}
		if len(out) == maxMounts {
			return nil, fmt.Errorf("%w: more than %d mounts", ErrMountinfo, maxMounts)
		}
		out = append(out, Mount{Point: p, FSType: r[0]})
	}
	return out, nil
}

// unescapeMount decodes mountinfo's \ooo octal escapes.
func unescapeMount(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", ErrMountinfo
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", ErrMountinfo
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}

// skippedFS are the pseudo filesystems (no files an account owns) and the
// network ones (another host's files, and a walk that can hang), which the
// owner scan lists and does not walk. Every fuse.* type is skipped too: a
// FUSE filesystem may be remote.
var skippedFS = []string{
	"proc", "sysfs", "cgroup", "cgroup2", "devpts", "devtmpfs", "mqueue", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
	"configfs", "fusectl", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "rpc_pipefs", "nsfs", "selinuxfs",
	"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "afs", "davfs", "lustre", "gfs2", "ocfs2",
}

func skipped(t string) bool { return slices.Contains(skippedFS, t) || strings.HasPrefix(t, "fuse.") }

// errHit stops a walk at the first owned entry.
type errHit struct{ path string }

func (e *errHit) Error() string { return "owned: " + e.path }

// ownerScan is TARGET-SETUP §4's free-id find: every local filesystem of
// mounts walked on its own device (find -xdev), or only paths when given,
// stopping at the first entry owned by one of uids or gids.
func ownerScan(mounts []Mount, uids, gids []uint32, paths []string) (ScanResult, error) {
	var res ScanResult
	var local []string
	for _, m := range mounts {
		if skipped(m.FSType) {
			res.Skipped = append(res.Skipped, m.Point+" ("+m.FSType+")")
			continue
		}
		if !slices.Contains(local, m.Point) {
			local = append(local, m.Point)
		}
	}
	slices.Sort(res.Skipped)
	res.Skipped = slices.Compact(res.Skipped)
	roots := local
	if len(paths) > 0 {
		roots = paths
		for _, l := range local {
			if !slices.Contains(paths, l) {
				res.NotCovered = append(res.NotCovered, l)
			}
		}
	}
	owned := func(st *syscall.Stat_t) bool { return slices.Contains(uids, st.Uid) || slices.Contains(gids, st.Gid) }
	for _, root := range roots {
		var rst syscall.Stat_t
		if err := syscall.Lstat(root, &rst); err != nil {
			// A mount point that went away, or that this process cannot
			// reach: it is not walked, and says so.
			res.Skipped = append(res.Skipped, root+" (cannot be read: "+err.Error()+")")
			continue
		}
		res.Walked = append(res.Walked, root)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				// Entries that vanish or cannot be listed mid-walk are
				// skipped, as find does.
				if d != nil && d.IsDir() && p != root {
					return fs.SkipDir
				}
				return nil
			}
			var st syscall.Stat_t
			if err := syscall.Lstat(p, &st); err != nil {
				return nil
			}
			if st.Dev != rst.Dev {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if owned(&st) {
				return &errHit{p}
			}
			return nil
		})
		var hit *errHit
		if errors.As(err, &hit) {
			res.Hit = hit.path
			return res, nil
		}
		if err != nil {
			return res, err
		}
	}
	return res, nil
}
