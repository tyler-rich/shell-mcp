//go:build linux

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged helper's delete backs up exactly what it will remove,
// from the plan the deletion then walks (handoff
// docs/handoff/S4C-PRIVILEGED.md D10; PRIVILEGED §6): no directory is read
// again. A file is backed up through a descriptor opened by its name from
// its parent's handle (O_NOFOLLOW) whose statx must show the object the
// walk saw, with the same size and change time; after the backup has read
// it, the name must still show that object unchanged. A directory is
// re-opened from its parent's handle and must have the walk's identity
// (inSubdir). Only directories and regular files can be backed up: a
// symlink, FIFO or socket in the plan is backup_failed, and nothing is
// removed. Every refusal here is made before anything is removed, so it is
// provably unchanged.
//
// The deletion's own first check of each entry (stillListed) then requires
// the same size and change time again: a file written after the backup
// read it stops the deletion before that entry is removed. What remains is
// POLICY §3's third case: a write through a descriptor opened earlier,
// after the entry's last check, lands in an inode that is then removed,
// and the backup holds the content as it read it.

// statInfo is an fs.FileInfo of a plan entry, from the walk's statx (the
// backup's tar headers and metadata take the mode, owner, size and
// modification time from it).
type statInfo struct {
	name string
	id   ident
}

func (s *statInfo) Name() string { return s.name }
func (s *statInfo) Size() int64  { return s.id.size }
func (s *statInfo) IsDir() bool  { return s.id.isDir() }
func (s *statInfo) Sys() any {
	return &syscall.Stat_t{Dev: s.id.dev, Ino: s.id.ino, Mode: s.id.typ | s.id.perm, Uid: s.id.uid, Gid: s.id.gid, Size: s.id.size}
}

func (s *statInfo) ModTime() time.Time {
	return time.Unix(s.id.mtime.Sec, int64(s.id.mtime.Nsec))
}

func (s *statInfo) Mode() fs.FileMode {
	m := fs.FileMode(s.id.perm & 0o777)
	if s.id.perm&unix.S_ISUID != 0 {
		m |= fs.ModeSetuid
	}
	if s.id.perm&unix.S_ISGID != 0 {
		m |= fs.ModeSetgid
	}
	if s.id.perm&unix.S_ISVTX != 0 {
		m |= fs.ModeSticky
	}
	switch s.id.typ {
	case unix.S_IFDIR:
		m |= fs.ModeDir
	case unix.S_IFLNK:
		m |= fs.ModeSymlink
	case unix.S_IFIFO:
		m |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		m |= fs.ModeSocket
	case unix.S_IFCHR:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFBLK:
		m |= fs.ModeDevice
	}
	return m
}

func (e *planEntry) info() fs.FileInfo { return &statInfo{name: e.name, id: e.id} }

// source describes what the plan's delete backs up: the file, or the tree
// beneath the target with List over the plan (no descriptor is opened).
// The delete adds File or Walk.
func (pl *plan) source() *BackupSource {
	src := &BackupSource{Path: pl.l.p, Kind: BackupFile, Info: pl.top.info()}
	if pl.top.id.isDir() {
		src.Kind, src.Count = BackupTree, pl.entries-1
		src.List = func(visit func(rel string, fi fs.FileInfo) error) error { return listPlan(pl.top, "", visit) }
	}
	return src
}

// listPlan visits node's entries in walk order (pre-order, names sorted).
func listPlan(node *planEntry, rel string, visit func(rel string, fi fs.FileInfo) error) error {
	for _, k := range node.kids {
		r := joinRel(rel, k.name)
		if err := visit(r, k.info()); err != nil {
			return err
		}
		if k.id.isDir() {
			if err := listPlan(k, r, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinRel(rel, name string) string {
	if rel == "" {
		return name
	}
	return rel + "/" + name
}

func errNotBackedUp() *Error {
	return errf(protocol.CodeBackupFailed, "the tree holds a symlink or special file, which cannot be backed up, so it is not deleted while backups are on")
}

// backupPlan hands the plan to Config.Backup before anything is removed.
func (f *FS) backupPlan(pl *plan) error {
	src := pl.source()
	if !pl.top.id.isDir() {
		if pl.top.id.typ != unix.S_IFREG {
			return errf(protocol.CodeBackupFailed, "only regular files and directories can be backed up, so this is not deleted while backups are on")
		}
		return withFD(pl.parent, func(pfd int) error {
			f.step(DeleteStepBeforeBackupEntry, pl.top.lp)
			file, err := openPlanned(pfd, pl.top)
			if err != nil {
				return err
			}
			defer func() { _ = file.Close() }()
			src.File = file
			if err := f.cfg.Backup(src); err != nil {
				return backupErr(err)
			}
			return stillPlanned(pfd, pl.top)
		})
	}
	src.Walk = func(visit func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error) error {
		return f.inSubdir(pl.l, pl.l.parent, pl.top, func(sub *os.Root, sfd int) error {
			return f.backupDir(pl, sub, sfd, pl.top, "", visit)
		})
	}
	if err := f.cfg.Backup(src); err != nil {
		return backupErr(err)
	}
	return nil
}

// backupDir visits node's entries (node is open as dir, descriptor dfd) in
// walk order, re-opening each directory from its parent's handle with the
// walk's identity.
func (f *FS) backupDir(pl *plan, dir *os.Root, dfd int, node *planEntry, rel string,
	visit func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error,
) error {
	for _, k := range node.kids {
		r := joinRel(rel, k.name)
		switch k.id.typ {
		case unix.S_IFDIR:
			if err := visit(r, k.info(), nil); err != nil {
				return err
			}
			if err := f.inSubdir(pl.l, dir, k, func(sub *os.Root, sfd int) error {
				return f.backupDir(pl, sub, sfd, k, r, visit)
			}); err != nil {
				return err
			}
		case unix.S_IFREG:
			f.step(DeleteStepBeforeBackupEntry, k.lp)
			if err := visit(r, k.info(), func() (*os.File, error) { return openPlanned(dfd, k) }); err != nil {
				return err
			}
			if err := stillPlanned(dfd, k); err != nil {
				return err
			}
		default:
			return errNotBackedUp()
		}
	}
	return nil
}

func errReplacedBeforeBackup() *Error {
	return errf(protocol.CodeExists, "an entry of the preview was replaced or changed while it was being backed up; nothing was deleted")
}

// openPlanned opens e, a regular file in the directory dfd, by its name
// without following a symlink, and requires the object the walk saw, with
// the same size and change time.
func openPlanned(dfd int, e *planEntry) (*os.File, error) {
	fd, err := unix.Openat(dfd, e.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ELOOP):
		return nil, errReplacedBeforeBackup()
	case err != nil:
		return nil, mapErr(&fs.PathError{Op: "openat", Path: e.lp, Err: err})
	}
	file := os.NewFile(uintptr(fd), e.lp)
	id, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil || id.typ != unix.S_IFREG || !id.unchanged(&e.id) {
		_ = file.Close()
		return nil, errReplacedBeforeBackup()
	}
	return file, nil
}

// stillPlanned: after the backup read it, e's name still shows the object
// the walk saw, unchanged.
func stillPlanned(dfd int, e *planEntry) error {
	id, err := statxAt(dfd, e.name, 0)
	if err != nil || !id.unchanged(&e.id) {
		return errReplacedBeforeBackup()
	}
	return nil
}

// unchangedErr marks err, a refusal made before anything was changed, as
// provably unchanged (Error.Unchanged).
func unchangedErr(err error) error {
	var fe *Error
	if errors.As(err, &fe) {
		fe.Unchanged = true
		return fe
	}
	if me := mapErr(err); me != nil {
		return unchanged(me)
	}
	return err
}
