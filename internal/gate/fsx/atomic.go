//go:build linux

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Create-only commits (docs/POLICY.md §3): write_file with expect_absent,
// and copy and move without overwrite, refuse a destination that exists at
// the moment of the commit, not only when it was checked. There is never a
// fallback to check-then-rename: a filesystem that cannot refuse atomically
// is refused.
//
// Verified at the source (Go 1.27.2): os.Root has Link, which is linkat(2)
// with flags 0 between directory descriptors it resolved inside the root,
// but its Rename is renameat(2) with no flags argument, so RENAME_NOREPLACE
// is not reachable through it. Write and copy therefore commit with
// Root.Link; move, which must also handle directories (which cannot be hard
// linked) and must not unlink a source that was replaced meanwhile, calls
// renameat2(2) itself, on descriptors of the parent directories that locate
// opened through os.Root and verified, with single-component names only.

// linkNoReplace commits the temp file tmp as name in dir: link(2) fails
// with EEXIST if name exists (as anything, a symlink included, which it
// never follows).
func (f *FS) linkNoReplace(dir *os.Root, tmp, name string) *Error {
	var err error
	if f.cfg.InjectNoReplaceFault != nil {
		err = f.cfg.InjectNoReplaceFault()
	} else {
		err = dir.Link(tmp, name)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EEXIST):
		return errf(protocol.CodeExists, "destination exists")
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.ENOSYS):
		return errf(protocol.CodeBadRequest, "the filesystem refused the hard link that commits a create-only write "+
			"(it may not support hard links), so an existing destination could not be refused atomically; nothing was written")
	}
	return mapErr(err)
}

// renameNoReplace renames srcName in srcDir to dstName in dstDir with
// RENAME_NOREPLACE: EEXIST if dstName exists at that moment. Both
// directories are verified sub-roots from locate; the names are their
// targets' base names.
func (f *FS) renameNoReplace(srcDir *os.Root, srcName string, dstDir *os.Root, dstName string) *Error {
	if !singleComponent(srcName) || !singleComponent(dstName) {
		return errf(protocol.CodeInternal, "rename names must be single path components")
	}
	var err error
	if f.cfg.InjectNoReplaceFault != nil {
		err = f.cfg.InjectNoReplaceFault()
	} else {
		err = renameat2NoReplace(srcDir, srcName, dstDir, dstName)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EEXIST):
		return errf(protocol.CodeExists, "destination exists")
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
		return errf(protocol.CodeBadRequest, "the filesystem does not support RENAME_NOREPLACE, which a move without "+
			"overwrite needs to refuse an existing destination atomically; nothing was moved")
	}
	return mapErr(err)
}

func singleComponent(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// renameat2NoReplace runs renameat2(2) between the descriptors of two
// os.Roots' directories.
func renameat2NoReplace(srcDir *os.Root, srcName string, dstDir *os.Root, dstName string) error {
	sd, err := srcDir.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = sd.Close() }()
	dd, err := dstDir.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dd.Close() }()
	var rerr error
	err = withFD(sd, func(sfd int) error {
		return withFD(dd, func(dfd int) error {
			rerr = unix.Renameat2(sfd, srcName, dfd, dstName, unix.RENAME_NOREPLACE)
			return nil
		})
	})
	if err != nil {
		return err
	}
	if rerr != nil {
		return &fs.PathError{Op: "renameat2", Path: srcName, Err: rerr}
	}
	return nil
}

// withFD calls fn with f's descriptor, kept valid for the call.
func withFD(f *os.File, fn func(fd int) error) error {
	sc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := sc.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
}
