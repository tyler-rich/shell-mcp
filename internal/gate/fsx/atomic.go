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
		return unchanged(errf(protocol.CodeExists, "destination exists"))
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.ENOSYS):
		return unchanged(errf(protocol.CodeBadRequest, "the filesystem refused the hard link that commits a create-only write "+
			"(it may not support hard links), so an existing destination could not be refused atomically; nothing was written"))
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
		err = renameat2(srcDir, srcName, dstDir, dstName, unix.RENAME_NOREPLACE)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EEXIST):
		return unchanged(errf(protocol.CodeExists, "destination exists"))
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
		return unchanged(errf(protocol.CodeBadRequest, "the filesystem does not support RENAME_NOREPLACE, which a move without "+
			"overwrite needs to refuse an existing destination atomically; nothing was moved"))
	}
	return mapErr(err)
}

func singleComponent(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// Verified replaces: every replace in the helper (Config.VerifyReplaced),
// and in the gate every replace bound to the destination's content (a
// write with expected_sha256, a copy or move with
// expected_destination_sha256). Linux has no conditional rename-over:
// rename(2) replaces whatever is under the name at that moment, so a
// destination replaced or rewritten after the last check would be lost
// (and in the helper the backup would not hold what was replaced). Instead
// the commit exchanges the new file and the destination (renameat2 with
// RENAME_EXCHANGE, atomic), then checks the inode it took out: it must be
// the one that was checked (and backed up) (same inode, size and mtime);
// anything else is exchanged back and the operation refused with exists.
// Only then is the old inode's name removed. What remains is POLICY §3's
// case for a delete: a process that holds the old file open for writing
// and writes through that descriptor after the check (a few system calls)
// writes into an inode that is then removed; and a process with write
// access to the directory that swaps the exchanged-out name in the moment
// between the exchange and its check (it could replace the destination
// itself). A filesystem without RENAME_EXCHANGE is refused, never replaced
// unchecked.

// exchangeVerified commits a replace of dstName in dstDir by srcName in
// srcDir (the new file: a temp file, or a move's source), verified against
// want, the destination as last checked.
func (f *FS) exchangeVerified(srcDir *os.Root, srcName string, dstDir *os.Root, dstName string, want fs.FileInfo) *Error {
	if !singleComponent(srcName) || !singleComponent(dstName) {
		return errf(protocol.CodeInternal, "rename names must be single path components")
	}
	var err error
	if f.cfg.InjectExchangeFault != nil {
		err = f.cfg.InjectExchangeFault()
	} else {
		err = renameat2(srcDir, srcName, dstDir, dstName, unix.RENAME_EXCHANGE)
	}
	switch {
	case err == nil:
	case errors.Is(err, syscall.ENOENT):
		return unchanged(errf(protocol.CodeNotFound, "the destination disappeared before the commit; nothing was replaced"))
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
		return unchanged(errf(protocol.CodeBadRequest, "the filesystem does not support RENAME_EXCHANGE, which a verified replace needs "+
			"to refuse a destination that changed after it was checked; nothing was replaced"))
	default:
		return mapErr(err)
	}
	got, err := srcDir.Lstat(srcName)
	if err != nil || !got.Mode().IsRegular() || !os.SameFile(got, want) || got.Size() != want.Size() || !got.ModTime().Equal(want.ModTime()) {
		if berr := renameat2(srcDir, srcName, dstDir, dstName, unix.RENAME_EXCHANGE); berr != nil {
			f.commit() // the new file stays at the destination
			return errf(protocol.CodeInternal, "the destination changed after it was checked, and could not be put back: the new file is at the "+
				"destination and the other one is under the name %q beside the source", srcName)
		}
		return unchanged(errf(protocol.CodeExists, "the destination changed after it was checked; it was not replaced, and nothing was changed"))
	}
	f.commit()
	if err := srcDir.Remove(srcName); err != nil {
		return errf(protocol.CodeInternal, "the destination was replaced, but its previous version could not be removed from the name %q beside the source", srcName)
	}
	return nil
}

// renameat2 runs renameat2(2) with flags between the descriptors of two
// os.Roots' directories.
func renameat2(srcDir *os.Root, srcName string, dstDir *os.Root, dstName string, flags uint) error {
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
			rerr = unix.Renameat2(sfd, srcName, dfd, dstName, flags)
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

// ErrExchangeUnsupported is ProbeExchange's answer for a filesystem without
// RENAME_EXCHANGE.
var ErrExchangeUnsupported = errors.New("the filesystem does not support RENAME_EXCHANGE")

// ProbeExchange reports whether dir's filesystem supports RENAME_EXCHANGE,
// which verified replaces need (the helper's, and the gate's bound ones): it creates
// two files inside dir, exchanges them and removes both, as ProbeNoReplace
// does for RENAME_NOREPLACE.
func ProbeExchange(dir string) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	a, b := probePrefix+randHex(16), probePrefix+randHex(16)
	for _, n := range []string{a, b} {
		fh, oerr := r.OpenFile(n, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			_ = r.Remove(a)
			return oerr
		}
		if err = fh.Close(); err != nil {
			_ = r.Remove(a)
			_ = r.Remove(b)
			return err
		}
	}
	defer func() { _ = r.Remove(a); _ = r.Remove(b) }()
	err = renameat2(r, a, r, b, unix.RENAME_EXCHANGE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
		return ErrExchangeUnsupported
	}
	return err
}
