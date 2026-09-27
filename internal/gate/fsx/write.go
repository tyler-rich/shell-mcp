//go:build linux

package fsx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

const (
	defaultFileMode = 0o640
	defaultDirMode  = 0o750
	tempPrefix      = ".shell-mcp-"
)

// WriteFile atomically writes content to p under a write root.
func (f *FS) WriteFile(p string, content []byte, o WriteOptions) (WriteResult, error) {
	if len(content) > f.cfg.Limits.MaxWriteBytes {
		return WriteResult{}, errf(protocol.CodeTooLarge, "content exceeds max_write_bytes (%d)", f.cfg.Limits.MaxWriteBytes)
	}
	if o.Mode != nil {
		if e := checkMode(*o.Mode); e != nil {
			return WriteResult{}, e
		}
	}
	if o.ExpectedSHA256 != "" && !isSHA256Hex(o.ExpectedSHA256) {
		return WriteResult{}, errf(protocol.CodeBadRequest, "expected_sha256 must be 64 lowercase hex characters")
	}
	l, err := f.locate(p, true)
	if err != nil {
		return WriteResult{}, err
	}
	defer l.close()
	if l.parent == nil {
		return WriteResult{}, errf(protocol.CodeIsADirectory, "is a directory")
	}
	return f.writeAtomic(l, content, o.Mode, defaultFileMode, o.Create, true, o.ExpectedSHA256)
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func countLines(b []byte) int {
	n := bytes.Count(b, []byte("\n"))
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// writeAtomic writes content to l's target: a temp file in the same
// directory (through the parent's os.Root), fsync, rename over the target,
// fsync the directory, then re-open the target and compare SHA-256. An
// existing file keeps its mode (unless mode is given) and, where the
// service user may, its owner and group.
func (f *FS) writeAtomic(l *loc, content []byte, mode *os.FileMode, newMode os.FileMode, create, overwrite bool, expected string) (WriteResult, error) {
	res := WriteResult{Path: l.p}
	fi, err := l.parent.Lstat(l.base)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, mapErr(err)
	}
	var oldUID, oldGID uint32
	if exists {
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return res, errf(protocol.CodePathDenied, "final path component is a symlink")
		case fi.IsDir():
			return res, errf(protocol.CodeIsADirectory, "is a directory")
		case !fi.Mode().IsRegular():
			return res, errf(protocol.CodeBadRequest, "not a regular file")
		case !overwrite:
			return res, errf(protocol.CodeExists, "destination exists")
		}
		um := unixMode(fi)
		if um&0o7002 != 0 {
			return res, errf(protocol.CodePolicyDenied, "existing file has setuid, setgid, sticky or world-write bits")
		}
		old, err := f.openTarget(l, os.O_RDONLY|syscall.O_NONBLOCK)
		if err != nil {
			return res, err
		}
		h := sha256.New()
		lines := &lineCounter{}
		_, err = io.Copy(io.MultiWriter(h, lines), old)
		_ = old.Close()
		if err != nil {
			return res, mapErr(err)
		}
		res.OldSHA256 = hex.EncodeToString(h.Sum(nil))
		res.LinesOld = lines.total()
		if expected != "" && expected != res.OldSHA256 {
			return res, errf(protocol.CodeExists, "current content does not match expected_sha256")
		}
		newMode = os.FileMode(um)
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			oldUID, oldGID = st.Uid, st.Gid
		}
	} else {
		if !create {
			return res, errf(protocol.CodeNotFound, "file does not exist and create is false")
		}
		if expected != "" {
			return res, errf(protocol.CodeNotFound, "file does not exist but expected_sha256 was given")
		}
	}
	if mode != nil {
		newMode = *mode
	}

	tmp := tempPrefix + randHex(8) + ".tmp"
	tf, err := l.parent.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return res, mapErr(err)
	}
	committed, closed := false, false
	defer func() {
		if !closed {
			_ = tf.Close()
		}
		if !committed {
			_ = l.parent.Remove(tmp)
		}
	}()
	if _, err := tf.Write(content); err != nil {
		return res, mapErr(err)
	}
	if err := tf.Chmod(newMode); err != nil {
		return res, mapErr(err)
	}
	res.OwnerPreserved = true
	if exists {
		if tfi, err := tf.Stat(); err == nil {
			if st, ok := tfi.Sys().(*syscall.Stat_t); ok && (st.Uid != oldUID || st.Gid != oldGID) {
				res.OwnerPreserved = tf.Chown(int(oldUID), int(oldGID)) == nil
			}
		}
	}
	if err := tf.Sync(); err != nil {
		return res, mapErr(err)
	}
	closed = true
	if err := tf.Close(); err != nil {
		return res, mapErr(err)
	}
	if err := l.parent.Rename(tmp, l.base); err != nil {
		return res, mapErr(err)
	}
	committed = true
	if d, err := l.parent.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	// Read-back verification: a mismatch is a failure, never a warning.
	rf, err := f.openTarget(l, os.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return res, errf(protocol.CodeVerifyFailed, "written file could not be re-opened for verification")
	}
	back, err := io.ReadAll(io.LimitReader(rf, int64(len(content))+1))
	_ = rf.Close()
	if err != nil {
		return res, errf(protocol.CodeVerifyFailed, "written file could not be read back")
	}
	if f.cfg.InjectReadBackFault != nil {
		back = f.cfg.InjectReadBackFault(back)
	}
	res.SHA256 = sumHex(content)
	if sumHex(back) != res.SHA256 {
		return res, errf(protocol.CodeVerifyFailed, "read-back SHA-256 does not match what was written")
	}
	res.Bytes = len(content)
	res.Created = !exists
	res.Mode = fmt.Sprintf("%04o", uint32(newMode.Perm()))
	res.LinesNew = countLines(content)
	res.Verified = true
	return res, nil
}

type lineCounter struct {
	n    int
	last byte
	any  bool
}

func (c *lineCounter) Write(p []byte) (int, error) {
	c.n += bytes.Count(p, []byte("\n"))
	if len(p) > 0 {
		c.last, c.any = p[len(p)-1], true
	}
	return len(p), nil
}

func (c *lineCounter) total() int {
	if c.any && c.last != '\n' {
		return c.n + 1
	}
	return c.n
}

// Mkdir creates the directory p under a write root. With parents, missing
// ancestors are created one component at a time, each opened and verified
// before the next is created inside it.
func (f *FS) Mkdir(p string, mode *os.FileMode, parents bool) (MkdirResult, error) {
	m := os.FileMode(defaultDirMode)
	if mode != nil {
		if e := checkMode(*mode); e != nil {
			return MkdirResult{}, e
		}
		m = *mode
	}
	res := MkdirResult{Path: p, Mode: fmt.Sprintf("%04o", uint32(m))}
	if !parents {
		l, err := f.locate(p, true)
		if err != nil {
			return res, err
		}
		defer l.close()
		if l.parent == nil {
			return res, errf(protocol.CodeExists, "directory exists")
		}
		created, err := f.mkdirIn(l, l.parent, l.parentReal, l.base, m)
		if err != nil {
			return res, err
		}
		if !created {
			return res, errf(protocol.CodeExists, "already exists")
		}
		res.Created = true
		return res, nil
	}
	if err := pathx.CheckClean(p); err != nil {
		return res, errf(protocol.CodeBadRequest, "path must be absolute and clean: %v", err)
	}
	root, ok := pathx.Longest(f.cfg.WriteRoots, p)
	if !ok {
		return res, errf(protocol.CodePathDenied, "path is outside the policy's write roots")
	}
	if e := f.checkPath(p, true); e != nil {
		return res, e
	}
	top, err := os.OpenRoot(root)
	if err != nil {
		return res, mapErr(err)
	}
	defer top.Close()
	l := &loc{p: p, write: true, root: root, top: top}
	if l.rootReal, err = realPathOfRoot(top); err != nil {
		return res, mapErr(err)
	}
	rel := pathx.Rel(root, p)
	if rel == "." {
		return res, nil
	}
	cur, curReal := top, l.rootReal
	comps := strings.Split(rel, "/")
	for i, c := range comps {
		created, err := f.mkdirIn(l, cur, curReal, c, m)
		if err != nil {
			if cur != top {
				_ = cur.Close()
			}
			return res, err
		}
		if i == len(comps)-1 {
			res.Created = created
			if cur != top {
				_ = cur.Close()
			}
			break
		}
		next, nextReal, _, err := f.openSubdir(l, cur, join(curReal, c), c)
		if cur != top {
			_ = cur.Close()
		}
		if err != nil {
			return res, err
		}
		cur, curReal = next, nextReal
	}
	return res, nil
}

// mkdirIn creates name in dir unless it is already a directory, verifies
// it, and sets its mode (mkdir(2) is subject to the umask). It reports
// whether it created the directory.
func (f *FS) mkdirIn(l *loc, dir *os.Root, dirReal, name string, m os.FileMode) (bool, error) {
	fi, err := dir.Lstat(name)
	switch {
	case err == nil && fi.Mode()&fs.ModeSymlink != 0:
		return false, errf(protocol.CodePathDenied, "a path component is a symlink")
	case err == nil && !fi.IsDir():
		return false, errf(protocol.CodeNotADirectory, "a path component exists and is not a directory")
	case err == nil:
		return false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return false, mapErr(err)
	}
	if e := f.checkReal(l, join(dirReal, name), true); e != nil {
		return false, e
	}
	if err := dir.Mkdir(name, 0o700); err != nil {
		return false, mapErr(err)
	}
	sub, _, _, err := f.openSubdir(l, dir, join(dirReal, name), name)
	if err != nil {
		return true, err
	}
	defer sub.Close()
	d, err := sub.Open(".")
	if err != nil {
		return true, mapErr(err)
	}
	defer d.Close()
	if err := d.Chmod(m); err != nil {
		return true, mapErr(err)
	}
	return true, nil
}

// Copy copies the regular file src (any root) to dst (a write root). The
// copy is bounded by max_read_bytes, refused for files holding a private
// key, and read-back verified.
func (f *FS) Copy(src, dst string, overwrite bool) (WriteResult, error) {
	ls, err := f.locate(src, false)
	if err != nil {
		return WriteResult{}, err
	}
	defer ls.close()
	file, err := f.openTarget(ls, os.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return WriteResult{}, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return WriteResult{}, mapErr(err)
	}
	if fi.IsDir() {
		return WriteResult{}, errf(protocol.CodeIsADirectory, "copy handles regular files only")
	}
	if !fi.Mode().IsRegular() {
		return WriteResult{}, errf(protocol.CodeBadRequest, "copy handles regular files only")
	}
	limit := f.cfg.Limits.MaxReadBytes
	if fi.Size() > int64(limit) {
		return WriteResult{}, errf(protocol.CodeTooLarge, "source exceeds max_read_bytes (%d)", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return WriteResult{}, mapErr(err)
	}
	if len(data) > limit {
		return WriteResult{}, errf(protocol.CodeTooLarge, "source exceeds max_read_bytes (%d)", limit)
	}
	if redact.ContainsPrivateKey(data[:min(len(data), sniffKeyBytes)]) {
		return WriteResult{}, errf(protocol.CodePathDenied, "file contains a private key")
	}
	ld, err := f.locate(dst, true)
	if err != nil {
		return WriteResult{}, err
	}
	defer ld.close()
	if ld.parent == nil {
		return WriteResult{}, errf(protocol.CodeIsADirectory, "destination is a directory")
	}
	srcMode := os.FileMode(unixMode(fi)) &^ 0o7002
	return f.writeAtomic(ld, data, nil, srcMode, true, overwrite, "")
}

// Move renames src to dst. Both must be under the same write root; a
// directory is moved only if no entry in it is denied or protected at its
// old or new path. A rename within one directory goes through that
// directory's verified os.Root; otherwise through the root's, and the moved
// entry is then re-identified by device and inode.
func (f *FS) Move(src, dst string, overwrite bool) (MoveResult, error) {
	res := MoveResult{Source: src, Destination: dst}
	ls, err := f.locate(src, true)
	if err != nil {
		return res, err
	}
	defer ls.close()
	if ls.parent == nil {
		return res, errf(protocol.CodePathDenied, "a root cannot be moved")
	}
	ld, err := f.locate(dst, true)
	if err != nil {
		return res, err
	}
	defer ld.close()
	if ld.parent == nil {
		return res, errf(protocol.CodePathDenied, "a root cannot be replaced")
	}
	if ld.root != ls.root {
		return res, errf(protocol.CodePolicyDenied, "source and destination are under different write roots")
	}
	sfi, err := ls.parent.Lstat(ls.base)
	if err != nil {
		return res, mapErr(err)
	}
	if sfi.Mode()&fs.ModeSymlink != 0 {
		return res, errf(protocol.CodePathDenied, "final path component is a symlink")
	}
	res.Type = typeOf(sfi.Mode())
	if sfi.IsDir() {
		if pathx.Within(src, dst) {
			return res, errf(protocol.CodeBadRequest, "cannot move a directory into itself")
		}
		sub, subReal, _, err := f.openSubdir(ls, ls.parent, ls.targetReal(), ls.base)
		if err != nil {
			return res, err
		}
		count := 0
		err = f.walkTree(ls, sub, src, subReal, 1, func(lp string, _ fs.FileInfo) error {
			count++
			if count > f.cfg.Limits.MaxDeleteEntries {
				return errf(protocol.CodeTooLarge, "directory has more than %d entries", f.cfg.Limits.MaxDeleteEntries)
			}
			return f.checkPath(join(dst, pathx.Rel(src, lp)), true).orNil()
		})
		_ = sub.Close()
		if err != nil {
			return res, err
		}
	}
	dfi, err := ld.parent.Lstat(ld.base)
	switch {
	case err == nil && dfi.Mode()&fs.ModeSymlink != 0:
		return res, errf(protocol.CodePathDenied, "destination is a symlink")
	case err == nil && (dfi.IsDir() || sfi.IsDir()):
		return res, errf(protocol.CodeExists, "destination exists; directories are never replaced")
	case err == nil && !overwrite:
		return res, errf(protocol.CodeExists, "destination exists")
	case err == nil:
		res.Replaced = true
	case !errors.Is(err, fs.ErrNotExist):
		return res, mapErr(err)
	}
	if ls.parentReal == ld.parentReal {
		err = ls.parent.Rename(ls.base, ld.base)
	} else {
		err = ls.top.Rename(ls.rel, ld.rel)
	}
	if err != nil {
		return res, mapErr(err)
	}
	nfi, err := ld.parent.Lstat(ld.base)
	if err != nil || !os.SameFile(sfi, nfi) {
		return res, errf(protocol.CodeInternal, "the moved entry could not be verified at its destination")
	}
	return res, nil
}

// orNil lets a nil *Error be returned as a nil error.
func (e *Error) orNil() error {
	if e == nil {
		return nil
	}
	return e
}

// Chmod sets the mode of p under a write root, through a descriptor opened
// without following a final symlink.
func (f *FS) Chmod(p string, mode os.FileMode) (ChmodResult, error) {
	if e := checkMode(mode); e != nil {
		return ChmodResult{}, e
	}
	l, err := f.locate(p, true)
	if err != nil {
		return ChmodResult{}, err
	}
	defer l.close()
	file, err := f.openTarget(l, os.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return ChmodResult{}, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return ChmodResult{}, mapErr(err)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return ChmodResult{}, errf(protocol.CodeBadRequest, "only regular files and directories")
	}
	res := ChmodResult{Path: p, OldMode: fmt.Sprintf("%04o", unixMode(fi)), Mode: fmt.Sprintf("%04o", uint32(mode))}
	if err := file.Chmod(mode); err != nil {
		return ChmodResult{}, mapErr(err)
	}
	return res, nil
}

// ResolveWrite returns the real path of p under a write root; p need not
// exist, but its parent must (for {path:write}).
func (f *FS) ResolveWrite(p string) (string, error) {
	l, err := f.locate(p, true)
	if err != nil {
		return "", err
	}
	defer l.close()
	if l.parent == nil {
		return l.rootReal, nil
	}
	fi, err := l.parent.Lstat(l.base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return l.targetReal(), nil
	case err != nil:
		return "", mapErr(err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return "", errf(protocol.CodePathDenied, "final path component is a symlink")
	}
	file, err := f.openTarget(l, os.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return "", err
	}
	_ = file.Close()
	return l.targetReal(), nil
}
