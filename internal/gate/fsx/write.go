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
	if o.ExpectAbsent && o.ExpectedSHA256 != "" {
		return WriteResult{}, errf(protocol.CodeBadRequest, "expect_absent and expected_sha256 are mutually exclusive")
	}
	l, err := f.locate(p, true)
	if err != nil {
		return WriteResult{}, err
	}
	defer l.close()
	if l.parent == nil {
		return WriteResult{}, errf(protocol.CodeIsADirectory, "is a directory")
	}
	newMode := os.FileMode(defaultFileMode)
	if o.DefaultMode != 0 {
		if e := checkMode(o.DefaultMode); e != nil {
			return WriteResult{}, e
		}
		newMode = o.DefaultMode
	}
	return f.writeAtomic(l, content, &atomicOpts{mode: o.Mode, newMode: newMode, create: o.Create, overwrite: !o.ExpectAbsent, expected: o.ExpectedSHA256, owner: o.Owner})
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
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
// existing file keeps its mode (unless mode is given; masked by ModesMax in
// the helper, like every new inode's) and, where the
// service user may, its owner and group. Without overwrite the commit is a
// hard link of the temp file to the target instead of the rename: link(2)
// fails with EEXIST if the target exists at that moment, so a file that
// appeared after the checks is refused, never replaced. A replace bound to
// the content checked (expected), and every replace in the helper, is an
// exchange checked afterwards instead of the rename (exchangeVerified).
// atomicOpts are writeAtomic's options.
type atomicOpts struct {
	mode      *os.FileMode // requested mode (nil: keep, or newMode for a new file)
	newMode   os.FileMode
	create    bool
	overwrite bool   // false: create only (expect_absent, copy without overwrite)
	expected  string // expected_sha256 of the current content
	owner     *Owner // explicit owner (the helper only)
	// destination: expected is a copy's expected_destination_sha256 (P-9):
	// a destination that is not a regular file is then exists.
	destination bool
	// copy: the content is a copy's, which cannot name an owner (the
	// moved-in rule refuses it over a file whose owner it may not keep).
	copy bool
}

func (f *FS) writeAtomic(l *loc, content []byte, o *atomicOpts) (WriteResult, error) {
	mode, newMode, create, overwrite, expected := o.mode, o.newMode, o.create, o.overwrite, o.expected
	res := WriteResult{Path: l.p}
	fi, err := l.parent.Lstat(l.base)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, mapErr(err)
	}
	var oldUID, oldGID uint32
	// replaced is the file to be replaced as last checked: what a verified
	// replace (Config.VerifyReplaced) requires to find at its commit.
	var replaced fs.FileInfo
	if exists && o.destination && expected != "" && !fi.Mode().IsRegular() {
		return res, errf(protocol.CodeExists, "the destination is no longer a regular file; nothing was copied")
	}
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
		old, oerr := f.openTarget(l)
		if oerr != nil {
			return res, oerr
		}
		if replaced, err = old.Stat(); err != nil {
			_ = old.Close()
			return res, mapErr(err)
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
			if o.destination {
				return res, errf(protocol.CodeExists, "the destination's content does not match expected_destination_sha256; nothing was copied")
			}
			return res, errf(protocol.CodeExists, "current content does not match expected_sha256")
		}
		newMode = os.FileMode(um)
		if st, ok := replaced.Sys().(*syscall.Stat_t); ok {
			oldUID, oldGID = st.Uid, st.Gid
		}
	} else {
		if !create {
			return res, errf(protocol.CodeNotFound, "file does not exist and create is false")
		}
		if expected != "" {
			if o.destination {
				return res, errf(protocol.CodeNotFound, "the destination does not exist but expected_destination_sha256 was given; nothing was copied")
			}
			return res, errf(protocol.CodeNotFound, "file does not exist but expected_sha256 was given")
		}
	}
	// Rule R (the helper): the owner the file will have must be one that
	// could have made it there itself; nothing is backed up or written
	// otherwise (PRIVILEGED §6, handoff N-6, N-8).
	if err := f.ownerRule(l, o, exists, oldUID); err != nil {
		return res, err
	}
	if mode != nil {
		newMode = *mode
	}
	newMode = f.maskMode(newMode)
	// The helper backs up the version it is about to replace, handing the
	// hook the hash it just computed; a failed backup changes nothing.
	var backedUp fs.FileInfo
	if exists && f.cfg.Backup != nil {
		if backedUp, err = f.backupFile(l, res.OldSHA256, replaced); err != nil {
			return res, err
		}
		replaced = backedUp
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
	if _, err = tf.Write(content); err != nil {
		return res, mapErr(err)
	}
	if err = tf.Chmod(newMode); err != nil {
		return res, mapErr(err)
	}
	res.OwnerPreserved = true
	switch {
	case f.cfg.ExplicitOwner:
		// The helper sets both ids on every new inode: those given, else the
		// replaced file's, else its own, so a setgid parent never chooses
		// the group (handoff N-8).
		uid, gid := os.Geteuid(), os.Getegid()
		if exists {
			uid, gid = int(oldUID), int(oldGID)
		}
		if o.owner != nil && o.owner.UID != nil {
			uid = int(*o.owner.UID)
		}
		if o.owner != nil && o.owner.GID != nil {
			gid = int(*o.owner.GID)
		}
		if err = tf.Chown(uid, gid); err != nil {
			return res, mapErr(err)
		}
	case exists && o.owner == nil:
		if tfi, serr := tf.Stat(); serr == nil {
			if st, ok := tfi.Sys().(*syscall.Stat_t); ok && (st.Uid != oldUID || st.Gid != oldGID) {
				res.OwnerPreserved = tf.Chown(int(oldUID), int(oldGID)) == nil
			}
		}
	case o.owner != nil:
		// An explicit owner must be set; the unset half keeps the old
		// file's id (or the process's, for a new file).
		uid, gid := -1, -1
		if exists {
			uid, gid = int(oldUID), int(oldGID)
		}
		if o.owner.UID != nil {
			uid = int(*o.owner.UID)
		}
		if o.owner.GID != nil {
			gid = int(*o.owner.GID)
		}
		if err = tf.Chown(uid, gid); err != nil {
			return res, mapErr(err)
		}
	}
	if tfi, serr := tf.Stat(); serr == nil {
		if st, ok := tfi.Sys().(*syscall.Stat_t); ok {
			res.UID, res.GID = st.Uid, st.Gid
		}
	}
	if err = tf.Sync(); err != nil {
		return res, mapErr(err)
	}
	closed = true
	if err = tf.Close(); err != nil {
		return res, mapErr(err)
	}
	if backedUp != nil {
		if e := unchangedSince(l.parent, l.base, backedUp); e != nil {
			return res, e
		}
	}
	if f.cfg.InjectBeforeCommit != nil {
		f.cfg.InjectBeforeCommit()
	}
	switch {
	case overwrite && exists && (f.cfg.VerifyReplaced || expected != ""):
		// The helper, and in the gate a replace bound to the content it
		// checked (expected): an exchange checked afterwards, so a file that
		// replaced or rewrote the destination since it was checked is
		// exchanged back, never lost (exchangeVerified).
		if e := f.exchangeVerified(l.parent, tmp, l.parent, l.base, replaced); e != nil {
			return res, e
		}
		committed = true
		f.commit()
	case overwrite && (exists || !f.cfg.VerifyReplaced):
		// The gate's unconditional replace: rename(2) over whatever is there.
		// (In the helper, a file that was absent when checked is committed
		// create-only below: it replaces only what it checked.)
		if err = l.parent.Rename(tmp, l.base); err != nil {
			return res, mapErr(err)
		}
		committed = true
		f.commit()
	default:
		if e := f.linkNoReplace(l.parent, tmp, l.base); e != nil {
			return res, e
		}
		committed = true
		f.commit()
		if err = l.parent.Remove(tmp); err != nil {
			return res, errf(protocol.CodeInternal, "the file was written, but its temporary name could not be removed")
		}
	}
	if d, derr := l.parent.Open("."); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	// Read-back verification: a mismatch is a failure, never a warning.
	rf, err := f.openTarget(l)
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
	return f.MkdirAs(p, mode, parents, nil)
}

// MkdirAs is Mkdir with an owner for every directory it creates (the
// helper only). A directory whose owner cannot be set is removed again.
func (f *FS) MkdirAs(p string, mode *os.FileMode, parents bool, owner *Owner) (MkdirResult, error) {
	m := os.FileMode(defaultDirMode)
	if mode != nil {
		if e := checkMode(*mode); e != nil {
			return MkdirResult{}, e
		}
		m = *mode
	}
	m = f.maskMode(m)
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
		created, err := f.mkdirIn(l, l.parent, l.parentReal, l.base, m, owner, &res)
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
	defer func() { _ = top.Close() }()
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
		var out *MkdirResult
		if i == len(comps)-1 {
			out = &res
		}
		created, err := f.mkdirIn(l, cur, curReal, c, m, owner, out)
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
// whether it created the directory; out, when set, gets the directory's
// owner and group (read from its descriptor when it was created).
func (f *FS) mkdirIn(l *loc, dir *os.Root, dirReal, name string, m os.FileMode, owner *Owner, out *MkdirResult) (bool, error) {
	fi, err := dir.Lstat(name)
	switch {
	case err == nil && fi.Mode()&fs.ModeSymlink != 0:
		return false, errf(protocol.CodePathDenied, "a path component is a symlink")
	case err == nil && !fi.IsDir():
		return false, errf(protocol.CodeNotADirectory, "a path component exists and is not a directory")
	case err == nil:
		if out != nil {
			mo := metaOf(fi)
			out.UID, out.GID = mo.UID, mo.GID
		}
		return false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return false, mapErr(err)
	}
	if e := f.checkReal(l, join(dirReal, name), true); e != nil {
		return false, e
	}
	if err = dir.Mkdir(name, 0o700); err != nil {
		return false, mapErr(err)
	}
	f.commit()
	sub, _, _, err := f.openSubdir(l, dir, join(dirReal, name), name)
	if err != nil {
		return true, err
	}
	defer func() { _ = sub.Close() }()
	d, err := sub.Open(".")
	if err != nil {
		return true, mapErr(err)
	}
	defer func() { _ = d.Close() }()
	if err = d.Chmod(m); err != nil {
		return true, mapErr(err)
	}
	if owner != nil || f.cfg.ExplicitOwner {
		uid, gid := -1, -1
		if f.cfg.ExplicitOwner {
			// The helper sets both ids, so a setgid parent never chooses the
			// group (handoff N-8); the chmod above cleared its setgid bit.
			uid, gid = os.Geteuid(), os.Getegid()
		}
		if owner != nil && owner.UID != nil {
			uid = int(*owner.UID)
		}
		if owner != nil && owner.GID != nil {
			gid = int(*owner.GID)
		}
		if err = d.Chown(uid, gid); err != nil {
			_ = dir.Remove(name) // just created and empty
			return false, mapErr(err)
		}
	}
	if out != nil {
		if dfi, serr := d.Stat(); serr == nil {
			mo := metaOf(dfi)
			out.UID, out.GID = mo.UID, mo.GID
		}
	}
	return true, nil
}

// CopyExpecting copies the regular file src (any root) to dst (a write root). The
// copy is bounded by max_read_bytes, refused for files holding a private
// key, and read-back verified. A new copy takes the source's mode, a copy
// over a file the destination's, without setuid, setgid, sticky or
// world-write, and masked by ModesMax in the helper. With overwrite and
// expected (expected_destination_sha256, P-9), the destination must be a
// regular file with that content: otherwise exists (not_found when it is
// gone), and nothing changes.
func (f *FS) CopyExpecting(src, dst string, overwrite bool, expected string) (WriteResult, error) {
	if e := checkExpectedDestination(overwrite, expected); e != nil {
		return WriteResult{}, e
	}
	ls, err := f.locate(src, false)
	if err != nil {
		return WriteResult{}, err
	}
	defer ls.close()
	file, err := f.openTarget(ls)
	if err != nil {
		return WriteResult{}, err
	}
	defer func() { _ = file.Close() }()
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
	// The source is read under the moved-in rule (handoff N-7).
	if merr := f.movedInRead(ls, fi); merr != nil {
		return WriteResult{}, merr
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
	return f.writeAtomic(ld, data, &atomicOpts{newMode: srcMode, create: true, overwrite: overwrite, expected: expected, destination: expected != "", copy: true})
}

// Copy copies src to dst (CopyExpecting without a destination hash).
func (f *FS) Copy(src, dst string, overwrite bool) (WriteResult, error) {
	return f.CopyExpecting(src, dst, overwrite, "")
}

// checkExpectedDestination validates expected_destination_sha256 (P-9):
// only with overwrite, 64 lowercase hex digits.
func checkExpectedDestination(overwrite bool, expected string) *Error {
	switch {
	case expected == "":
		return nil
	case !overwrite:
		return errf(protocol.CodeBadRequest, "expected_destination_sha256 is valid only with overwrite")
	case !isSHA256Hex(expected):
		return errf(protocol.CodeBadRequest, "expected_destination_sha256 must be 64 lowercase hex characters")
	}
	return nil
}

// Move renames src to dst (MoveExpecting without a destination hash).
func (f *FS) Move(src, dst string, overwrite bool) (MoveResult, error) {
	return f.MoveExpecting(src, dst, overwrite, "")
}

// MoveExpecting renames src to dst. Both must be under the same write
// root; a directory is moved only if no entry in it is denied or protected
// at its old or new path. A rename within one directory goes through that
// directory's verified os.Root; otherwise through the root's, and the moved
// entry is then re-identified by device and inode. With overwrite and
// expected (expected_destination_sha256, P-9), the destination must be a
// regular file with that content: otherwise exists (not_found when it is
// gone), and nothing changes.
func (f *FS) MoveExpecting(src, dst string, overwrite bool, expected string) (MoveResult, error) {
	res := MoveResult{Source: src, Destination: dst}
	if e := checkExpectedDestination(overwrite, expected); e != nil {
		return res, e
	}
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
		sub, subReal, _, serr := f.openSubdir(ls, ls.parent, ls.targetReal(), ls.base)
		if serr != nil {
			return res, serr
		}
		count := 0
		werr := f.walkTree(ls, sub, src, subReal, 1, func(e *treeEntry) error {
			count++
			if count > f.cfg.Limits.MaxDeleteEntries {
				return errf(protocol.CodeTooLarge, "directory has more than %d entries", f.cfg.Limits.MaxDeleteEntries)
			}
			return f.checkPath(join(dst, pathx.Rel(src, e.lp)), true).orNil()
		})
		_ = sub.Close()
		if werr != nil {
			return res, werr
		}
	}
	dfi, err := ld.parent.Lstat(ld.base)
	switch {
	case expected != "" && errors.Is(err, fs.ErrNotExist):
		return res, errf(protocol.CodeNotFound, "the destination does not exist but expected_destination_sha256 was given; nothing was moved")
	case expected != "" && err == nil && !dfi.Mode().IsRegular():
		return res, errf(protocol.CodeExists, "the destination is no longer a regular file; nothing was moved")
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
	// replaced is the destination as last checked: what a verified replace
	// requires to find at its commit.
	var replaced fs.FileInfo
	if res.Replaced && (expected != "" || f.cfg.Backup != nil || f.cfg.VerifyReplaced) {
		var sha string
		if replaced, sha, err = f.hashTarget(ld, expected != "" || f.cfg.Backup != nil); err != nil {
			return res, err
		}
		if expected != "" && sha != expected {
			return res, errf(protocol.CodeExists, "the destination's content does not match expected_destination_sha256; nothing was moved")
		}
		if f.cfg.Backup != nil {
			if !replaced.Mode().IsRegular() {
				return res, errf(protocol.CodeBackupFailed, "only regular files can be backed up; nothing was moved")
			}
			if replaced, err = f.backupFile(ld, sha, replaced); err != nil {
				return res, err
			}
			if e := unchangedSince(ld.parent, ld.base, replaced); e != nil {
				return res, e
			}
		}
	}
	if f.cfg.InjectBeforeCommit != nil {
		f.cfg.InjectBeforeCommit()
	}
	switch {
	case res.Replaced && (f.cfg.VerifyReplaced || expected != ""):
		// The helper, and in the gate a replace bound to the content it
		// hashed (expected): an exchange checked afterwards
		// (exchangeVerified), which also refuses a destination changed
		// since it was hashed.
		if e := f.exchangeVerified(ls.parent, ls.base, ld.parent, ld.base, replaced); e != nil {
			return res, e
		}
	case !overwrite || f.cfg.VerifyReplaced:
		// (In the helper, a destination that was absent when checked is
		// committed create-only: overwrite replaces only what it checked.)
		// Without overwrite the rename itself refuses an existing
		// destination (RENAME_NOREPLACE), so one that appeared after the
		// check above is never replaced.
		if e := f.renameNoReplace(ls.parent, ls.base, ld.parent, ld.base); e != nil {
			return res, e
		}
		err = nil // err still holds the destination's not-found Lstat
	case ls.parentReal == ld.parentReal:
		err = ls.parent.Rename(ls.base, ld.base)
	default:
		err = ls.top.Rename(ls.rel, ld.rel)
	}
	if err != nil {
		return res, mapErr(err)
	}
	f.commit()
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

// maskMode applies ModesMax (the helper's modes.max) to a new inode's mode.
func (f *FS) maskMode(m os.FileMode) os.FileMode {
	if f.cfg.ModesMax != nil {
		return m & *f.cfg.ModesMax
	}
	return m
}

// metaOf is fi's mode, owner and group.
func metaOf(fi fs.FileInfo) Meta {
	m := Meta{Mode: unixMode(fi)}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		m.UID, m.GID = st.Uid, st.Gid
	}
	return m
}

// singleLink refuses a non-directory with more than one link. Chmod and
// chown change the inode, not the name, and the inode's other names can lie
// outside the write roots: roots, the unit's ReadWritePaths= and Landlock
// all confine paths. fi must come from fstat of the descriptor the change
// is then made through, so the inode checked is the inode changed. A link
// made after this check is a link made after the change.
func singleLink(p string, fi fs.FileInfo) *Error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errf(protocol.CodeInternal, "no link count")
	}
	if !fi.IsDir() && st.Nlink > 1 {
		return errf(protocol.CodePathDenied, "%q has %d links: its mode and owner are changed only when it has one, since another name can lie outside the write roots", p, st.Nlink)
	}
	return nil
}

// verifyMeta re-reads the mode, owner and group of the inode a change was
// made through, when VerifyMetadata is set (the helper); a mismatch with
// want is verify_failed, never a success.
func (f *FS) verifyMeta(file *os.File, want Meta) *Error {
	if !f.cfg.VerifyMetadata {
		return nil
	}
	fi, err := file.Stat()
	if err != nil {
		return errf(protocol.CodeVerifyFailed, "the change could not be read back")
	}
	got := metaOf(fi)
	if f.cfg.InjectMetadataReadBackFault != nil {
		got = f.cfg.InjectMetadataReadBackFault(got)
	}
	if got != want {
		return errf(protocol.CodeVerifyFailed, "read back mode %04o and owner %d:%d, not the %04o and %d:%d that were set",
			got.Mode, got.UID, got.GID, want.Mode, want.UID, want.GID)
	}
	return nil
}

// Chmod sets the mode of p under a write root, through a descriptor opened
// without following a final symlink (the gate's chmod; the helper's is
// ApplyMeta). A file with setuid, setgid or sticky bits (handoff N-2: chmod
// could only clear them, and clearing a shared directory's sticky bit or a
// setgid directory's bit is not harmless), or with more than one link
// (singleLink), is refused.
func (f *FS) Chmod(p string, mode os.FileMode) (ChmodResult, error) {
	if e := checkMode(mode); e != nil {
		return ChmodResult{}, e
	}
	l, err := f.locate(p, true)
	if err != nil {
		return ChmodResult{}, err
	}
	defer l.close()
	file, err := f.openTarget(l)
	if err != nil {
		return ChmodResult{}, err
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil {
		return ChmodResult{}, mapErr(err)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return ChmodResult{}, errf(protocol.CodeBadRequest, "only regular files and directories")
	}
	if unixMode(fi)&0o7000 != 0 {
		return ChmodResult{}, errf(protocol.CodePolicyDenied, "files with setuid, setgid or sticky bits are never changed")
	}
	if e := singleLink(p, fi); e != nil {
		return ChmodResult{}, e
	}
	res := ChmodResult{Path: p, OldMode: fmt.Sprintf("%04o", unixMode(fi)), Mode: fmt.Sprintf("%04o", uint32(mode)), Before: metaOf(fi)}
	if err := file.Chmod(mode); err != nil {
		return ChmodResult{}, mapErr(err)
	}
	f.commit()
	res.Changed = true
	want := res.Before
	want.Mode = uint32(mode)
	if e := f.verifyMeta(file, want); e != nil {
		return res, e
	}
	return res, nil
}

// ResolveWrite returns the real path of p under a write root; p need not
// exist, but its parent must (for {path:write}). With GuardExecPaths it
// applies the chain rule (exec_chain.go).
func (f *FS) ResolveWrite(p string) (string, error) {
	l, err := f.locate(p, true)
	if err != nil {
		return "", err
	}
	defer l.close()
	var file *os.File // the target as opened; nil when it does not exist yet
	exists := true
	if l.parent != nil {
		fi, lerr := l.parent.Lstat(l.base)
		switch {
		case errors.Is(lerr, fs.ErrNotExist):
			exists = false
		case lerr != nil:
			return "", mapErr(lerr)
		case fi.Mode()&fs.ModeSymlink != 0:
			return "", errf(protocol.CodePathDenied, "final path component is a symlink")
		}
	}
	// The root itself is opened only for the chain rule (the gate never
	// opened it here).
	if exists && (l.parent != nil || f.cfg.GuardExecPaths) {
		if file, err = f.openTarget(l); err != nil {
			return "", err
		}
		defer func() { _ = file.Close() }()
	}
	if err := f.execChain(l, file); err != nil {
		return "", err
	}
	return l.targetReal(), nil
}
