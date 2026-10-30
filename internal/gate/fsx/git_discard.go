//go:build linux

package fsx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// git_discard's filesystem side (docs/POLICY.md §7, "Discarding changes").
//
// The gate restores a tracked path only after it has set aside what is
// there, with the steps of DeleteExact's deletion pass, so an entry that is
// not exactly what the preview saw is put back instead of being discarded:
//
//  1. statx(name) on the parent directory's descriptor: the object the
//     preview saw (device, inode, type, mount id, birth time), with the same
//     size, change time and permission bits;
//  2. renameat2(name → .shell-mcp-delete-<32 hex>, RENAME_NOREPLACE);
//  3. statx(tmp): the same object, size and permission bits, and its content
//     (or a symlink's target) has the SHA-256 the preview saw; otherwise it
//     is put back under its name (RENAME_NOREPLACE) and the discard stops.
//
// Git then writes the restored file under the free name (checkout-index
// without -f creates it with O_EXCL and never replaces anything), and the
// entry set aside is removed only after git has verified the restored file.
// An entry that cannot be put back because its name was taken again stays
// under its temporary name, as a delete leaves one (POLICY §3).
//
// The discard holds git's own index lock, <repo>/.git/index.lock, from
// before its recompute to the end, so no git process can change the index
// meanwhile; the new index is built by git in a temporary index in .git and
// renamed onto .git/index. These three names (index.lock, the temporary
// index and the rename onto index) are the only writes the gate itself
// makes under a .git directory; every file operation still refuses .git.

// DiscardStep names a point of git_discard, for tests
// (Options.InjectDiscardStep in the gate).
type DiscardStep int

// Points of a discard.
const (
	// DiscardStepAfterCompare: the lock is held and the preview hash
	// matched; nothing has changed yet.
	DiscardStepAfterCompare DiscardStep = iota + 1
	// DiscardStepBeforeUntracked: tracked entries are set aside; untracked
	// ones are about to be removed.
	DiscardStepBeforeUntracked
	// DiscardStepBeforeCheckout: git is about to write the restored files.
	DiscardStepBeforeCheckout
	// DiscardStepAfterCheckout: git wrote them; nothing is verified yet.
	DiscardStepAfterCheckout
	// DiscardStepBeforeCommit: everything verified; the index is about to
	// be replaced.
	DiscardStepBeforeCommit
)

// WorktreeEntry is what is at a tracked path in the work tree.
type WorktreeEntry struct {
	Path      string // the logical path
	State     string // absent, file, symlink or dir
	Mode      uint32 // permission bits of a file or directory
	Size      int64
	SHA256    string // a file's content, or a symlink's target
	BlockedBy string // the first ancestor that exists and is not a directory

	id  ident // the entry (present only)
	dir ident // its parent directory (present only)
}

// ObserveWorktree describes the entry at p (under a write root),
// following nothing: absent (also when an ancestor is missing, or is not a
// directory, which BlockedBy then names), a file (its content's SHA-256), a
// symlink (its target's SHA-256) or a directory. Anything else, the deny
// list, the protected set (.git included), a mount point and a set-aside
// name are refused. budget bounds the bytes hashed across calls.
func (f *FS) ObserveWorktree(p string, budget *int64) (WorktreeEntry, error) {
	w := WorktreeEntry{Path: p, State: "absent"}
	if err := pathx.CheckClean(p); err != nil {
		return w, errf(protocol.CodeBadRequest, "path must be absolute and clean: %v", err)
	}
	if hasSetAsideComponent(p) {
		return w, errSetAside()
	}
	root, ok := pathx.Longest(f.cfg.WriteRoots, p)
	if !ok {
		return w, errf(protocol.CodePathDenied, "path is outside the policy's write roots")
	}
	if e := f.checkPath(p, true); e != nil {
		return w, e
	}
	rel := pathx.Rel(root, p)
	if rel == "." {
		return w, errf(protocol.CodePathDenied, "a root is never a tracked path")
	}
	blocked, missing, err := f.ancestors(root, rel)
	if err != nil || missing {
		return w, err
	}
	if blocked != "" {
		w.BlockedBy = join(root, blocked)
		return w, nil
	}
	err = f.inParent(p, func(l *loc, pfd int, pid *ident) error {
		id, serr := statxAt(pfd, l.base, 0)
		if errors.Is(serr, fs.ErrNotExist) {
			return nil
		}
		if serr != nil {
			return mapErr(serr)
		}
		if crossesMount(pid, &id) {
			return errf(protocol.CodePathDenied, "the path is a mount point (or the root of another filesystem), which is never discarded")
		}
		w.id, w.dir, w.Size, w.Mode = id, *pid, id.size, id.perm
		switch id.typ {
		case unix.S_IFREG:
			w.State = "file"
		case unix.S_IFLNK:
			w.State = "symlink"
		case unix.S_IFDIR:
			w.State, w.Size = "dir", 0
			return nil
		default:
			return errf(protocol.CodePathDenied, "the path is not a regular file, a symlink or a directory")
		}
		sum, herr := contentHash(pfd, l.base, &id, budget, true)
		if herr != nil {
			return herr
		}
		w.SHA256 = sum
		return nil
	})
	return w, err
}

// ancestors walks rel's directories under root without following
// anything: the first one that is missing (missing), or that exists and is
// not a directory (blocked, relative to root).
func (f *FS) ancestors(root, rel string) (blocked string, missing bool, err error) {
	top, err := os.OpenRoot(root)
	if err != nil {
		return "", false, mapErr(err)
	}
	defer func() { _ = top.Close() }()
	comps := strings.Split(rel, "/")
	cur := ""
	for _, c := range comps[:len(comps)-1] {
		cur = path.Join(cur, c)
		fi, err := top.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", true, nil
		case err != nil:
			return "", false, mapErr(err)
		case !fi.IsDir():
			return cur, false, nil
		}
	}
	return "", false, nil
}

// inParent locates p, requires that no symlink lies on the way to its
// parent directory, and calls fn with the parent's descriptor and
// identity.
func (f *FS) inParent(p string, fn func(l *loc, pfd int, pid *ident) error) error {
	l, err := f.locate(p, true)
	if err != nil {
		return err
	}
	defer l.close()
	if l.parent == nil {
		return errf(protocol.CodePathDenied, "a root is never a tracked path")
	}
	if pathx.Rel(l.rootReal, l.parentReal) != path.Dir(l.rel) {
		return errf(protocol.CodePathDenied, "a directory on the path is a symlink")
	}
	pf, err := l.parent.Open(".")
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = pf.Close() }()
	return withFD(pf, func(pfd int) error {
		pid, err := statxAt(pfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return mapErr(err)
		}
		return fn(l, pfd, &pid)
	})
}

// contentHash is the SHA-256 of name's content (a file, opened without
// following anything) or of its target (a symlink). The file must be the
// object want describes, with its size and, when strict, its change time
// (never after a rename, which may move it), and must not change while it
// is read. The bytes hashed are taken from budget.
func contentHash(dfd int, name string, want *ident, budget *int64, strict bool) (string, error) {
	h := sha256.New()
	if want.typ == unix.S_IFLNK {
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(dfd, name, buf)
		if err != nil {
			return "", mapErr(err)
		}
		_, _ = h.Write(buf[:n])
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", mapErr(&fs.PathError{Op: "open", Path: name, Err: err})
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	got, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return "", mapErr(err)
	}
	if !got.sameObject(want) || got.size != want.size || strict && !got.unchanged(want) {
		return "", errf(protocol.CodeExists, "a file changed while it was read")
	}
	if *budget < want.size {
		return "", errf(protocol.CodeTooLarge, "the files to discard are larger than the %d bytes the gate hashes for one discard", maxDiscardHashBytes)
	}
	n, err := io.Copy(h, io.LimitReader(file, want.size+1))
	if err != nil {
		return "", mapErr(err)
	}
	*budget -= n
	after, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return "", mapErr(err)
	}
	if n != want.size || !after.unchanged(&got) {
		return "", errf(protocol.CodeExists, "a file changed while it was read")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maxDiscardHashBytes bounds the bytes one discard hashes (the gate's ops
// give each preview and discard this budget).
const maxDiscardHashBytes = 256 << 20

// MaxDiscardHashBytes is that bound, for the gate's ops.
const MaxDiscardHashBytes = maxDiscardHashBytes

// AppendHash appends w's hash input: its path, type, size, device, inode,
// change and birth time (as a delete preview entry), then its state, its
// permission bits, its content hash and BlockedBy, each with a fixed width
// or a length (FuzzWorktreeEntryEncoding).
func (w *WorktreeEntry) AppendHash(b []byte) []byte {
	id := w.id
	id.size = w.Size
	b = appendPreviewEntry(b, w.Path, &id)
	b = appendString(b, w.State)
	b = binary.BigEndian.AppendUint32(b, w.Mode)
	b = appendString(b, w.SHA256)
	return appendString(b, w.BlockedBy)
}

func appendString(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// AsideEntry is a work-tree entry set aside under a temporary name in its
// own directory.
type AsideEntry struct {
	f   *FS
	w   WorktreeEntry
	tmp string // the temporary name in the entry's directory
	// checked is the entry under its temporary name once its content was
	// checked: Remove requires the same size and change time, so a write
	// through a descriptor opened before the discard, made while the
	// discard went on, keeps the entry from being removed.
	checked ident
}

// changedSince is the refusal for an entry that is not what the preview
// saw.
func changedSince(p string) *Error {
	return errf(protocol.CodeExists, "%s was changed or replaced since the preview", quote(p))
}

// quote shows a path in a one-line message.
func quote(p string) string { return fmt.Sprintf("%q", p) }

// SetAside sets w's entry (a file or a symlink) aside, after checking that
// it is what w describes, and checks it again under the temporary name (see
// the file comment). A refusal leaves the entry under its name, or, when its
// name was taken again before it could be put back, under the temporary
// name, which the error then names (Error.SetAside).
func (f *FS) SetAside(w *WorktreeEntry) (*AsideEntry, error) {
	if w.State != "file" && w.State != "symlink" {
		return nil, errf(protocol.CodeInternal, "only files and symlinks are set aside")
	}
	a := &AsideEntry{f: f, w: *w, tmp: deleteTempPrefix + randHex(16)}
	err := f.inParent(w.Path, func(l *loc, pfd int, pid *ident) error {
		if !pid.sameObject(&w.dir) {
			return changedSince(w.Path)
		}
		f.step(DeleteStepBeforeEntry, w.Path)
		pre, err := statxAt(pfd, l.base, 0)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return changedSince(w.Path)
		case err != nil:
			return mapErr(err)
		case !pre.unchanged(&w.id) || pre.perm != w.id.perm:
			return changedSince(w.Path)
		}
		if e := f.checkPath(join(dirOf(w.Path), a.tmp), true); e != nil {
			return e
		}
		f.step(DeleteStepBeforeRename, w.Path)
		if f.cfg.InjectNoReplaceFault != nil {
			err = f.cfg.InjectNoReplaceFault()
		} else {
			err = unix.Renameat2(pfd, l.base, pfd, a.tmp, unix.RENAME_NOREPLACE)
		}
		switch {
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
			return errf(protocol.CodeBadRequest, "the filesystem does not support RENAME_NOREPLACE, which a discard needs to set each "+
				"entry aside before checking it; nothing more was changed")
		case errors.Is(err, syscall.ENOENT):
			return changedSince(w.Path)
		case err != nil:
			return mapErr(err)
		}
		f.step(DeleteStepAfterRename, w.Path)
		post, err := statxAt(pfd, a.tmp, 0)
		budget := w.Size
		if err == nil && post.sameObject(&w.id) && post.size == w.id.size && post.perm == w.id.perm {
			var sum string
			if sum, err = contentHash(pfd, a.tmp, &w.id, &budget, false); err == nil && sum == w.SHA256 {
				if a.checked, err = statxAt(pfd, a.tmp, 0); err == nil && a.checked.sameObject(&w.id) {
					return nil
				}
			}
		}
		return a.putBackAt(pfd, l.base, changedSince(w.Path))
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// putBackAt puts the entry back under name in dfd, never replacing
// anything; reason is returned, naming the temporary path when the name
// was taken again.
func (a *AsideEntry) putBackAt(dfd int, name string, reason *Error) *Error {
	if err := unix.Renameat2(dfd, a.tmp, dfd, name, unix.RENAME_NOREPLACE); err != nil {
		out := errf(reason.Code, "%s; the entry set aside from %s could not be put back because that name was taken again; "+
			"it was left, not discarded, as %s", reason.Msg, quote(a.w.Path), a.Temp())
		out.SetAside = a.Temp()
		return out
	}
	return reason
}

// Temp is the entry's temporary path.
func (a *AsideEntry) Temp() string { return join(dirOf(a.w.Path), a.tmp) }

// From is the path the entry was set aside from.
func (a *AsideEntry) From() string { return a.w.Path }

// inDir re-opens the entry's directory by its path, as SetAside found it.
func (a *AsideEntry) inDir(fn func(l *loc, pfd int) error) error {
	return a.f.inParent(a.w.Path, func(l *loc, pfd int, pid *ident) error {
		if !pid.sameObject(&a.w.dir) {
			return errf(protocol.CodeExists, "the directory of %s was replaced", quote(a.w.Path))
		}
		return fn(l, pfd)
	})
}

// Remove removes the entry set aside, if it is still the object that was
// set aside, unchanged (size and change time) since its content was
// checked.
func (a *AsideEntry) Remove() error {
	return a.inDir(func(_ *loc, pfd int) error {
		a.f.step(DeleteStepBeforeUnlink, a.w.Path)
		post, err := statxAt(pfd, a.tmp, 0)
		if err != nil || !post.unchanged(&a.checked) {
			e := errf(protocol.CodeExists, "the entry set aside from %s was replaced or written under its temporary name after it was checked; "+
				"it was left, not discarded, as %s", quote(a.w.Path), a.Temp())
			e.SetAside = a.Temp()
			return e
		}
		if err := unix.Unlinkat(pfd, a.tmp, 0); err != nil {
			return mapErr(err)
		}
		return nil
	})
}

// PutBack puts the entry back under its name, never replacing anything.
// When the name was taken again it stays set aside, and the error names it.
func (a *AsideEntry) PutBack() error {
	err := a.inDir(func(l *loc, pfd int) error {
		if e := a.putBackAt(pfd, l.base, errf(protocol.CodeExists, "%s was not restored", quote(a.w.Path))); e.SetAside != "" {
			return e
		}
		return nil
	})
	var fe *Error
	if err != nil && !errors.As(err, &fe) {
		return mapErr(err)
	}
	if fe != nil && fe.SetAside == "" {
		fe.SetAside = a.Temp()
	}
	return err
}

// GitIndexLock is git's index lock, <repo>/.git/index.lock, held by this
// gate for one discard.
type GitIndexLock struct {
	gd   *os.Root // the repository's .git, verified
	real string   // its real path
	id   ident    // the lock file this gate created
	tmp  string   // the temporary index's name in .git ("" when none)
	held bool
}

// The lock file's content: git never reads it, and it tells a later
// preview that a gate (not git) left it.
const indexLockMarker = "shell-mcp-gate git_discard\n"

// tempIndexPrefix starts the temporary index's name in .git.
const tempIndexPrefix = ".shell-mcp-index-"

// openGitDir opens <repo>/.git, which must be a real directory inside the
// repository (a write root's tree): the deny list applies, the protected
// set does not (it covers every .git; this is git_discard's narrow
// exception, for the names above only).
func (f *FS) openGitDir(repo string) (*os.Root, string, error) {
	l, err := f.locate(repo, true)
	if err != nil {
		return nil, "", err
	}
	defer l.close()
	dir, rp, owned, err := f.openDirRoot(l)
	if err != nil {
		return nil, "", err
	}
	if owned {
		defer func() { _ = dir.Close() }()
	}
	fi, err := dir.Lstat(".git")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "", errf(protocol.CodeNotFound, "repo has no .git directory")
	case err != nil:
		return nil, "", mapErr(err)
	case !fi.IsDir():
		return nil, "", errf(protocol.CodePathDenied, "repo/.git must be a real directory (a gitfile or a symlink is refused)")
	}
	gd, err := dir.OpenRoot(".git")
	if err != nil {
		return nil, "", mapErr(err)
	}
	gr, err := realPathOfRoot(f.cfg.Proc, gd)
	if err != nil || gr != rp+"/.git" {
		_ = gd.Close()
		return nil, "", errf(protocol.CodePathDenied, "repo/.git must be a real directory inside the root")
	}
	if e := f.checkPath(gr, false); e != nil {
		_ = gd.Close()
		return nil, "", e
	}
	return gd, gr, nil
}

// withRootFD calls fn with the descriptor of r's directory.
func withRootFD(r *os.Root, fn func(fd int) error) error {
	d, err := r.Open(".")
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = d.Close() }()
	return withFD(d, fn)
}

// errIndexLocked is the refusal while .git/index.lock exists: git holds it
// (or left it), or a gate that stopped while discarding left it. The gate
// never removes a lock it did not create in the same request.
func errIndexLocked(byGate bool) *Error {
	if byGate {
		return errf(protocol.CodeExists, "the repository is locked by a gate that stopped while discarding (.git/index.lock was left by shell-mcp-gate); "+
			"nothing was changed. Check on the host that no git process is running, then remove .git/index.lock in the repository and preview again")
	}
	return errf(protocol.CodeExists, "the repository is locked by another git process (.git/index.lock exists); nothing was changed. "+
		"If no git process is running on the host, remove .git/index.lock in the repository and try again")
}

// LockGitIndex creates <repo>/.git/index.lock exclusively (O_CREAT, O_EXCL,
// O_NOFOLLOW on the verified .git descriptor), as git itself does before it
// changes the index. An existing lock, or anything else at that name, is
// refused (exists) and left alone.
func (f *FS) LockGitIndex(repo string) (*GitIndexLock, error) {
	gd, gr, err := f.openGitDir(repo)
	if err != nil {
		return nil, err
	}
	k := &GitIndexLock{gd: gd, real: gr}
	err = withRootFD(gd, func(gfd int) error {
		fd, oerr := unix.Openat(gfd, "index.lock", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
		if errors.Is(oerr, syscall.EEXIST) {
			return errIndexLocked(lockedByGate(gfd))
		}
		if oerr != nil {
			return mapErr(&fs.PathError{Op: "open", Path: "index.lock", Err: oerr})
		}
		file := os.NewFile(uintptr(fd), "index.lock")
		defer func() { _ = file.Close() }()
		// The identity is taken after the marker is written, so Release can
		// tell this file (object, size and change time) from one that
		// replaced it, even under a reused inode number.
		_, werr := file.WriteString(indexLockMarker)
		var serr error
		if werr == nil {
			k.id, serr = statxAt(fd, "", unix.AT_EMPTY_PATH)
		}
		if jerr := errors.Join(werr, serr); jerr != nil {
			_ = unix.Unlinkat(gfd, "index.lock", 0)
			return mapErr(jerr)
		}
		k.held = true
		return nil
	})
	if err != nil {
		k.Release()
		return nil, err
	}
	return k, nil
}

// lockedByGate reports whether the existing index.lock in gfd carries the
// gate's marker.
func lockedByGate(gfd int) bool {
	fd, err := unix.Openat(gfd, "index.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), "index.lock")
	defer func() { _ = file.Close() }()
	b := make([]byte, len(indexLockMarker))
	n, _ := io.ReadFull(file, b)
	return bytes.Equal(b[:n], []byte(indexLockMarker))
}

// GitIndexLockState reports whether <repo>/.git/index.lock exists and
// whether a gate created it.
func (f *FS) GitIndexLockState(repo string) (locked, byGate bool, err error) {
	gd, _, err := f.openGitDir(repo)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = gd.Close() }()
	err = withRootFD(gd, func(gfd int) error {
		if _, serr := statxAt(gfd, "index.lock", 0); serr != nil {
			if errors.Is(serr, fs.ErrNotExist) {
				return nil
			}
			return mapErr(serr)
		}
		locked, byGate = true, lockedByGate(gfd)
		return nil
	})
	return locked, byGate, err
}

// ErrIndexLocked is the refusal GitIndexLockState's answer calls for.
func ErrIndexLocked(byGate bool) error { return errIndexLocked(byGate) }

// NewTempIndex creates the temporary index (.git/.shell-mcp-index-<32
// hex>, O_CREAT, O_EXCL, O_NOFOLLOW) and returns its real path, for git's
// GIT_INDEX_FILE. Git replaces it through its own <name>.lock.
func (k *GitIndexLock) NewTempIndex() (string, error) {
	if !k.held || k.tmp != "" {
		return "", errf(protocol.CodeInternal, "no lock held, or a temporary index exists already")
	}
	name := tempIndexPrefix + randHex(16)
	err := withRootFD(k.gd, func(gfd int) error {
		fd, err := unix.Openat(gfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
		if err != nil {
			return mapErr(&fs.PathError{Op: "open", Path: name, Err: err})
		}
		k.tmp = name
		return unix.Close(fd)
	})
	if err != nil {
		return "", err
	}
	return k.real + "/" + name, nil
}

// CommitTempIndex renames the temporary index onto .git/index, as git's
// own commit of a locked index does. The lock is still held.
func (k *GitIndexLock) CommitTempIndex() error {
	if !k.held || k.tmp == "" {
		return errf(protocol.CodeInternal, "no temporary index to commit")
	}
	return withRootFD(k.gd, func(gfd int) error {
		if err := unix.Renameat(gfd, k.tmp, gfd, "index"); err != nil {
			return mapErr(err)
		}
		k.tmp = ""
		return nil
	})
}

// Release removes what this lock created: the temporary index (and git's
// lock for it, which git leaves if it is killed), then index.lock, only if
// it is still the file this gate created. It is safe to call more than
// once.
func (k *GitIndexLock) Release() {
	if k == nil || k.gd == nil {
		return
	}
	_ = withRootFD(k.gd, func(gfd int) error {
		if k.tmp != "" {
			_ = unix.Unlinkat(gfd, k.tmp, 0)
			_ = unix.Unlinkat(gfd, k.tmp+".lock", 0)
			k.tmp = ""
		}
		if k.held {
			if cur, err := statxAt(gfd, "index.lock", 0); err == nil && cur.unchanged(&k.id) {
				_ = unix.Unlinkat(gfd, "index.lock", 0)
			}
			k.held = false
		}
		return nil
	})
	_ = k.gd.Close()
	k.gd = nil
}
