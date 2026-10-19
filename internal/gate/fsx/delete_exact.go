//go:build linux

package fsx

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The gate's delete and delete_preview (docs/ARCHITECTURE.md §4.3,
// docs/POLICY.md §3): a delete removes exactly what its preview listed, or
// stops.
//
// PreviewDelete walks the tree once, through os.Root sub-roots opened one
// directory at a time from their parent's handle (each re-checked against
// the roots, the deny list and the protected set, by requested and real
// path, and by statx identity), never following a symlink and never
// entering another mount. It returns the counts, the first entries and
// preview_sha256: a SHA-256 over every entry's path, type, size, device,
// inode, change time and (where the filesystem reports it) birth time, so
// an entry added, removed, renamed, resized, modified or replaced by
// another inode changes it, also when an inode number is reused.
//
// DeleteExact repeats that walk and refuses (exists, nothing deleted)
// unless its hash equals expected_preview_sha256. It then removes the
// listed entries bottom-up, re-opening each directory by its single
// component name from its parent's handle and requiring the identity the
// walk saw; it never reads a directory again and never addresses an entry
// by a path from the root. Each entry is removed in four steps on its
// parent directory's descriptor:
//
//  1. statx(name): the same object as the walk saw (device, inode, type,
//     mount id, birth time where reported) and, for a non-directory this
//     pass has not yet renamed or unlinked under another name, the same
//     size and change time;
//  2. renameat2(name → tmp, RENAME_NOREPLACE): whatever is under the name
//     now is set aside under .shell-mcp-delete-<32 hex> in the same
//     directory;
//  3. statx(tmp): the same object (device, inode, type, mount id, birth
//     time); otherwise it is put back under its name (RENAME_NOREPLACE)
//     and the deletion stops;
//  4. unlinkat(tmp) (AT_REMOVEDIR for a directory, which the kernel refuses
//     on a directory that is not empty; it is then put back and the
//     deletion stops).
//
// Change times are compared only where nothing this pass did can have
// moved them: in the hash (the walk changes nothing) and in step 1 for a
// non-directory not yet touched. A rename may move the renamed inode's
// change time (POSIX leaves it open, and Linux filesystems commonly set
// it), so step 3 never compares it, whatever the filesystem does; removing a directory's entries moves its change and modification
// times, so no step compares a directory's times or size (its emptiness is
// the kernel's AT_REMOVEDIR check); and unlinking one name of a hard-linked
// inode moves that inode's change time (its link count), so its other
// names are compared by object and size only (touched).
//
// An entry that fails step 3, or whose directory gained entries, is put
// back; when its name was taken again meanwhile it stays under its
// temporary name, which the refusal (Error.SetAside) and the gate's audit
// line name. No preview or delete ever touches a path with that prefix
// (errSetAside): an operator recovers it (POLICY §3). The prefix also
// finds what a gate that died between steps 2 and 4 left.
//
// Linux has no conditional unlink: unlinkat removes whatever is under a
// name at that moment. Step 2 turns "whatever is under the name" into a
// fixed object that step 3 can check before step 4 removes it, so an entry
// replaced under a listed name, at any moment, is never what gets removed.
// What remains (ARCHIVE §14, 2026-10-18) is a process that finds the random
// temporary name and replaces it between steps 3 and 4: it needs write
// access to that directory, so it could delete the entry itself; and, on a
// filesystem that reports no birth time, an inode number reused between
// steps 1 and 2 by an entry created under the listed name after the
// listed entry was removed by someone else. A filesystem without
// RENAME_NOREPLACE is refused (bad_request) before anything is removed;
// there is no fallback to a plain unlink.

// DeleteStep names a point of DeleteExact's deletion pass, for tests
// (Config.InjectDeleteStep).
type DeleteStep int

// Points of the deletion pass.
const (
	// DeleteStepAfterCompare: the preview hash matched; nothing is removed yet.
	DeleteStepAfterCompare DeleteStep = iota + 1
	// DeleteStepBeforeEntry: before an entry is checked under its name.
	DeleteStepBeforeEntry
	// DeleteStepBeforeRename: after that check, before the entry is set
	// aside under a temporary name in its directory.
	DeleteStepBeforeRename
	// DeleteStepAfterRename: after it was set aside, before it is checked
	// again under the temporary name.
	DeleteStepAfterRename
	// DeleteStepBeforeUnlink: after that check, before the temporary name
	// is removed.
	DeleteStepBeforeUnlink
)

// DeletePlan is the gate's delete_preview and delete result.
type DeletePlan struct {
	Path          string   `json:"path"`
	Type          string   `json:"type"`
	Entries       int      `json:"entries"`
	Bytes         int64    `json:"bytes"`
	First         []string `json:"first"`
	PreviewSHA256 string   `json:"preview_sha256"`
	Deleted       bool     `json:"deleted"`
}

// deleteTempPrefix starts the temporary name an entry is set aside under.
const deleteTempPrefix = ".shell-mcp-delete-"

// previewDomain separates preview hashes from any other SHA-256 input.
const previewDomain = "shell-mcp delete preview v1\x00"

// ValidPreviewSHA256 reports whether s is a preview hash: 64 lowercase hex
// digits.
func ValidPreviewSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// ident is what statx says about one entry.
type ident struct {
	dev, ino, mnt uint64
	typ           uint32 // S_IFMT bits
	perm          uint32 // permission bits (git_discard compares them; a delete does not)
	uid, gid      uint32 // owner and group (the helper's chown and chmod)
	nlink         uint32 // link count (the helper's chown and chmod)
	size          int64
	ctime, btime  unix.StatxTimestamp
	hasBtime      bool
}

const (
	statxWant = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_CTIME | unix.STATX_BTIME | unix.STATX_MNT_ID
	statxNeed = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_CTIME | unix.STATX_MNT_ID
)

// statxAt describes name in the directory dfd without following a
// symlink ("" with AT_EMPTY_PATH: dfd itself). A mount point is described
// as the root of what is mounted on it, so its mount id differs.
func statxAt(dfd int, name string, flags int) (ident, error) {
	var st unix.Statx_t
	if err := unix.Statx(dfd, name, flags|unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_SYNC_AS_STAT, statxWant, &st); err != nil {
		return ident{}, &fs.PathError{Op: "statx", Path: name, Err: err}
	}
	if st.Mask&statxNeed != statxNeed {
		return ident{}, errf(protocol.CodeBadRequest, "the kernel did not report the mount id, inode, type, size and change time "+
			"(statx, Linux 5.8 or later) that a delete needs; nothing was deleted")
	}
	return ident{
		dev: unix.Mkdev(st.Dev_major, st.Dev_minor), ino: st.Ino, mnt: st.Mnt_id, typ: uint32(st.Mode) & unix.S_IFMT, perm: uint32(st.Mode) & 0o7777,
		size: int64(st.Size), ctime: st.Ctime, btime: st.Btime, hasBtime: st.Mask&unix.STATX_BTIME != 0, //nolint:gosec // G115: file sizes fit int64
	}, nil
}

func (a *ident) isDir() bool { return a.typ == unix.S_IFDIR }

// sameObject: the same inode on the same mount, as far as the filesystem
// can tell (the birth time separates a reused inode number).
func (a *ident) sameObject(b *ident) bool {
	return a.dev == b.dev && a.ino == b.ino && a.typ == b.typ && a.mnt == b.mnt && a.hasBtime == b.hasBtime &&
		(!a.hasBtime || a.btime == b.btime)
}

// unchanged: the same object, and for anything but a directory (whose
// change time the deletion's own removals move) the same size and change
// time.
func (a *ident) unchanged(b *ident) bool {
	return a.sameObject(b) && (a.isDir() || a.size == b.size && a.ctime == b.ctime)
}

func typeName(t uint32) string {
	switch t {
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFLNK:
		return "symlink"
	}
	return "other"
}

// planEntry is one entry of a delete: its name in its parent, its logical
// and real paths, its identity, and for a directory its entries, sorted by
// name.
type planEntry struct {
	name, lp, rp string
	id           ident
	kids         []*planEntry
}

// plan is a walked tree, its parent directory still open.
type plan struct {
	l         *loc
	parent    *os.File // the target's parent directory
	recursive bool
	top       *planEntry
	entries   int
	bytes     int64
	first     []string
	hash      string
}

func (pl *plan) close() {
	if pl.parent != nil {
		_ = pl.parent.Close()
	}
	pl.l.close()
}

func (pl *plan) result() DeletePlan {
	return DeletePlan{Path: pl.l.p, Type: typeName(pl.top.id.typ), Entries: pl.entries, Bytes: pl.bytes, First: pl.first, PreviewSHA256: pl.hash}
}

func (f *FS) isConfiguredRoot(p string) bool {
	return slices.Contains(f.cfg.WriteRoots, p) || slices.Contains(f.cfg.ReadRoots, p)
}

// PreviewDelete reports what DeleteExact would remove, removing nothing.
func (f *FS) PreviewDelete(p string, recursive bool) (DeletePlan, error) {
	pl, err := f.walkPlan(p, recursive)
	if err != nil {
		return DeletePlan{Path: p, First: []string{}}, err
	}
	defer pl.close()
	return pl.result(), nil
}

// walkPlan locates p under a write root and walks it (see the file
// comment).
func (f *FS) walkPlan(p string, recursive bool) (*plan, error) {
	l, err := f.locate(p, true)
	if err != nil {
		return nil, err
	}
	pl := &plan{l: l, recursive: recursive, first: []string{}}
	if err := f.walkTop(pl); err != nil {
		pl.close()
		return nil, err
	}
	h := sha256.New()
	b := []byte(previewDomain)
	if recursive {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	_, _ = h.Write(b)
	hashTree(h, pl.top, nil)
	pl.hash = hex.EncodeToString(h.Sum(nil))
	return pl, nil
}

func (f *FS) walkTop(pl *plan) error {
	l := pl.l
	if l.parent == nil || f.isConfiguredRoot(l.p) {
		return errf(protocol.CodePathDenied, "a root cannot be deleted")
	}
	if hasSetAsideComponent(l.p) || hasSetAsideComponent(l.targetReal()) {
		return errSetAside()
	}
	var err error
	if pl.parent, err = l.parent.Open("."); err != nil {
		return mapErr(err)
	}
	return withFD(pl.parent, func(pfd int) error {
		pid, err := statxAt(pfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return mapErr(err)
		}
		tid, err := statxAt(pfd, l.base, 0)
		if err != nil {
			return mapErr(err)
		}
		if tid.typ == unix.S_IFLNK {
			return errf(protocol.CodePathDenied, "final path component is a symlink")
		}
		if crossesMount(&pid, &tid) {
			return errf(protocol.CodePathDenied, "the path is a mount point (or the root of another filesystem), which is never deleted")
		}
		if isDevice(&tid) {
			return errDevice()
		}
		pl.top = &planEntry{name: l.base, lp: l.p, rp: l.targetReal(), id: tid}
		if err := f.addEntry(pl, pl.top); err != nil {
			return err
		}
		if !tid.isDir() {
			return nil
		}
		return f.inSubdir(l, l.parent, pl.top, func(sub *os.Root, sfd int) error {
			return f.walkDir(pl, sub, sfd, &pid, pl.top, 1)
		})
	})
}

// crossesMount: child is on another mount than its parent directory, or
// is a directory on another device (a btrfs subvolume, for example). Only
// directories are compared by device: overlayfs reports the underlying
// device for other files.
func crossesMount(parent, child *ident) bool {
	return child.mnt != parent.mnt || child.isDir() && child.dev != parent.dev
}

// inSubdir opens e (a directory in dir) as a verified sub-root, requires
// the identity the walk saw, and calls fn with it and its descriptor.
func (f *FS) inSubdir(l *loc, dir *os.Root, e *planEntry, fn func(sub *os.Root, sfd int) error) error {
	sub, _, _, err := f.openSubdir(l, dir, e.rp, e.name)
	if err != nil {
		return err
	}
	defer func() { _ = sub.Close() }()
	sf, err := sub.Open(".")
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = sf.Close() }()
	return withFD(sf, func(sfd int) error {
		sid, err := statxAt(sfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return mapErr(err)
		}
		if !sid.sameObject(&e.id) {
			return errf(protocol.CodeExists, "a directory was replaced while the tree was read")
		}
		return fn(sub, sfd)
	})
}

func (f *FS) addEntry(pl *plan, e *planEntry) error {
	pl.entries++
	if pl.entries > f.cfg.Limits.MaxDeleteEntries {
		return errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) entries", f.cfg.Limits.MaxDeleteEntries)
	}
	if e.id.typ == unix.S_IFREG {
		pl.bytes += e.id.size
	}
	if len(pl.first) < previewFirst {
		pl.first = append(pl.first, e.lp)
	}
	return nil
}

// walkDir records the entries of node (open as dir, descriptor dfd), in
// byte order of their names, and walks its subdirectories.
func (f *FS) walkDir(pl *plan, dir *os.Root, dfd int, top *ident, node *planEntry, depth int) error {
	if depth > maxTreeDepth {
		return errf(protocol.CodeTooLarge, "tree is deeper than %d levels", maxTreeDepth)
	}
	ents, err := readAll(dir, f.cfg.Limits.MaxDeleteEntries+1)
	if err != nil {
		return err
	}
	if len(ents) > 0 && !pl.recursive {
		return errf(protocol.CodeBadRequest, "directory is not empty; set recursive to delete it")
	}
	names := make([]string, 0, len(ents))
	for _, en := range ents {
		names = append(names, en.Name())
	}
	slices.Sort(names)
	for _, name := range names {
		e := &planEntry{name: name, lp: join(node.lp, name), rp: join(node.rp, name)}
		if strings.HasPrefix(name, deleteTempPrefix) {
			return errSetAside()
		}
		if err := f.checkPath(e.lp, true); err != nil {
			return err
		}
		if err := f.checkPath(e.rp, true); err != nil {
			return err
		}
		if f.isConfiguredRoot(e.lp) || f.isConfiguredRoot(e.rp) {
			return errf(protocol.CodePathDenied, "the tree holds a configured root, which cannot be deleted")
		}
		if e.id, err = statxAt(dfd, name, 0); err != nil {
			return mapErr(err)
		}
		if crossesMount(top, &e.id) {
			return errf(protocol.CodePathDenied, "the tree holds a mount point (or the root of another filesystem), which is never deleted or entered")
		}
		if isDevice(&e.id) {
			return errDevice()
		}
		node.kids = append(node.kids, e)
		if err := f.addEntry(pl, e); err != nil {
			return err
		}
		if e.id.isDir() {
			if err := f.inSubdir(pl.l, dir, e, func(sub *os.Root, sfd int) error {
				return f.walkDir(pl, sub, sfd, top, e, depth+1)
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// hashTree writes e and everything under it, in walk order, to h.
func hashTree(h interface{ Write([]byte) (int, error) }, e *planEntry, buf []byte) []byte {
	buf = appendPreviewEntry(buf[:0], e.lp, &e.id)
	_, _ = h.Write(buf)
	for _, k := range e.kids {
		buf = hashTree(h, k, buf)
	}
	return buf
}

// appendPreviewEntry appends one entry's hash input: its path (length
// first), type, size, device, inode, change time, and birth time when the
// filesystem reports one. Every field has a fixed width or a length, so
// different entries never encode alike (FuzzPreviewEntryEncoding).
func appendPreviewEntry(b []byte, path string, id *ident) []byte {
	b = binary.AppendUvarint(b, uint64(len(path)))
	b = append(b, path...)
	b = binary.BigEndian.AppendUint32(b, id.typ)
	b = binary.BigEndian.AppendUint64(b, uint64(id.size)) //nolint:gosec // G115: a size's bits, not its value
	b = binary.BigEndian.AppendUint64(b, id.dev)
	b = binary.BigEndian.AppendUint64(b, id.ino)
	b = binary.BigEndian.AppendUint64(b, uint64(id.ctime.Sec)) //nolint:gosec // G115: a time's bits, not its value
	b = binary.BigEndian.AppendUint32(b, id.ctime.Nsec)
	if !id.hasBtime {
		return append(b, 0)
	}
	b = append(b, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(id.btime.Sec)) //nolint:gosec // G115: a time's bits, not its value
	return binary.BigEndian.AppendUint32(b, id.btime.Nsec)
}

// DeleteExact removes what PreviewDelete reported for the same path and
// recursive flag, if its preview_sha256 is still expected (see the file
// comment).
func (f *FS) DeleteExact(p string, recursive bool, expected string) (DeletePlan, error) {
	res := DeletePlan{Path: p, First: []string{}}
	if !ValidPreviewSHA256(expected) {
		return res, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that delete_preview returned")
	}
	pl, err := f.walkPlan(p, recursive)
	if err != nil {
		return res, err
	}
	defer pl.close()
	res = pl.result()
	if pl.hash != expected {
		return res, errf(protocol.CodeExists, "the path changed since the preview (its preview_sha256 differs); nothing was deleted")
	}
	f.step(DeleteStepAfterCompare, p)
	d := &deleter{f: f, pl: pl}
	err = withFD(pl.parent, func(pfd int) error {
		if pl.top.id.isDir() {
			if ierr := f.inSubdir(pl.l, pl.l.parent, pl.top, func(sub *os.Root, sfd int) error {
				return d.empty(sub, sfd, pl.top)
			}); ierr != nil {
				return ierr
			}
		}
		return d.remove(pfd, pl.top)
	})
	if err != nil {
		return res, d.stopped(err)
	}
	res.Deleted = true
	return res, nil
}

func (f *FS) step(s DeleteStep, p string) {
	if f.cfg.InjectDeleteStep != nil {
		f.cfg.InjectDeleteStep(s, p)
	}
}

// deleter is one deletion pass.
type deleter struct {
	f       *FS
	pl      *plan
	deleted int
	// setAside names an entry that could not be put back under its name
	// (taken again meanwhile); it was not deleted.
	setAside string
	// setAsideFrom is the name it appeared under.
	setAsideFrom string
	// touched are the inodes (device, inode) of non-directories this pass
	// has already renamed or unlinked under another of their names: their
	// change time moved because of this pass (a hard link).
	touched map[[2]uint64]bool
}

// changed is the refusal for an entry that is not what the preview saw.
type changed struct{ reason string }

func (c *changed) Error() string { return c.reason }

// unsupported is the refusal for a filesystem without RENAME_NOREPLACE.
type unsupported struct{}

func (*unsupported) Error() string { return "unsupported" }

// empty removes node's entries (node is open as dir, descriptor dfd).
func (d *deleter) empty(dir *os.Root, dfd int, node *planEntry) error {
	for _, k := range node.kids {
		if k.id.isDir() {
			if err := d.f.inSubdir(d.pl.l, dir, k, func(sub *os.Root, sfd int) error {
				return d.empty(sub, sfd, k)
			}); err != nil {
				return err
			}
		}
		if err := d.remove(dfd, k); err != nil {
			return err
		}
	}
	return nil
}

// remove removes e from the directory dfd in the four steps of the
// file comment.
func (d *deleter) remove(dfd int, e *planEntry) error {
	f := d.f
	f.step(DeleteStepBeforeEntry, e.lp)
	pre, err := statxAt(dfd, e.name, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &changed{"an entry of the preview is gone"}
	case err != nil:
		return err
	case !d.stillListed(&pre, e):
		return &changed{"an entry of the preview was replaced or changed"}
	}
	tmp := deleteTempPrefix + randHex(16)
	if e := f.checkPath(join(dirOf(e.lp), tmp), true); e != nil {
		return e
	}
	f.step(DeleteStepBeforeRename, e.lp)
	if f.cfg.InjectNoReplaceFault != nil {
		err = f.cfg.InjectNoReplaceFault()
	} else {
		err = unix.Renameat2(dfd, e.name, dfd, tmp, unix.RENAME_NOREPLACE)
	}
	switch {
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
		return &unsupported{}
	case errors.Is(err, syscall.ENOENT):
		return &changed{"an entry of the preview is gone"}
	case err != nil:
		return mapErr(err)
	}
	if !e.id.isDir() {
		if d.touched == nil {
			d.touched = map[[2]uint64]bool{}
		}
		d.touched[key2(&e.id)] = true
	}
	f.step(DeleteStepAfterRename, e.lp)
	post, err := statxAt(dfd, tmp, 0)
	if err != nil || !post.sameObject(&e.id) {
		d.restore(dfd, tmp, e)
		return &changed{"an entry of the preview was replaced while it was being deleted"}
	}
	f.step(DeleteStepBeforeUnlink, e.lp)
	flags := 0
	if e.id.isDir() {
		flags = unix.AT_REMOVEDIR
	}
	if err := unix.Unlinkat(dfd, tmp, flags); err != nil {
		d.restore(dfd, tmp, e)
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
			return &changed{"a directory gained entries during deletion"}
		}
		return mapErr(err)
	}
	d.deleted++
	return nil
}

// restore puts what was set aside as tmp back under e's name, never
// replacing anything that took the name meanwhile.
func (d *deleter) restore(dfd int, tmp string, e *planEntry) {
	if err := unix.Renameat2(dfd, tmp, dfd, e.name, unix.RENAME_NOREPLACE); err != nil {
		d.setAside, d.setAsideFrom = join(dirOf(e.lp), tmp), e.lp
	}
}

func dirOf(p string) string {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "/"
}

// stopped is the error of a deletion pass that stopped: why, and what was
// and was not deleted.
func (d *deleter) stopped(err error) error {
	code, reason := protocol.CodeInternal, "filesystem error"
	var ch *changed
	var un *unsupported
	var fe *Error
	switch {
	case errors.As(err, &ch):
		code, reason = protocol.CodeExists, ch.reason
	case errors.As(err, &un):
		code, reason = protocol.CodeBadRequest, "the filesystem does not support RENAME_NOREPLACE, which a delete needs to set each "+
			"entry aside before checking and removing it"
	case errors.As(err, &fe):
		code, reason = fe.Code, fe.Msg
	default:
		if me := mapErr(err); me != nil {
			code, reason = me.Code, me.Msg
		}
	}
	total := d.pl.entries
	msg := fmt.Sprintf("deletion stopped: %s; nothing was deleted (0 of %d entries)", reason, total)
	if d.deleted > 0 {
		msg = fmt.Sprintf("deletion stopped: %s; %d of %d entries were deleted and %d were not (preview the path again to see what remains); "+
			"nothing outside the preview was deleted", reason, d.deleted, total, total-d.deleted)
	}
	if d.setAside != "" {
		msg += fmt.Sprintf("; the entry set aside from %s could not be put back because that name was taken again; it was left, not deleted, as %s", d.setAsideFrom, d.setAside)
	}
	out := errf(code, "%s", msg)
	out.SetAside = d.setAside
	return out
}

// isDevice: a character or block device node. The gate's Landlock
// sandbox grants no right to create one in a write root (POLICY §4a), and
// setting an entry aside is a rename, which needs it; refusing device
// nodes in the walk keeps the delete all or nothing.
func isDevice(id *ident) bool { return id.typ == unix.S_IFCHR || id.typ == unix.S_IFBLK }

func errDevice() error {
	return errf(protocol.CodePathDenied, "the path is or holds a device node, which a delete never removes")
}

// key2 identifies an inode.
func key2(id *ident) [2]uint64 { return [2]uint64{id.dev, id.ino} }

// hasSetAsideComponent: a component of p carries the set-aside prefix.
func hasSetAsideComponent(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(c string) bool { return strings.HasPrefix(c, deleteTempPrefix) })
}

// errSetAside refuses a path that is or holds an entry an earlier delete
// set aside and did not remove (it could not put it back, or the gate died
// part-way): such an entry is never deleted; an operator recovers it
// (POLICY §3).
func errSetAside() error {
	return errf(protocol.CodePathDenied, "the path is or holds an entry set aside by an earlier delete (a name starting with "+
		deleteTempPrefix+"), which is never deleted; recover it first (see the policy documentation)")
}

// ErrNoReplaceUnsupported is ProbeNoReplace's answer for a filesystem
// without RENAME_NOREPLACE.
var ErrNoReplaceUnsupported = errors.New("the filesystem does not support RENAME_NOREPLACE")

// probePrefix starts the names ProbeNoReplace creates and removes.
const probePrefix = ".shell-mcp-probe-"

// ProbeNoReplace reports whether dir's filesystem supports RENAME_NOREPLACE
// (check-policy, for each write root): it creates a file under a fresh
// name in dir, renames it to another fresh name with RENAME_NOREPLACE, and
// removes it. A filesystem that refuses the flag (EINVAL, ENOSYS) is
// ErrNoReplaceUnsupported; any other failure is returned as is. Nothing is
// left behind unless the process dies between the steps (a name starting
// with .shell-mcp-probe-).
func ProbeNoReplace(dir string) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	a, b := probePrefix+randHex(16), probePrefix+randHex(16)
	fh, err := r.OpenFile(a, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err = fh.Close(); err != nil {
		_ = r.Remove(a)
		return err
	}
	d, err := r.Open(".")
	if err != nil {
		_ = r.Remove(a)
		return err
	}
	defer func() { _ = d.Close() }()
	var rerr error
	if err = withFD(d, func(fd int) error {
		rerr = unix.Renameat2(fd, a, fd, b, unix.RENAME_NOREPLACE)
		return nil
	}); err != nil {
		_ = r.Remove(a)
		return err
	}
	switch {
	case rerr == nil:
		return r.Remove(b)
	case errors.Is(rerr, syscall.EINVAL), errors.Is(rerr, syscall.ENOSYS):
		_ = r.Remove(a)
		return ErrNoReplaceUnsupported
	}
	_ = r.Remove(a)
	return &fs.PathError{Op: "renameat2", Path: dir, Err: rerr}
}

// stillListed is step 1's check: pre (what is under e's name now) is the
// entry the walk listed. A non-directory this pass already renamed or
// unlinked under another of its names (a hard link) is compared by object
// and size only, since that moved its change time.
func (d *deleter) stillListed(pre *ident, e *planEntry) bool {
	if d.touched[key2(&e.id)] {
		return pre.sameObject(&e.id) && pre.size == e.id.size
	}
	return pre.unchanged(&e.id)
}
