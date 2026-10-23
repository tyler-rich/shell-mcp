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

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged helper's chown and chmod (PRIVILEGED §6; handoff
// docs/handoff/S4C-PRIVILEGED.md D4, N-1, F-2, X-10): root changes the
// owner or mode of existing inodes in place, so it must change exactly the
// inodes the approver saw, and only inodes that nobody else could have put
// under the write root.
//
// PreviewMeta walks the target (with recursive, the tree under it) as
// PreviewDelete does: each directory opened as an os.Root from its parent's
// handle and re-checked by requested and real path and by statx identity,
// never following a symlink and never entering another mount. It refuses
// roots, mount points, device nodes, FIFOs and sockets, set-aside names,
// denied and protected paths, setuid, setgid and sticky entries, and
// non-directories with more than one link (another name could lie outside
// the write roots, F-2). It returns the counts, the first entries with
// their current and new values, and preview_sha256: a SHA-256 over the
// change asked for, the caller's binding (the helper's policy hash) and
// every entry's path, type, device, inode, birth time (where the filesystem
// reports one), owner, group and mode. Size and change time are not in it:
// a content change does not matter to a chown or chmod. Nor is the mount id:
// stx_mnt_id is local to the mount namespace that read it, every helper
// instance has a namespace of its own whose mounts get new ids (the lowest
// free ones), so the preview's instance and the operation's can see
// different ids for an unchanged tree. A mount placed into the tree is
// refused by the walk itself, which compares mount ids within one instance.
//
// The chain rule (N-1). An account that can write a directory under the
// write root and the directory of a file elsewhere on the same filesystem
// could move that file in, have it changed, and move it out again; the
// link count stays 1. So an entry is changed only when every directory
// from / to it is owned by a trusted uid (root; Config.TrustedDirOwner) and
// is neither group- nor world-writable (the group bits are the ACL mask's,
// an upper bound on every named ACL entry): then only root can have put it
// there. The directories from / to the target's parent are checked by
// descriptor, each opened from the previous one with O_PATH|O_NOFOLLOW
// (never by a separate lookup of a path), and the last must be the parent
// fsx holds; inside a tree, every directory that holds entries is checked
// as the walk opens it.
//
// ApplyMeta repeats the walk and refuses (exists, nothing changed) unless
// its hash equals expected_preview_sha256. It then changes the entries that
// need it, children before their directory and the target last, each on a
// descriptor opened by its single-component name from its parent's handle
// (O_NOFOLLOW): the descriptor's statx must show the object the walk saw
// (device, inode, type, mount id, birth time) with the same owner, group
// and mode, its link count is checked on that descriptor (F-2), then
// fchown or fchmod acts on it and fstat on it reads the change back
// (X-10): a mismatch is verify_failed. Change times are never compared
// (the change itself moves them). A newcomer is never changed (no
// directory is read again); an entry replaced, changed or removed stops
// the pass with exists and says how many entries were changed. There is
// no rollback; the helper's audit line records every entry changed with its
// old values (Q8). A link made after an entry's check is equivalent to one
// made after its change, as for S4c-0's chmod.

// MetaOp is the kind of metadata change.
type MetaOp int

// Metadata changes.
const (
	MetaChown MetaOp = iota + 1
	MetaChmod
)

// MetaChange is what a chown or chmod sets: for MetaChown the owner and/or
// group (nil is kept), for MetaChmod the mode (permission bits only).
type MetaChange struct {
	Op       MetaOp
	UID, GID *uint32
	Mode     os.FileMode
}

// MetaStep names a point of ApplyMeta's pass, for tests
// (Config.InjectMetaStep).
type MetaStep int

// Points of the pass.
const (
	// MetaStepAfterCompare: the preview hash matched; nothing is changed yet.
	MetaStepAfterCompare MetaStep = iota + 1
	// MetaStepBeforeEntry: before an entry is opened by its name.
	MetaStepBeforeEntry
	// MetaStepBeforeChange: after its check on the descriptor, before the
	// change.
	MetaStepBeforeChange
)

// MetaEntry is one entry of a plan: its current owner, group and mode,
// those it gets, and whether it changes (symlinks never do).
type MetaEntry struct {
	Path, Type              string
	UID, GID, Mode          uint32
	NewUID, NewGID, NewMode uint32
	Change                  bool
}

// MetaChanged is an entry ApplyMeta changed, with its values before (for
// the helper's audit; also when its read-back then failed).
type MetaChanged struct {
	Path   string
	Before Meta
}

// MetaPlan is PreviewMeta's and ApplyMeta's result: the target's type, the
// entry count (the target included), how many entries change, the first
// entries (at most 50, in walk order) and the hash; Top is the target's
// entry. ApplyMeta adds what it changed, and Done when it changed
// everything the plan said.
type MetaPlan struct {
	Path          string
	Type          string
	Entries       int
	Changes       int
	First         []MetaEntry
	PreviewSHA256 string
	Top           MetaEntry
	Changed       []MetaChanged
	Done          bool
}

// metaDomain separates metadata preview hashes from any other SHA-256 input.
// v2: the mount id left out of every entry (handoff D4, as amended).
const metaDomain = "shell-mcp metadata preview v2\x00"

// statxMeta is what the chain rule and the pass need beyond a delete's.
const statxMeta = unix.STATX_UID | unix.STATX_GID | unix.STATX_MODE | unix.STATX_NLINK

type metaNode struct {
	name, lp, rp string
	id           ident
	change       bool
	kids         []*metaNode
}

type metaPlan struct {
	l         *loc
	parent    *os.File // the target's parent directory
	ch        MetaChange
	recursive bool
	top       *metaNode
	entries   int
	changes   int
	first     []MetaEntry
	hash      string
}

func (pl *metaPlan) close() {
	if pl.parent != nil {
		_ = pl.parent.Close()
	}
	pl.l.close()
}

func (pl *metaPlan) entry(e *metaNode) MetaEntry {
	me := MetaEntry{Path: e.lp, Type: typeName(e.id.typ), UID: e.id.uid, GID: e.id.gid, Mode: e.id.perm,
		NewUID: e.id.uid, NewGID: e.id.gid, NewMode: e.id.perm, Change: e.change}
	if e.id.typ == unix.S_IFLNK {
		return me
	}
	switch pl.ch.Op {
	case MetaChown:
		if pl.ch.UID != nil {
			me.NewUID = *pl.ch.UID
		}
		if pl.ch.GID != nil {
			me.NewGID = *pl.ch.GID
		}
	case MetaChmod:
		me.NewMode = uint32(pl.ch.Mode.Perm())
	}
	return me
}

func (pl *metaPlan) result() MetaPlan {
	return MetaPlan{Path: pl.l.p, Type: typeName(pl.top.id.typ), Entries: pl.entries, Changes: pl.changes, First: pl.first,
		PreviewSHA256: pl.hash, Top: pl.entry(pl.top)}
}

// trustedOwner: whose directories the chain rule trusts (root unless the
// helper says otherwise).
func (f *FS) trustedOwner(uid uint32) bool {
	if f.cfg.TrustedDirOwner == nil {
		return uid == 0
	}
	return f.cfg.TrustedDirOwner(uid)
}

// closedDir: a directory no other account can add entries to or remove
// them from: owned by a trusted uid and neither group- nor world-writable.
func (f *FS) closedDir(id *ident) bool {
	return f.trustedOwner(id.uid) && id.perm&0o022 == 0
}

// why says why a directory is not closed.
func (f *FS) why(id *ident) string {
	var r []string
	if !f.trustedOwner(id.uid) {
		r = append(r, fmt.Sprintf("owned by uid %d", id.uid))
	}
	if id.perm&0o022 != 0 {
		r = append(r, fmt.Sprintf("group- or world-writable (mode %04o)", id.perm))
	}
	return strings.Join(r, " and ")
}

// chainDirName names a directory on the path to l's target in a refusal:
// its logical path where it can be derived from the request.
func (l *loc) chainDirName(rp string) string {
	switch {
	case rp == l.rootReal:
		return "the directory " + l.root
	case pathx.Within(l.rootReal, rp):
		return "the directory " + join(l.root, pathx.Rel(l.rootReal, rp))
	case l.rootReal == l.root:
		return "the directory " + rp
	case !l.write:
		return "a directory above the root"
	}
	return "a directory above the write root"
}

// chainCheck opens every directory from / to rp (a clean absolute path),
// each from the previous one's descriptor with O_PATH|O_NOFOLLOW, calls
// check with each one's path and identity, and returns the last identity.
// No path is looked up again: a directory renamed or replaced meanwhile is
// either the one checked or fails the next open.
func chainCheck(rp string, check func(dir string, id *ident) error) (ident, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ident{}, mapErr(&fs.PathError{Op: "open", Path: "/", Err: err})
	}
	var comps []string
	if rp != "/" {
		comps = strings.Split(rp[1:], "/")
	}
	cur := "/"
	for i := 0; ; i++ {
		id, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
		if err == nil && id.mask&statxMeta != statxMeta {
			err = errf(protocol.CodeBadRequest, "the kernel did not report the owner and mode (statx) that the helper checks on a path; nothing was done")
		}
		if err == nil {
			err = check(cur, &id)
		}
		if err != nil || i == len(comps) {
			_ = unix.Close(fd)
			return id, err
		}
		nfd, oerr := unix.Openat(fd, comps[i], unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		cur = join(cur, comps[i])
		if oerr != nil {
			return ident{}, mapErr(&fs.PathError{Op: "openat", Path: cur, Err: oerr})
		}
		fd = nfd
	}
}

// ChainError is a directory on a path that an account other than a trusted
// one could write (CheckRootChain).
type ChainError struct {
	Dir      string
	UID      uint32
	Mode     uint32
	Owner    bool // owned by an untrusted uid
	Writable bool // group- or world-writable
}

func (e *ChainError) Error() string {
	var r []string
	if e.Owner {
		r = append(r, fmt.Sprintf("is owned by uid %d", e.UID))
	}
	if e.Writable {
		r = append(r, fmt.Sprintf("is group- or world-writable (mode %04o)", e.Mode))
	}
	return e.Dir + " " + strings.Join(r, " and ")
}

// CheckRootChain applies the chain rule to dir itself (check-policy, for
// each privileged write root): every directory from / to dir, dir
// included, by descriptor, must be owned by a uid trusted accepts (nil:
// root) and be neither group- nor world-writable. A failing directory is a
// *ChainError; anything else that stops the check is returned as is.
func CheckRootChain(dir string, trusted func(uint32) bool) error {
	if trusted == nil {
		trusted = func(uid uint32) bool { return uid == 0 }
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	rp, err := realPathOfRoot(r)
	if err != nil {
		return err
	}
	d, err := r.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return withFD(d, func(dfd int) error {
		want, err := statxAt(dfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return err
		}
		last, err := chainCheck(rp, func(cur string, id *ident) error {
			ce := &ChainError{Dir: cur, UID: id.uid, Mode: id.perm, Owner: !trusted(id.uid), Writable: id.perm&0o022 != 0}
			if ce.Owner || ce.Writable {
				return ce
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !last.sameObject(&want) {
			return errors.New("the directory changed while its path was checked")
		}
		return nil
	})
}

// checkChange validates what is asked for.
func checkChange(ch MetaChange) *Error {
	switch ch.Op {
	case MetaChown:
		if ch.UID == nil && ch.GID == nil {
			return errf(protocol.CodeBadRequest, "an owner or a group is required")
		}
		return nil
	case MetaChmod:
		return checkMode(ch.Mode)
	}
	return errf(protocol.CodeBadRequest, "unknown metadata change")
}

// wants reports whether e must change for ch (symlinks never change).
func wants(ch MetaChange, id *ident) bool {
	switch {
	case id.typ == unix.S_IFLNK:
		return false
	case ch.Op == MetaChown:
		return ch.UID != nil && *ch.UID != id.uid || ch.GID != nil && *ch.GID != id.gid
	}
	return id.perm != uint32(ch.Mode.Perm())
}

// metaChecks are the per-entry refusals for a regular file or directory,
// on an identity from the walk or from the descriptor about to be changed.
func metaChecks(p string, id *ident) *Error {
	if id.mask&statxMeta != statxMeta {
		return errf(protocol.CodeBadRequest, "the kernel did not report the owner, mode and link count (statx) that chmod and chown need; nothing was changed")
	}
	if id.perm&0o7000 != 0 {
		return errf(protocol.CodePolicyDenied, "%q has setuid, setgid or sticky bits: such files are never changed", p)
	}
	if !id.isDir() && id.nlink > 1 {
		return errf(protocol.CodePathDenied, "%q has %d links: its mode and owner are changed only when it has one, since another name can lie outside the write roots", p, id.nlink)
	}
	return nil
}

func errSetAsideMeta() error {
	return errf(protocol.CodePathDenied, "the path is or holds an entry set aside by an earlier delete (a name starting with "+
		deleteTempPrefix+"), whose mode and owner are never changed; recover it first (see the policy documentation)")
}

// PreviewMeta reports what ApplyMeta would change, changing nothing. bind
// is hashed in (the helper's policy hash).
func (f *FS) PreviewMeta(p string, ch MetaChange, recursive bool, bind string) (MetaPlan, error) {
	pl, err := f.walkMeta(p, ch, recursive, bind)
	if err != nil {
		return MetaPlan{Path: p, First: []MetaEntry{}}, err
	}
	defer pl.close()
	return pl.result(), nil
}

func (f *FS) walkMeta(p string, ch MetaChange, recursive bool, bind string) (*metaPlan, error) {
	if e := checkChange(ch); e != nil {
		return nil, e
	}
	l, err := f.locate(p, true)
	if err != nil {
		return nil, err
	}
	pl := &metaPlan{l: l, ch: ch, recursive: recursive, first: []MetaEntry{}}
	if err := f.walkMetaTop(pl); err != nil {
		pl.close()
		return nil, err
	}
	pl.hash = metaHash(pl, bind)
	return pl, nil
}

func (f *FS) walkMetaTop(pl *metaPlan) error {
	l := pl.l
	if l.parent == nil || f.isConfiguredRoot(l.p) {
		return errf(protocol.CodePathDenied, "a root's mode and owner are never changed")
	}
	if hasSetAsideComponent(l.p) || hasSetAsideComponent(l.targetReal()) {
		return errSetAsideMeta()
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
		// Every directory from / to the parent, by descriptor, ending at
		// the parent fsx holds.
		last, err := chainCheck(l.parentReal, func(dir string, id *ident) error {
			if !f.closedDir(id) {
				return errf(protocol.CodePathDenied, "%q is never changed as root: %s on its path is %s, so another account could have moved it there "+
					"and could move it out again; nothing was changed", l.p, l.chainDirName(dir), f.why(id))
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !last.sameObject(&pid) {
			return errf(protocol.CodePathDenied, "the path changed while it was checked; nothing was changed")
		}
		tid, err := statxAt(pfd, l.base, 0)
		if err != nil {
			return mapErr(err)
		}
		switch {
		case tid.typ == unix.S_IFLNK:
			return errf(protocol.CodePathDenied, "final path component is a symlink")
		case crossesMount(&pid, &tid):
			return errf(protocol.CodePathDenied, "the path is a mount point (or the root of another filesystem), whose mode and owner are never changed")
		case tid.typ != unix.S_IFREG && tid.typ != unix.S_IFDIR:
			return errf(protocol.CodeBadRequest, "only regular files and directories")
		}
		if e := metaChecks(l.p, &tid); e != nil {
			return e
		}
		pl.top = &metaNode{name: l.base, lp: l.p, rp: l.targetReal(), id: tid}
		if err := f.addMeta(pl, pl.top); err != nil {
			return err
		}
		if !tid.isDir() || !pl.recursive {
			return nil
		}
		return f.inDir(l, l.parent, pl.top.name, pl.top.rp, &pl.top.id, func(sub *os.Root, sfd int) error {
			return f.walkMetaDir(pl, sub, sfd, &pid, pl.top, 1)
		})
	})
}

func (f *FS) addMeta(pl *metaPlan, e *metaNode) error {
	pl.entries++
	if pl.entries > f.cfg.Limits.MaxDeleteEntries {
		return errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) entries", f.cfg.Limits.MaxDeleteEntries)
	}
	e.change = wants(pl.ch, &e.id)
	if e.change {
		pl.changes++
	}
	if len(pl.first) < previewFirst {
		pl.first = append(pl.first, pl.entry(e))
	}
	return nil
}

// walkMetaDir records the entries of node (open as dir, descriptor dfd), in
// byte order of their names, and walks its subdirectories.
func (f *FS) walkMetaDir(pl *metaPlan, dir *os.Root, dfd int, top *ident, node *metaNode, depth int) error {
	if depth > maxTreeDepth {
		return errf(protocol.CodeTooLarge, "tree is deeper than %d levels", maxTreeDepth)
	}
	ents, err := readAll(dir, f.cfg.Limits.MaxDeleteEntries+1)
	if err != nil {
		return err
	}
	if len(ents) > 0 && !f.closedDir(&node.id) {
		return errf(protocol.CodePathDenied, "the entries of %q are never changed as root: it is %s, so another account could have moved them there "+
			"and could move them out again; nothing was changed", node.lp, f.why(&node.id))
	}
	names := make([]string, 0, len(ents))
	for _, en := range ents {
		names = append(names, en.Name())
	}
	slices.Sort(names)
	for _, name := range names {
		e := &metaNode{name: name, lp: join(node.lp, name), rp: join(node.rp, name)}
		if strings.HasPrefix(name, deleteTempPrefix) {
			return errSetAsideMeta()
		}
		if serr := f.stagedRefused(name); serr != nil {
			return serr
		}
		if err := f.checkPath(e.lp, true); err != nil {
			return err
		}
		if err := f.checkPath(e.rp, true); err != nil {
			return err
		}
		if f.isConfiguredRoot(e.lp) || f.isConfiguredRoot(e.rp) {
			return errf(protocol.CodePathDenied, "the tree holds a configured root, whose mode and owner are never changed")
		}
		if e.id, err = statxAt(dfd, name, 0); err != nil {
			return mapErr(err)
		}
		if crossesMount(top, &e.id) {
			return errf(protocol.CodePathDenied, "the tree holds a mount point (or the root of another filesystem), which is never changed or entered")
		}
		switch e.id.typ {
		case unix.S_IFREG, unix.S_IFDIR:
			if err := metaChecks(e.lp, &e.id); err != nil {
				return err
			}
		case unix.S_IFLNK:
		default:
			return errf(protocol.CodePathDenied, "the tree holds a device node, FIFO or socket (%q), whose mode and owner are never changed", e.lp)
		}
		node.kids = append(node.kids, e)
		if err := f.addMeta(pl, e); err != nil {
			return err
		}
		if e.id.isDir() {
			if err := f.inDir(pl.l, dir, e.name, e.rp, &e.id, func(sub *os.Root, sfd int) error {
				return f.walkMetaDir(pl, sub, sfd, top, e, depth+1)
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// metaHash is the plan's preview_sha256: the change, recursive, bind and
// every entry in walk order.
func metaHash(pl *metaPlan, bind string) string {
	h := sha256.New()
	b := append([]byte(metaDomain), byte(pl.ch.Op)) //nolint:gosec // G115: MetaOp is 1 or 2 (checkChange)
	if pl.recursive {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	for _, id := range []*uint32{pl.ch.UID, pl.ch.GID} {
		if id == nil {
			b = append(b, 0)
			continue
		}
		b = binary.BigEndian.AppendUint32(append(b, 1), *id)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(pl.ch.Mode.Perm()))
	b = binary.AppendUvarint(b, uint64(len(bind)))
	b = append(b, bind...)
	_, _ = h.Write(b)
	var walk func(e *metaNode, buf []byte) []byte
	walk = func(e *metaNode, buf []byte) []byte {
		buf = appendMetaEntry(buf[:0], e.lp, &e.id)
		_, _ = h.Write(buf)
		for _, k := range e.kids {
			buf = walk(k, buf)
		}
		return buf
	}
	walk(pl.top, nil)
	return hex.EncodeToString(h.Sum(nil))
}

// appendMetaEntry appends one entry's hash input: its path (length first),
// type, device, inode, owner, group, mode, and birth time when the
// filesystem reports one; never the mount id, which differs between
// helper instances (see the file comment). Every field has a fixed width or
// a length, so different entries never encode alike (FuzzMetaEntryEncoding).
func appendMetaEntry(b []byte, path string, id *ident) []byte {
	b = binary.AppendUvarint(b, uint64(len(path)))
	b = append(b, path...)
	b = binary.BigEndian.AppendUint32(b, id.typ)
	b = binary.BigEndian.AppendUint64(b, id.dev)
	b = binary.BigEndian.AppendUint64(b, id.ino)
	b = binary.BigEndian.AppendUint32(b, id.uid)
	b = binary.BigEndian.AppendUint32(b, id.gid)
	b = binary.BigEndian.AppendUint32(b, id.perm)
	if !id.hasBtime {
		return append(b, 0)
	}
	b = append(b, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(id.btime.Sec)) //nolint:gosec // G115: a time's bits, not its value
	return binary.BigEndian.AppendUint32(b, id.btime.Nsec)
}

// ApplyMeta makes the change PreviewMeta reported for the same path,
// change, recursive flag and bind, if its preview_sha256 is still expected
// (see the file comment).
func (f *FS) ApplyMeta(p string, ch MetaChange, recursive bool, bind, expected string) (MetaPlan, error) {
	res := MetaPlan{Path: p, First: []MetaEntry{}}
	if !ValidPreviewSHA256(expected) {
		return res, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that the operation's preview returned")
	}
	pl, err := f.walkMeta(p, ch, recursive, bind)
	if err != nil {
		return res, err
	}
	defer pl.close()
	res = pl.result()
	if pl.hash != expected {
		return res, errf(protocol.CodeExists, "the path changed since the preview (its preview_sha256 differs); nothing was changed")
	}
	f.metaStep(MetaStepAfterCompare, p)
	a := &metaApplier{f: f, pl: pl}
	err = withFD(pl.parent, func(pfd int) error {
		if pl.recursive && pl.top.id.isDir() {
			if kerr := f.inDir(pl.l, pl.l.parent, pl.top.name, pl.top.rp, &pl.top.id, func(sub *os.Root, sfd int) error {
				return a.kids(sub, sfd, pl.top)
			}); kerr != nil {
				return kerr
			}
		}
		return a.change(pfd, pl.top)
	})
	res.Changed = a.changed
	if err != nil {
		return res, a.stopped(err)
	}
	res.Done = true
	return res, nil
}

func (f *FS) metaStep(s MetaStep, p string) {
	if f.cfg.InjectMetaStep != nil {
		f.cfg.InjectMetaStep(s, p)
	}
}

// metaApplier is one pass of ApplyMeta.
type metaApplier struct {
	f       *FS
	pl      *metaPlan
	changed []MetaChanged
}

// kids changes node's entries (node is open as dir, descriptor dfd), each
// directory's entries before the directory itself.
func (a *metaApplier) kids(dir *os.Root, dfd int, node *metaNode) error {
	for _, k := range node.kids {
		if k.id.isDir() {
			if err := a.f.inDir(a.pl.l, dir, k.name, k.rp, &k.id, func(sub *os.Root, sfd int) error {
				return a.kids(sub, sfd, k)
			}); err != nil {
				return err
			}
		}
		if err := a.change(dfd, k); err != nil {
			return err
		}
	}
	return nil
}

// change changes e (in the directory dfd) on a descriptor opened by its
// name and checked, then reads the change back through it.
func (a *metaApplier) change(dfd int, e *metaNode) error {
	if !e.change {
		return nil
	}
	f := a.f
	f.metaStep(MetaStepBeforeEntry, e.lp)
	fd, err := unix.Openat(dfd, e.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, syscall.ENOENT):
		return &changed{"an entry of the preview is gone"}
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENXIO), errors.Is(err, syscall.ENODEV), errors.Is(err, syscall.EWOULDBLOCK):
		return &changed{"an entry of the preview was replaced"}
	case err != nil:
		return mapErr(err)
	}
	defer func() { _ = unix.Close(fd) }()
	cur, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return mapErr(err)
	}
	if !cur.sameObject(&e.id) || cur.uid != e.id.uid || cur.gid != e.id.gid || cur.perm != e.id.perm {
		return &changed{"an entry of the preview was replaced or changed"}
	}
	// The link count, on the descriptor that is changed (F-2).
	if e := metaChecks(e.lp, &cur); e != nil {
		return e
	}
	f.metaStep(MetaStepBeforeChange, e.lp)
	before := Meta{Mode: cur.perm, UID: cur.uid, GID: cur.gid}
	want := before
	switch a.pl.ch.Op {
	case MetaChown:
		uid, gid := -1, -1
		if a.pl.ch.UID != nil {
			uid, want.UID = int(*a.pl.ch.UID), *a.pl.ch.UID
		}
		if a.pl.ch.GID != nil {
			gid, want.GID = int(*a.pl.ch.GID), *a.pl.ch.GID
		}
		err = unix.Fchown(fd, uid, gid)
	case MetaChmod:
		want.Mode = uint32(a.pl.ch.Mode.Perm())
		err = unix.Fchmod(fd, want.Mode)
	}
	if err != nil {
		return mapErr(err)
	}
	f.commit()
	a.changed = append(a.changed, MetaChanged{Path: e.lp, Before: before})
	// Read back through the same descriptor (X-10): always, whatever
	// VerifyMetadata says (only the helper uses this pass).
	after, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return errf(protocol.CodeVerifyFailed, "the change to %q could not be read back", e.lp)
	}
	got := Meta{Mode: after.perm, UID: after.uid, GID: after.gid}
	if f.cfg.InjectMetadataReadBackFault != nil {
		got = f.cfg.InjectMetadataReadBackFault(got)
	}
	if got != want {
		return errf(protocol.CodeVerifyFailed, "%q read back mode %04o and owner %d:%d, not the %04o and %d:%d that were set",
			e.lp, got.Mode, got.UID, got.GID, want.Mode, want.UID, want.GID)
	}
	return nil
}

// stopped is the error of a pass that stopped: why, and how many of the
// entries the plan changes were changed.
func (a *metaApplier) stopped(err error) error {
	code, reason := protocol.CodeInternal, "filesystem error"
	var ch *changed
	var fe *Error
	switch {
	case errors.As(err, &ch):
		code, reason = protocol.CodeExists, ch.reason
	case errors.As(err, &fe):
		code, reason = fe.Code, fe.Msg
	default:
		if me := mapErr(err); me != nil {
			code, reason = me.Code, me.Msg
		}
	}
	total, done := a.pl.changes, len(a.changed)
	if done == 0 {
		return errf(code, "change stopped: %s; nothing was changed (0 of %d entries)", reason, total)
	}
	return errf(code, "change stopped: %s; %d of %d entries were changed and %d were not (preview the path again to see what remains); "+
		"nothing outside the preview was changed", reason, done, total, total-done)
}
