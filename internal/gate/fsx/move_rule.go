//go:build linux

package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The move rule (handoff docs/handoff/S4C-PRIVILEGED.md N-17; PRIVILEGED
// §6, "Moves"), applied with Config.GuardMovedIn (the helper). A move keeps
// its inode, owner and mode, so two things the other operations rule out
// would otherwise be open: root placing a file another account put in a
// directory it can write (the source), and root handing a file to another
// account by moving it into a directory that account can write (the
// destination, rule R). So root moves a non-directory only when its owner
// is owner-matched on the chain from the root to the source's parent (no
// world-readable exception: what moves is the inode, not its content) and
// on the chain to the destination's parent; in a moved tree both chains are
// extended by the tree's own directories, read by statx on the descriptor
// the walk opened. Directories are exempt, as priv_mkdir is (another
// account cannot move a directory to another parent without write access
// to it), but every directory of a moved tree must have a mode priv_mkdir
// could create: within modes.max, neither group- nor world-writable, no
// setuid, setgid or sticky bit.
//
// rename(2) acts on a name, so the commit is staged: the source is renamed
// (RENAME_NOREPLACE) under .shell-mcp-move-<32 hex> in the destination's
// directory, checked there to be the inode that was checked (device, inode,
// type, mount id, birth time, owner), and only then renamed to its name
// (RENAME_NOREPLACE) or exchanged with the destination (a verified replace,
// which leaves the replaced file under the staging name in the
// destination's directory until it is removed, never in the source's).
// Anything else staged is put back under the source's name; when that name
// was taken again meanwhile, under another staging name in the source's
// directory, which the refusal names (Error.SetAside). Changes made after
// the walk inside a moved tree's directories can only be made by those
// directories' owners, which the rule has made the owners of every
// non-directory beneath them and which keep those directories after the
// move; they could make the same change afterwards.
//
// A helper that dies between the stage and the commit leaves the staging
// entry. The helper never touches a path through such a name (locate,
// CheckWritable, and the delete, chown/chmod and move walks refuse it),
// and a move into or out of a directory holding one is refused naming it,
// until an operator recovers it.

// moveTempPrefix starts the name a move stages its source under.
const moveTempPrefix = ".shell-mcp-move-"

// maxStagedScan bounds the names of a directory a move reads when it looks
// for entries a stopped move left there.
const maxStagedScan = 1 << 16

// hasStagedComponent: a component of p carries the staging prefix.
func hasStagedComponent(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(c string) bool { return strings.HasPrefix(c, moveTempPrefix) })
}

// errStaged refuses a path that is or holds an entry a move staged and did
// not commit or put back.
func errStaged() error {
	return errf(protocol.CodePathDenied, "the path is or holds an entry left by a move as root that did not finish (a name starting with "+
		moveTempPrefix+"), which the helper never reads, changes, moves or deletes; recover it first (see the privileged helper's documentation)")
}

// stagedRefused applies errStaged to p in the helper.
func (f *FS) stagedRefused(p string) error {
	if f.cfg.GuardMovedIn && hasStagedComponent(p) {
		return errStaged()
	}
	return nil
}

// scanStaged refuses a move when dir (whose logical path is lp) holds an
// entry a stopped move left.
func (f *FS) scanStaged(dir *os.Root, lp string) error {
	ents, err := readAll(dir, maxStagedScan+1)
	if err != nil {
		return err
	}
	if len(ents) > maxStagedScan {
		return unchanged(errf(protocol.CodeTooLarge, "the directory %s holds more than %d entries, which a move as root reads to find entries a stopped move left; nothing was moved",
			lp, maxStagedScan))
	}
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), moveTempPrefix) {
			return unchanged(errf(protocol.CodePathDenied, "the directory %s holds %s, left by a move as root that did not finish (a name starting with %s); "+
				"the helper moves nothing into or out of that directory until it is recovered (see the privileged helper's documentation); nothing was moved",
				lp, join(lp, en.Name()), moveTempPrefix))
		}
	}
	return nil
}

// identIn describes name in dir by statx, never following a symlink.
func identIn(dir *os.Root, name string) (ident, error) {
	d, err := dir.Open(".")
	if err != nil {
		return ident{}, mapErr(err)
	}
	defer func() { _ = d.Close() }()
	var id ident
	err = withFD(d, func(fd int) error {
		var serr error
		flags := 0
		if name == "" {
			flags = unix.AT_EMPTY_PATH
		}
		id, serr = statxAt(fd, name, flags)
		return serr
	})
	if err != nil {
		return ident{}, mapErr(err)
	}
	if id.mask&statxMeta != statxMeta {
		return ident{}, errf(protocol.CodeBadRequest, "the kernel did not report the owner and mode (statx) that a move as root checks; nothing was moved")
	}
	return id, nil
}

// moveRule applies the rule to one non-directory a move places: lp is where
// it is, dst where it goes, uid its owner, src and dstChain the chains (the
// tree's directories included) at either end.
func (f *FS) moveRule(lp, dst string, uid uint32, src, dstChain []ChainDir) error {
	if d := f.MovedInBy(src, uid); d != nil {
		return unchanged(errf(protocol.CodePathDenied, "%q is not moved as root: the directory %s is %s, so another account could have put it there; "+
			"root moves only what no account but root and the owner could have put there; nothing was moved", lp, d.Path, f.MovedInWhy(d, uid)))
	}
	if d := f.MovedInBy(dstChain, uid); d != nil {
		v := f.OwnerVerdictOf(dstChain)
		return unchanged(errf(protocol.CodePathDenied, "%q is not moved as root to %q: the directory %s is %s, so another account could move it elsewhere "+
			"and keep what it could not have made itself; %s; nothing was moved", lp, dst, d.Path, f.MovedInWhy(d, uid), f.ownerHint(&v)))
	}
	return nil
}

// moveDirMode refuses a directory of a moved tree whose mode (perm, the
// permission and special bits) priv_mkdir could not create.
func (f *FS) moveDirMode(lp string, perm uint32) error {
	allowed := uint32(0o755)
	if f.cfg.ModesMax != nil {
		allowed &= uint32(*f.cfg.ModesMax)
	}
	if perm&^allowed == 0 {
		return nil
	}
	var why []string
	if perm&0o7000 != 0 {
		why = append(why, "setuid, setgid or sticky")
	}
	if perm&0o022 != 0 {
		why = append(why, "group- or world-writable")
	}
	if f.cfg.ModesMax != nil && perm&0o777&^uint32(*f.cfg.ModesMax) != 0 {
		why = append(why, fmt.Sprintf("beyond the privileged policy's modes.max %04o", uint32(*f.cfg.ModesMax)))
	}
	return unchanged(errf(protocol.CodePathDenied, "the directory %s has mode %04o (%s), which root's file tools never create; a move as root does not place it; nothing was moved",
		lp, perm, strings.Join(why, "; ")))
}

// chainPlus is chain followed by tree.
func chainPlus(chain, tree []ChainDir) []ChainDir {
	return append(append(make([]ChainDir, 0, len(chain)+len(tree)), chain...), tree...)
}

// moveGuard is what a move in the helper checked before its commit: the
// chains at either end and the source's identity.
type moveGuard struct {
	src, dst []ChainDir
	top      ident
}

// guardMove checks a move in the helper before anything is backed up or
// moved: no staging entry beside either end, the chains at either end,
// the source's identity (which must be sfi, its earlier lstat), and the
// rule for a non-directory source. A directory's contents are checked by
// the walk (guardTree, walkTree).
func (f *FS) guardMove(ls, ld *loc, sfi fs.FileInfo) (*moveGuard, error) {
	if err := f.scanStaged(ls.parent, path.Dir(ls.p)); err != nil {
		return nil, err
	}
	if ld.parentReal != ls.parentReal {
		if err := f.scanStaged(ld.parent, path.Dir(ld.p)); err != nil {
			return nil, err
		}
	}
	g := &moveGuard{}
	var err error
	if g.src, err = f.rootChain(ls); err != nil {
		return nil, err
	}
	if g.dst, err = f.rootChain(ld); err != nil {
		return nil, err
	}
	if g.top, err = identIn(ls.parent, ls.base); err != nil {
		return nil, err
	}
	if st, ok := sfi.Sys().(*syscall.Stat_t); !ok || st.Ino != g.top.ino || uint64(st.Dev) != g.top.dev { //nolint:unconvert // Dev's type differs by architecture
		return nil, unchanged(errf(protocol.CodeExists, "the source changed while it was checked; nothing was moved"))
	}
	if !g.top.isDir() {
		if err := f.moveRule(ls.p, ld.p, g.top.uid, g.src, g.dst); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// guardTree starts the walk of a moved directory: sub, the directory as
// opened, must be the source that was checked, with a mode priv_mkdir
// could create. It returns the tree's chain so far (the directory itself).
func (f *FS) guardTree(g *moveGuard, sub *os.Root, lp string) ([]ChainDir, error) {
	id, err := identIn(sub, "")
	if err != nil {
		return nil, err
	}
	if !id.sameObject(&g.top) {
		return nil, unchanged(errf(protocol.CodeExists, "the source changed while it was checked; nothing was moved"))
	}
	if err := f.moveDirMode(lp, id.perm); err != nil {
		return nil, err
	}
	return []ChainDir{{Path: lp, UID: id.uid, Mode: id.perm}}, nil
}

// treeDir adds sub, a directory of a moved tree opened at lp, to tree,
// after checking its mode.
func (f *FS) treeDir(sub *os.Root, lp string, tree []ChainDir) ([]ChainDir, error) {
	id, err := identIn(sub, "")
	if err != nil {
		return nil, err
	}
	if err := f.moveDirMode(lp, id.perm); err != nil {
		return nil, err
	}
	return chainPlus(tree, []ChainDir{{Path: lp, UID: id.uid, Mode: id.perm}}), nil
}

// guardEntry checks one entry the walk of a moved tree visits (src and dst
// are the move's paths).
func (f *FS) guardEntry(g *moveGuard, e *treeEntry, src, dst string) error {
	if strings.HasPrefix(e.name, moveTempPrefix) {
		return errStaged()
	}
	if e.info.IsDir() {
		return nil // its mode and owner are checked as the walk opens it
	}
	return f.moveRule(e.lp, join(dst, relTo(src, e.lp)), metaOf(e.info).UID, chainPlus(g.src, e.tree), chainPlus(g.dst, e.tree))
}

// relTo is p relative to base (p within base).
func relTo(base, p string) string {
	return strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
}

// commitStaged commits a checked move in the helper: stage, verify, then
// rename (or a verified replace of replaced), putting back what was staged
// when it is not what was checked or the commit is refused.
func (f *FS) commitStaged(ls, ld *loc, g *moveGuard, replace bool, replaced fs.FileInfo) error {
	tmp := moveTempPrefix + randHex(16)
	if err := renameat2(ls.parent, ls.base, ld.parent, tmp, unix.RENAME_NOREPLACE); err != nil {
		switch {
		case errors.Is(err, syscall.ENOENT):
			return unchanged(errf(protocol.CodeNotFound, "the source disappeared before it was moved; nothing was moved"))
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOSYS):
			return unchanged(errf(protocol.CodeBadRequest, "the filesystem does not support RENAME_NOREPLACE, which a move as root needs to stage its "+
				"source; nothing was moved"))
		}
		return unchanged(mapErr(err))
	}
	if f.cfg.InjectAfterStage != nil {
		if err := f.cfg.InjectAfterStage(tmp); err != nil {
			f.commit() // an entry is left staged
			return err
		}
	}
	got, err := identIn(ld.parent, tmp)
	if err != nil || !got.sameObject(&g.top) || got.uid != g.top.uid {
		return f.putBack(ls, ld, tmp, protocol.CodeExists, "the source changed after it was checked (another entry was under its name when it was moved)")
	}
	if replace {
		if e := f.exchangeVerified(ld.parent, tmp, ld.parent, ld.base, replaced); e != nil {
			if !e.Unchanged {
				return e
			}
			return f.putBack(ls, ld, tmp, e.Code, strings.TrimSuffix(e.Msg, "; it was not replaced, and nothing was changed"))
		}
	} else {
		if e := f.renameNoReplace(ld.parent, tmp, ld.parent, ld.base); e != nil {
			return f.putBack(ls, ld, tmp, e.Code, e.Msg)
		}
		f.commit()
	}
	id, err := identIn(ld.parent, ld.base)
	if err != nil || !id.sameObject(&g.top) {
		return errf(protocol.CodeInternal, "the moved entry could not be verified at its destination")
	}
	return nil
}

// putBack returns what was staged under tmp to the source's name, or, when
// that name was taken again, to another staging name in the source's
// directory, and refuses the move with code and why.
func (f *FS) putBack(ls, ld *loc, tmp, code, why string) error {
	if renameat2(ld.parent, tmp, ls.parent, ls.base, unix.RENAME_NOREPLACE) == nil {
		return unchanged(errf(code, "%s; it was put back, and nothing was moved", why))
	}
	f.commit()
	alt := moveTempPrefix + randHex(16)
	if renameat2(ld.parent, tmp, ls.parent, alt, unix.RENAME_NOREPLACE) == nil {
		p := join(path.Dir(ls.p), alt)
		e := errf(code, "%s; what was staged could not be put back under %q, whose name was taken again, so it is at %s; nothing reached the destination; "+
			"recover it (see the privileged helper's documentation)", why, ls.p, p)
		e.SetAside = p
		return e
	}
	p := join(path.Dir(ld.p), tmp)
	e := errf(protocol.CodeInternal, "%s; what was staged could not be put back, so it is at %s; recover it (see the privileged helper's documentation)", why, p)
	e.SetAside = p
	return e
}
