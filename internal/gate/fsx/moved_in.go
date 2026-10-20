//go:build linux

package fsx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The moved-in rule (PRIVILEGED §6, "Files another account could have moved
// in"; handoff docs/handoff/S4C-PRIVILEGED.md N-6, N-7), applied when
// Config.GuardMovedIn is set (the helper). An account that can write a
// directory on a file's path can move a file from elsewhere on the same
// filesystem into it (rename and link need write access to the directory
// that receives the name), or swap a sibling directory into the path (a
// rename within one parent needs write access to that parent only), have
// root act, and move the result out again.
//
// The chain is every directory from the root the path is resolved under
// (inclusive) down to the file's parent, each opened from the previous
// one's descriptor with O_PATH|O_NOFOLLOW and checked by statx, never by a
// separate lookup of a path; the last must be the parent fsx holds. A file
// is owner-matched when every directory in the chain is neither group- nor
// world-writable and is owned by a trusted uid (root; Config.TrustedDirOwner)
// or by the file's owner: then no account but root and that owner could
// have put it there. The first directory of the chain that another account
// could write cannot itself be moved (its parent is closed), so a walk by
// name from the root always passes through it.
//
// Reads (ReadFile, a copy's source, CurrentFile) return a file only when it
// is owner-matched or world-readable. A write or copy over an existing file
// keeps its owner and group only when it is owner-matched: otherwise a write
// needs both an owner and a group given, and a copy, which cannot name one,
// is refused. Directories above the root are not checked per request
// (check-policy reports them, CheckRootChain).

// ChainDir is one directory on the chain from a root to a file's parent:
// its path (for messages), owner and permission bits.
type ChainDir struct {
	Path string
	UID  uint32
	Mode uint32
}

// rootChain returns the chain of l's target: every directory from l's root
// (inclusive) to l's parent (inclusive), by descriptor. A root itself has
// none.
func (f *FS) rootChain(l *loc) ([]ChainDir, error) {
	if l.parent == nil {
		return nil, nil
	}
	pf, err := l.parent.Open(".")
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = pf.Close() }()
	top, err := l.top.Open(".")
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = top.Close() }()
	var comps []string
	if rel := pathx.Rel(l.rootReal, l.parentReal); rel != "." {
		comps = strings.Split(rel, "/")
	}
	var chain []ChainDir
	err = withFD(pf, func(pfd int) error {
		want, serr := statxAt(pfd, "", unix.AT_EMPTY_PATH)
		if serr != nil {
			return mapErr(serr)
		}
		return withFD(top, func(tfd int) error {
			fd, err := unix.Openat(tfd, ".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				return mapErr(&fs.PathError{Op: "openat", Path: l.rootReal, Err: err})
			}
			defer func() { _ = unix.Close(fd) }()
			cur := l.rootReal
			for i := 0; ; i++ {
				id, err := statxAt(fd, "", unix.AT_EMPTY_PATH)
				if err != nil {
					return mapErr(err)
				}
				if id.mask&statxMeta != statxMeta {
					return errf(protocol.CodeBadRequest, "the kernel did not report the owner and mode (statx) that the helper checks on a path; nothing was done")
				}
				chain = append(chain, ChainDir{Path: l.logical(cur), UID: id.uid, Mode: id.perm})
				if i == len(comps) {
					if !id.sameObject(&want) {
						return errf(protocol.CodePathDenied, "the path changed while it was checked; nothing was done")
					}
					return nil
				}
				nfd, oerr := unix.Openat(fd, comps[i], unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				cur = join(cur, comps[i])
				if oerr != nil {
					return mapErr(&fs.PathError{Op: "openat", Path: cur, Err: oerr})
				}
				_ = unix.Close(fd)
				fd = nfd
			}
		})
	})
	if err != nil {
		return nil, err
	}
	return chain, nil
}

// logical names a real path under l's root by its configured root's name.
func (l *loc) logical(rp string) string {
	if rp == l.rootReal {
		return l.root
	}
	return join(l.root, pathx.Rel(l.rootReal, rp))
}

// WriteChain returns the chain of p, a path under a write root whose parent
// exists (the helper's restore checks the owner it would set against it).
func (f *FS) WriteChain(p string) ([]ChainDir, error) {
	l, err := f.locate(p, true)
	if err != nil {
		return nil, err
	}
	defer l.close()
	return f.rootChain(l)
}

// MovedInBy returns the first directory of chain through which an account
// other than root and owner could have put an entry there (group- or
// world-writable, or owned by another uid), or nil when the chain is
// owner-matched for owner.
func (f *FS) MovedInBy(chain []ChainDir, owner uint32) *ChainDir {
	for i := range chain {
		d := &chain[i]
		if d.Mode&0o022 != 0 || !f.trustedOwner(d.UID) && d.UID != owner {
			return d
		}
	}
	return nil
}

// MovedInWhy says why d is open to another account, for messages.
func (f *FS) MovedInWhy(d *ChainDir, owner uint32) string {
	var r []string
	if !f.trustedOwner(d.UID) && d.UID != owner {
		r = append(r, fmt.Sprintf("owned by uid %d", d.UID))
	}
	if d.Mode&0o022 != 0 {
		r = append(r, fmt.Sprintf("group- or world-writable (mode %04o)", d.Mode))
	}
	return strings.Join(r, " and ")
}

// movedIn checks l's target, owned by owner, against the chain: nil when it
// is owner-matched, else the first open directory.
func (f *FS) movedIn(l *loc, owner uint32) (*ChainDir, error) {
	chain, err := f.rootChain(l)
	if err != nil {
		return nil, err
	}
	d := f.MovedInBy(chain, owner)
	if d == nil {
		return nil, nil
	}
	c := *d
	return &c, nil
}

// movedInRead applies the read rule to the opened target fi: a file that
// is neither owner-matched nor world-readable is not read.
func (f *FS) movedInRead(l *loc, fi fs.FileInfo) error {
	if !f.cfg.GuardMovedIn || fi.Mode().Perm()&0o004 != 0 {
		return nil
	}
	owner := metaOf(fi).UID
	d, err := f.movedIn(l, owner)
	if err != nil || d == nil {
		return err
	}
	return errf(protocol.CodePathDenied, "%q is not read as root: the directory %s is %s, so another account could have moved it there; "+
		"under such a directory root reads only what that account could read itself (its own file, or a world-readable one)",
		l.p, d.Path, f.MovedInWhy(d, owner))
}

// movedInOverwrite applies the overwrite rule to the file about to be
// replaced (fi, from its descriptor): its owner and group are kept only when
// it is owner-matched; otherwise a write must name both, and a copy is
// refused. The refusal comes before anything is backed up or written.
func (f *FS) movedInOverwrite(l *loc, fi fs.FileInfo, o *atomicOpts) error {
	if !f.cfg.GuardMovedIn || !o.copy && o.owner != nil && o.owner.UID != nil && o.owner.GID != nil {
		return nil
	}
	owner := metaOf(fi).UID
	d, err := f.movedIn(l, owner)
	if err != nil || d == nil {
		return err
	}
	if o.copy {
		return unchanged(errf(protocol.CodePathDenied, "%q is not overwritten by a copy as root: the directory %s is %s, so another account could have moved it there, "+
			"and a copy cannot name the owner and group to give the new file; nothing was changed", l.p, d.Path, f.MovedInWhy(d, owner)))
	}
	return unchanged(errf(protocol.CodePathDenied, "%q is not overwritten as root keeping its owner and group: the directory %s is %s, so another account could have moved it there; "+
		"give both an owner and a group from the privileged policy's owners; nothing was changed", l.p, d.Path, f.MovedInWhy(d, owner)))
}

// CurrentFile is what a restore would replace at p (a path under a write
// root, its parent existing): nil when nothing is there, else a regular file
// opened through a verified descriptor, its stat and SHA-256 (at most
// maxHashBytes), read under the moved-in rule. A symlink, a directory,
// another non-file, and a file with setuid, setgid, sticky or world-write
// bits are refused as a write over them would be.
func (f *FS) CurrentFile(p string) (fs.FileInfo, string, error) {
	l, err := f.locate(p, true)
	if err != nil {
		return nil, "", err
	}
	defer l.close()
	if l.parent == nil {
		return nil, "", errf(protocol.CodeIsADirectory, "is a directory")
	}
	fi, err := l.parent.Lstat(l.base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "", nil
	case err != nil:
		return nil, "", mapErr(err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return nil, "", errf(protocol.CodePathDenied, "final path component is a symlink")
	case fi.IsDir():
		return nil, "", errf(protocol.CodeIsADirectory, "is a directory")
	case !fi.Mode().IsRegular():
		return nil, "", errf(protocol.CodeBadRequest, "not a regular file")
	}
	file, err := f.openTarget(l)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, "", mapErr(err)
	}
	switch {
	case !info.Mode().IsRegular():
		return nil, "", errf(protocol.CodeBadRequest, "not a regular file")
	case unixMode(info)&0o7002 != 0:
		return nil, "", errf(protocol.CodePolicyDenied, "existing file has setuid, setgid, sticky or world-write bits")
	case info.Size() > maxHashBytes:
		return nil, "", errf(protocol.CodeTooLarge, "the file is larger than the %d MiB the helper hashes", maxHashBytes>>20)
	}
	if err := f.movedInRead(l, info); err != nil {
		return nil, "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, maxHashBytes+1)); err != nil {
		return nil, "", mapErr(err)
	}
	return info, hex.EncodeToString(h.Sum(nil)), nil
}

// CheckWritable applies the write path rules to p without touching the
// filesystem: absolute and clean, under a write root, not denied or
// protected (the restore preview, for every entry of a tree before any
// exists).
func (f *FS) CheckWritable(p string) error {
	if err := pathx.CheckClean(p); err != nil {
		return errf(protocol.CodeBadRequest, "path must be absolute and clean: %v", err)
	}
	if _, ok := pathx.Longest(f.cfg.WriteRoots, p); !ok {
		return errf(protocol.CodePathDenied, "path is outside the policy's write roots")
	}
	return f.checkPath(p, true).orNil()
}
