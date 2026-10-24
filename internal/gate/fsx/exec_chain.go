//go:build linux

package fsx

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The chain rule for commands' paths (handoff
// docs/handoff/S4C-PRIVILEGED.md N-10, N-11; PRIVILEGED §6, "Commands";
// POLICY §4), applied when Config.GuardExecPaths is set: by the helper for
// root commands, and by the gate for its own commands, which run as the
// service account. ResolveRead, ResolveWrite and ResolveDir find a path by
// descriptor and return its real path as a string; the command then looks
// that string up again itself, from /, following symlinks. An account that
// can change the entries of any directory on that path could replace the
// next component with a symlink in between: a rename within one parent
// needs write access to that parent only, so this holds for a directory
// above the root too, which can replace the root itself. So the path is
// returned only when every directory from / down to the target's parent is
// closed for commands: owned by a trusted uid (Config.TrustedDirOwner: root
// in the helper; root and the service account in the gate, whose commands
// run as that account, which gains nothing by changing its own
// directories), neither group- nor world-writable, and not sticky (a sticky
// directory counts as open, writable or not). Then only a trusted account
// can change what the string names between the resolution and the
// command's lookup. The directories are checked by
// descriptor, each opened from the previous one with O_PATH|O_NOFOLLOW
// (chainCheck), and the last must be the parent fsx holds; for the root
// itself, the chain is its ancestors, ending at the root fsx opened.
//
// A target that is a directory (the cwd, always; a {path:read} or
// {path:write} that is one) must be closed itself too, checked on the
// descriptor the resolution opened: the command works inside it, by
// relative names or by its own walk, and another account that could change
// its entries could plant a symlink there. A file needs no more than its
// chain: in a closed parent only root can replace or create its name, and
// a final symlink is refused already.

// execOpen says why a directory is open for commands, or "" when it is
// closed.
func (f *FS) execOpen(id *ident) string {
	r := ""
	if !f.closedDir(id) {
		r = f.why(id)
	}
	if id.perm&0o1000 != 0 {
		if r != "" {
			r += " and "
		}
		r += fmt.Sprintf("sticky (mode %04o)", id.perm)
	}
	return r
}

// pathOwner is the one account other than a trusted one that owns
// directories on a {path:read}'s path (OwnerMatchedReads), once one is seen.
type pathOwner struct {
	set bool
	uid uint32
	dir string
}

// readOpen says why a directory (named name in refusals) is open for a
// {path:read} under OwnerMatchedReads, or "" when it passes: a closed one,
// or one neither group- nor world-writable nor sticky whose owner is the
// one other account seen on the path so far (recorded in o). A second
// account is refused: either could rename the other's directory away.
func (f *FS) readOpen(id *ident, name string, o *pathOwner) string {
	why := f.execOpen(id)
	switch {
	case why == "" || id.perm&0o1022 != 0:
		return why
	case !o.set:
		o.set, o.uid, o.dir = true, id.uid, name
		return ""
	case o.uid == id.uid:
		return ""
	}
	return fmt.Sprintf("owned by uid %d, while %s is owned by uid %d: two accounts other than root and the service account, either of which could "+
		"rename the other's directory away", id.uid, o.dir, o.uid)
}

// execChain applies the rule to l's target, opened as target (nil for a
// {path:write} that does not exist yet); read is set for a {path:read},
// which OwnerMatchedReads relaxes (readOpen).
func (f *FS) execChain(l *loc, target *os.File, read bool) error {
	if !f.cfg.GuardExecPaths {
		return nil
	}
	var o pathOwner
	open := func(id *ident, name string) string {
		if read && f.cfg.OwnerMatchedReads {
			return f.readOpen(id, name, &o)
		}
		return f.execOpen(id)
	}
	held, dir := l.parent, l.parentReal
	if held == nil {
		held, dir = l.top, l.rootReal
	}
	hf, err := held.Open(".")
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = hf.Close() }()
	err = withFD(hf, func(hfd int) error {
		want, serr := statxAt(hfd, "", unix.AT_EMPTY_PATH)
		if serr != nil {
			return mapErr(serr)
		}
		last, cerr := chainCheck(dir, func(cur string, id *ident) error {
			if l.parent == nil && cur == dir {
				return nil // the root itself: checked below as the target
			}
			if why := open(id, l.chainDirName(cur)); why != "" {
				return errf(protocol.CodePathDenied, "%q is not given to a command%s: %s on its path is %s, so another account could replace "+
					"a directory or file on the path (with a symlink, for example) before the command looks the path up itself; nothing was run",
					l.p, f.asRoot(), l.chainDirName(cur), why)
			}
			return nil
		})
		if cerr != nil {
			return cerr
		}
		if !last.sameObject(&want) {
			return errf(protocol.CodePathDenied, "the path changed while it was checked; nothing was run")
		}
		return nil
	})
	if err != nil || target == nil {
		return err
	}
	return withFD(target, func(tfd int) error {
		id, err := statxAt(tfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return mapErr(err)
		}
		if id.mask&statxMeta != statxMeta {
			return errf(protocol.CodeBadRequest, "the kernel did not report the owner and mode (statx) that the helper checks on a path; nothing was done")
		}
		if !id.isDir() {
			return nil
		}
		if why := open(&id, "the directory itself"); why != "" {
			return errf(protocol.CodePathDenied, "%q is not given to a command%s: it is a directory that is %s, so another account could change "+
				"what is inside it (plant a symlink, for example) before or while the command works in it; nothing was run", l.p, f.asRoot(), why)
		}
		return nil
	})
}
