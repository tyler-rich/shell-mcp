//go:build linux

package fsx

import (
	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The chain rule for root commands' paths (handoff
// docs/handoff/S4C-PRIVILEGED.md N-10; PRIVILEGED §6, "Commands"), applied
// when Config.GuardExecPaths is set (the helper). ResolveRead, ResolveWrite
// and ResolveDir find a path by descriptor and return its real path as a
// string; the command then looks that string up again itself, as root,
// from /, following symlinks. An account that can change the entries of any
// directory on that path could replace the next component with a symlink in
// between: a rename within one parent needs write access to that parent
// only, so this holds for a directory above the root too, which can replace
// the root itself. So the path is returned only when every directory from /
// down to the target's parent is closed (owned by a trusted uid, root
// unless Config.TrustedDirOwner says otherwise, and neither group- nor
// world-writable; a sticky directory that others can write is open, since
// they can still add names to it): then only root can change what the
// string names between the resolution and the command's lookup. The
// directories are checked by descriptor, each opened from the previous one
// with O_PATH|O_NOFOLLOW (chainCheck), and the last must be the parent fsx
// holds; for the root itself, the chain ends at the root fsx opened, whose
// own mode does not matter (only its parent can replace it). The target
// itself needs no such check: in a closed parent only root can replace or
// create its name, and a final symlink is refused already.

// execChain applies the rule to l's target.
func (f *FS) execChain(l *loc) error {
	if !f.cfg.GuardExecPaths {
		return nil
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
	return withFD(hf, func(hfd int) error {
		want, err := statxAt(hfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return mapErr(err)
		}
		last, err := chainCheck(dir, func(cur string, id *ident) error {
			if l.parent == nil && cur == dir {
				return nil // the root itself: only what holds it matters
			}
			if !f.closedDir(id) {
				return errf(protocol.CodePathDenied, "%q is not given to a command as root: %s on its path is %s, so another account could replace "+
					"a directory or file on the path (with a symlink, for example) before the command looks the path up itself; nothing was run",
					l.p, l.chainDirName(cur), f.why(id))
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !last.sameObject(&want) {
			return errf(protocol.CodePathDenied, "the path changed while it was checked; nothing was run")
		}
		return nil
	})
}
