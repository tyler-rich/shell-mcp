//go:build linux

package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The closed-repository rule for the gate's built-in git operations (POLICY
// §7, handoff docs/handoff/S4C-PRIVILEGED.md N-20). The gate hands git the
// repository as strings (-C, GIT_DIR, GIT_WORK_TREE), which git looks up
// again itself, from /, in every process it starts; git applies no
// ownership check of its own (safe.directory) to a repository GIT_DIR
// names; and the repository's configuration is checked once (git config
// --local --no-includes) and then read again by each later git process. So
// before any git process starts, CheckGitRepo requires, by descriptor, that
// no account but a trusted one (Config.TrustedDirOwner: in the gate, root
// and the service account) can change what git reads in between: every
// directory from / to the repository, the repository itself, its .git and
// .git/config are owned by a trusted uid and neither group- nor
// world-writable nor sticky (a sticky directory counts as open, writable
// or not); .git is a real directory (not a gitfile or a symlink); and
// .git/commondir and .git/config.worktree, which would point git at other
// configuration, do not exist. In a closed .git only a trusted account could
// create them, or .git/config, later. There is no owner-matched exception:
// configuration is code.

// gitOpen says why a directory or the configuration file is open to another
// account, naming its owner and mode, or "" when it is closed.
func (f *FS) gitOpen(id *ident) string {
	var r []string
	if !f.trustedOwner(id.uid) {
		r = append(r, fmt.Sprintf("owned by uid %d", id.uid))
	}
	if id.perm&0o022 != 0 {
		r = append(r, "group- or world-writable")
	}
	if id.perm&unix.S_ISVTX != 0 {
		r = append(r, "sticky")
	}
	if len(r) == 0 {
		return ""
	}
	return fmt.Sprintf("%s (owner uid %d, mode %04o)", strings.Join(r, " and "), id.uid, id.perm)
}

// gitRefusal refuses the repository repo because entry is open (why).
func gitRefusal(repo, entry, why string) *Error {
	return errf(protocol.CodePathDenied, "git is not run in the repository %q: %s is %s, so another account could change what git reads "+
		"(its configuration, or the repository itself) between the gate's check and git's use of it; give it to root or the service account "+
		"and clear its group and world write bits and its sticky bit (POLICY §7); nothing was run", repo, entry, why)
}

func gitChanged(repo string) *Error {
	return errf(protocol.CodePathDenied, "the repository %q changed while it was checked; nothing was run", repo)
}

// CheckGitRepo applies the rule to the repository at repo, a directory
// under a read or write root: the chain from / to the repository as fsx
// opened it, then .git opened from the repository's descriptor, then the
// names in .git.
func (f *FS) CheckGitRepo(repo string) error {
	l, err := f.locate(repo, false)
	if err != nil {
		return err
	}
	defer l.close()
	dir, rp, owned, err := f.openDirRoot(l)
	if err != nil {
		return err
	}
	if owned {
		defer func() { _ = dir.Close() }()
	}
	return withRootFD(dir, func(rfd int) error {
		want, err := statxAt(rfd, "", unix.AT_EMPTY_PATH)
		if err != nil {
			return mapErr(err)
		}
		last, err := chainCheck(rp, func(cur string, id *ident) error {
			if why := f.gitOpen(id); why != "" {
				return gitRefusal(repo, l.chainDirName(cur), why)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !last.sameObject(&want) {
			return gitChanged(repo)
		}
		return f.checkGitDir(repo, rp, rfd)
	})
}

// checkGitDir checks .git in the repository (open as rfd, real path rp) and
// the names in it that git takes configuration from.
func (f *FS) checkGitDir(repo, rp string, rfd int) error {
	id, err := statxAt(rfd, ".git", 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return errf(protocol.CodeNotFound, "repo has no .git directory")
	case err != nil:
		return mapErr(err)
	case !id.isDir():
		return errf(protocol.CodePolicyDenied, "repo/.git must be a real directory (a gitfile or a symlink is refused)")
	}
	if e := f.checkPath(rp+"/.git", false); e != nil {
		return e
	}
	gfd, err := unix.Openat(rfd, ".git", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapErr(&fs.PathError{Op: "openat", Path: rp + "/.git", Err: err})
	}
	defer func() { _ = unix.Close(gfd) }()
	gid, err := statxAt(gfd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return mapErr(err)
	}
	if !gid.sameObject(&id) {
		return gitChanged(repo)
	}
	if why := f.gitOpen(&gid); why != "" {
		return gitRefusal(repo, "the directory "+repo+"/.git", why)
	}
	cid, err := statxAt(gfd, "config", 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		// No configuration: in a closed .git only a trusted account can add one.
	case err != nil:
		return mapErr(err)
	case cid.typ != unix.S_IFREG:
		return errf(protocol.CodePathDenied, "git is not run in the repository %q: its .git/config is not a regular file (a symlink, for example); nothing was run", repo)
	default:
		if why := f.gitOpen(&cid); why != "" {
			return gitRefusal(repo, "the file "+repo+"/.git/config", why)
		}
	}
	for _, n := range []struct{ name, msg string }{
		{"commondir", "repo/.git has a commondir (a linked worktree); only plain repositories are allowed"},
		{"config.worktree", "repo/.git has a config.worktree (per-worktree configuration); only plain repositories are allowed"},
	} {
		switch _, err := statxAt(gfd, n.name, 0); {
		case err == nil:
			return errf(protocol.CodePolicyDenied, "%s", n.msg)
		case !errors.Is(err, unix.ENOENT):
			return mapErr(err)
		}
	}
	return nil
}
