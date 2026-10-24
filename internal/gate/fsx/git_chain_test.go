//go:build linux

package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The closed-repository rule for the gate's git operations (POLICY §7,
// handoff docs/handoff/S4C-PRIVILEGED.md N-20): CheckGitRepo refuses a
// repository unless every directory from / to it, the repository itself,
// its .git and .git/config are owned by a trusted uid (root and the service
// account in the gate) and neither group- nor world-writable nor sticky,
// .git is a real directory, and .git/commondir and .git/config.worktree do
// not exist. An unprivileged test cannot give a directory to another
// account, so "another account can write it" is an open mode, or an
// untrusted owner (the trust without the test's uid); e2e-host runs the real
// case as root. Every layout is invented.

type gitChainEnv struct {
	anc, root, repo, gitDir, config string
	fs                              *FS
}

// newGitChainEnv makes <d>/x/w/deploy with .git and .git/config, under the
// root <d>/x/w and its ancestor <d>/x, all closed, with the gate's git trust
// (root and the test's uid, as the service account).
func newGitChainEnv(t *testing.T) *gitChainEnv {
	t.Helper()
	d := gatetest.SecureDir(t)
	e := &gitChainEnv{anc: filepath.Join(d, "x"), root: filepath.Join(d, "x", "w")}
	e.repo = filepath.Join(e.root, "deploy")
	e.gitDir = filepath.Join(e.repo, ".git")
	e.config = filepath.Join(e.gitDir, "config")
	for _, p := range []string{e.anc, e.root, e.repo, e.gitDir} {
		mkdirMode(t, p, 0o755)
	}
	putMode(t, e.config, "[core]\n\trepositoryformatversion = 0\n", 0o644)
	empty, err := pathx.NewMatcher(nil)
	must(t, err)
	e.fs = New(&Config{
		ReadRoots: []string{e.root}, WriteRoots: []string{e.root}, Deny: empty, Protected: empty,
		Limits:          Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: 20},
		TrustedDirOwner: gatetest.Trust().Owns,
	})
	return e
}

// wantGitRefusal requires a path_denied refusal naming entry, its owner and
// its mode.
func wantGitRefusal(t *testing.T, err error, entry string) {
	t.Helper()
	wantCode(t, err, protocol.CodePathDenied)
	msg := err.Error()
	if !strings.Contains(msg, entry+" is ") || !strings.Contains(msg, fmt.Sprintf("owner uid %d", os.Getuid())) || !strings.Contains(msg, "mode ") ||
		!strings.Contains(msg, "nothing was run") {
		t.Fatalf("the refusal does not name %s, its owner and its mode: %v", entry, err)
	}
}

// TestCheckGitRepoClosed: a closed repository passes, with or without a
// .git/config (in a closed .git only a trusted account could create one).
func TestCheckGitRepoClosed(t *testing.T) {
	e := newGitChainEnv(t)
	must(t, e.fs.CheckGitRepo(e.repo))
	must(t, os.Remove(e.config))
	must(t, e.fs.CheckGitRepo(e.repo))
}

// TestCheckGitRepoOpen: an ancestor above the root, the root, the
// repository, .git and .git/config, each group-writable, world-writable or
// (a directory) sticky, writable or not, are refused naming the entry, its
// owner and its mode; closed again, the repository passes.
func TestCheckGitRepoOpen(t *testing.T) {
	dirModes := []os.FileMode{0o775, 0o777, 0o757, os.ModeSticky | 0o777, os.ModeSticky | 0o755}
	fileModes := []os.FileMode{0o664, 0o666, 0o646}
	e := newGitChainEnv(t)
	for _, lvl := range []struct {
		name, path, entry string
		modes             []os.FileMode
		closed            os.FileMode
	}{
		{"ancestor", e.anc, "the directory " + e.anc, dirModes, 0o755},
		{"root", e.root, "the directory " + e.root, dirModes, 0o755},
		{"repository", e.repo, "the directory " + e.repo, dirModes, 0o755},
		{".git", e.gitDir, "the directory " + e.gitDir, dirModes, 0o755},
		{".git/config", e.config, "the file " + e.config, fileModes, 0o644},
	} {
		for _, mode := range lvl.modes {
			t.Run(fmt.Sprintf("%s %v", lvl.name, mode), func(t *testing.T) {
				must(t, os.Chmod(lvl.path, mode))
				exactMode(t, lvl.path, mode)
				err := e.fs.CheckGitRepo(e.repo)
				must(t, os.Chmod(lvl.path, lvl.closed))
				wantGitRefusal(t, err, lvl.entry)
				must(t, e.fs.CheckGitRepo(e.repo))
			})
		}
	}
}

// TestCheckGitRepoOwner: an entry owned by an untrusted uid is open whatever
// its mode (its owner can change the mode): the test's own directories, once
// its uid is not trusted. The first one on the path is named.
func TestCheckGitRepoOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs an unprivileged uid")
	}
	e := newGitChainEnv(t)
	e.fs.cfg.TrustedDirOwner = func(uid uint32) bool { return uid == 0 }
	err := e.fs.CheckGitRepo(e.repo)
	wantCode(t, err, protocol.CodePathDenied)
	if !strings.Contains(err.Error(), fmt.Sprintf("owned by uid %d (owner uid %d", os.Getuid(), os.Getuid())) {
		t.Fatalf("the refusal does not name the owner: %v", err)
	}
}

// TestCheckGitRepoStructure: .git must be a real directory (a gitfile or a
// symlink is policy_denied, a missing one not_found), .git/commondir and
// .git/config.worktree must not exist (policy_denied), and .git/config, when
// it exists, must be a regular file (path_denied).
func TestCheckGitRepoStructure(t *testing.T) {
	t.Run("gitfile", func(t *testing.T) {
		e := newGitChainEnv(t)
		must(t, os.Rename(e.gitDir, e.repo+"/real.git"))
		putMode(t, e.gitDir, "gitdir: "+e.repo+"/real.git\n", 0o644)
		wantCode(t, e.fs.CheckGitRepo(e.repo), protocol.CodePolicyDenied)
	})
	t.Run("symlink", func(t *testing.T) {
		e := newGitChainEnv(t)
		must(t, os.Rename(e.gitDir, e.repo+"/real.git"))
		must(t, os.Symlink("real.git", e.gitDir))
		wantCode(t, e.fs.CheckGitRepo(e.repo), protocol.CodePolicyDenied)
	})
	t.Run("missing", func(t *testing.T) {
		e := newGitChainEnv(t)
		must(t, os.RemoveAll(e.gitDir))
		wantCode(t, e.fs.CheckGitRepo(e.repo), protocol.CodeNotFound)
	})
	for _, name := range []string{"commondir", "config.worktree"} {
		t.Run(name, func(t *testing.T) {
			e := newGitChainEnv(t)
			putMode(t, filepath.Join(e.gitDir, name), "x\n", 0o644)
			err := e.fs.CheckGitRepo(e.repo)
			wantCode(t, err, protocol.CodePolicyDenied)
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("the refusal does not name %s: %v", name, err)
			}
			// A directory under that name is refused the same way.
			must(t, os.Remove(filepath.Join(e.gitDir, name)))
			mkdirMode(t, filepath.Join(e.gitDir, name), 0o755)
			wantCode(t, e.fs.CheckGitRepo(e.repo), protocol.CodePolicyDenied)
		})
	}
	t.Run("config symlink", func(t *testing.T) {
		e := newGitChainEnv(t)
		must(t, os.Rename(e.config, e.gitDir+"/config.real"))
		must(t, os.Symlink("config.real", e.config))
		wantCode(t, e.fs.CheckGitRepo(e.repo), protocol.CodePathDenied)
	})
	t.Run("config directory", func(t *testing.T) {
		e := newGitChainEnv(t)
		must(t, os.Remove(e.config))
		mkdirMode(t, e.config, 0o755)
		wantCode(t, e.fs.CheckGitRepo(e.repo), protocol.CodePathDenied)
	})
}

// FuzzGitOpen: the pure check against an oracle over owners and modes. An
// entry is closed exactly when its owner is trusted and it is neither group-
// nor world-writable nor sticky; a refusal names the owner and the mode.
func FuzzGitOpen(f *testing.F) {
	for _, s := range []struct {
		uid  uint32
		perm uint32
	}{{0, 0o755}, {0, 0o775}, {0, 0o1755}, {1000, 0o755}, {1000, 0o644}, {1000, 0o2755}, {1000, 0o4755}, {1001, 0o755}, {0, 0o757}, {1000, 0o666}} {
		f.Add(s.uid, s.perm)
	}
	fs := New(&Config{TrustedDirOwner: func(u uint32) bool { return u == 0 || u == 1000 }})
	f.Fuzz(func(t *testing.T, uid, perm uint32) {
		perm &= 0o7777
		id := &ident{typ: unix.S_IFDIR, uid: uid, perm: perm}
		closed := (uid == 0 || uid == 1000) && perm&0o022 == 0 && perm&unix.S_ISVTX == 0
		why := fs.gitOpen(id)
		if closed != (why == "") {
			t.Fatalf("uid %d mode %04o: closed %v, gitOpen %q", uid, perm, closed, why)
		}
		if !closed && (!strings.Contains(why, fmt.Sprintf("owner uid %d", uid)) || !strings.Contains(why, fmt.Sprintf("mode %04o", perm))) {
			t.Fatalf("uid %d mode %04o: %q does not name the owner and the mode", uid, perm, why)
		}
	})
}
