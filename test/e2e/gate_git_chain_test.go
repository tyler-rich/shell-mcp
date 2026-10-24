//go:build e2e && linux

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The closed repository rule for the gate's git operations, end to end
// (handoff docs/handoff/S4C-PRIVILEGED.md N-20, POLICY §7): the real gate as
// the service account (svc-shell), with Landlock, under the hardening policy
// (setup.sh), whose listed repository /srv/e2e-gate/work/git/repo has the
// operator tests' local HTTPS server as its origin. Before any git process
// starts, every git operation refuses the repository when any directory from
// / to it, the repository, .git or .git/config is owned by another account
// (example-app) or is group-writable, world-writable or sticky, and when .git
// is a gitfile or .git/commondir or .git/config.worktree exists; a closed
// repository works for every operation. Every path and name is invented.

const (
	hardGit  = hardWork + "/git"
	hardRepo = hardGit + "/repo"
)

// gitOpArgs is every git operation with arguments that pass its own checks
// (the discard's hash is well formed but stale).
func gitOpArgs() []struct {
	op   string
	args map[string]any
} {
	return []struct {
		op   string
		args map[string]any
	}{
		{"git_status", map[string]any{"repo": hardRepo}}, {"git_log", map[string]any{"repo": hardRepo}},
		{"git_diff", map[string]any{"repo": hardRepo}}, {"git_pull", map[string]any{"repo": hardRepo}},
		{"git_discard_preview", map[string]any{"repo": hardRepo, "include_untracked": true}},
		{"git_discard", map[string]any{"repo": hardRepo, "include_untracked": true, "expected_preview_sha256": strings.Repeat("a", 64)}},
	}
}

// hardRepoFixture clones the operator tests' upstream to hardRepo, every
// entry svc-shell's and closed.
func hardRepoFixture(t *testing.T) {
	t.Helper()
	opsServer(t) // the HTTPS server, its CA in the trust store, and opsBare
	ownDir(t, hardGit, svcShell, svcShell, 0o755)
	gatetest.Git(t, hardGit, "clone", "-q", opsBare, "repo")
	gatetest.Git(t, hardRepo, "remote", "set-url", "origin", opsRemote)
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "svc-shell:svc-shell", hardRepo).CombinedOutput(); err != nil {
		t.Fatalf("chown: %v: %s", err, out)
	}
}

// repoState is what a refused git operation must leave alone, read from the
// filesystem (root running git in svc-shell's repository would be refused
// as dubious ownership): every regular file directly in .git and under
// .git/refs, and every work-tree file, by content hash, and .git's names.
func repoState(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(hardRepo, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(hardRepo, p)
		if d.IsDir() {
			if rel == ".git/objects" || rel == ".git/logs" || rel == ".git/hooks" || rel == ".git/info" {
				return filepath.SkipDir
			}
			b.WriteString(rel + "/\n")
			return nil
		}
		c, rerr := os.ReadFile(p) //nolint:gosec // G304: the test's own repository
		if rerr != nil {
			return rerr
		}
		h := sha256.Sum256(c)
		b.WriteString(rel + " " + hex.EncodeToString(h[:]) + "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestGateGitRepoChain (N-20): see the file comment.
func TestGateGitRepoChain(t *testing.T) {
	hardRepoFixture(t)
	gitDir := hardRepo + "/.git"
	config := gitDir + "/config"
	conf := hardRepo + "/app.conf"

	t.Run("closed", func(t *testing.T) {
		for _, op := range []string{"git_status", "git_log", "git_diff", "git_pull"} {
			if r := hard(t, op, map[string]any{"repo": hardRepo}); !r.OK {
				t.Fatalf("%s on a closed repository: %+v", op, r.Error)
			}
		}
		ownFile(t, conf, "changed\n", svcShell, 0o644)
		ownFile(t, hardRepo+"/untracked.txt", "u\n", svcShell, 0o644)
		pv := hard(t, "git_discard_preview", map[string]any{"repo": hardRepo, "include_untracked": true})
		var p struct {
			PreviewSHA256 string `json:"preview_sha256"`
			Entries       int    `json:"entries"`
		}
		if !pv.OK || json.Unmarshal(pv.Data, &p) != nil || p.Entries != 2 {
			t.Fatalf("discard preview on a closed repository: %+v %s", pv.Error, pv.Data)
		}
		r := hard(t, "git_discard", map[string]any{"repo": hardRepo, "include_untracked": true, "expected_preview_sha256": p.PreviewSHA256})
		if !r.OK {
			t.Fatalf("discard on a closed repository: %+v", r.Error)
		}
		fileIs(t, conf, "version: 1\n")
	})

	// A change for the refused discards to leave alone.
	ownFile(t, conf, "changed\n", svcShell, 0o644)
	ownFile(t, hardRepo+"/untracked.txt", "u\n", svcShell, 0o644)
	for _, lvl := range []struct {
		name, path, entry string
		uid               int
		file              bool
	}{
		{"read root", hardRoot, "the directory " + hardRoot, 0, false},
		{"write root", hardWork, "the directory " + hardWork, svcShell, false},
		{"intermediate", hardGit, "the directory " + hardGit, svcShell, false},
		{"repository", hardRepo, "the directory " + hardRepo, svcShell, false},
		{".git", gitDir, "the directory " + gitDir, svcShell, false},
		{".git/config", config, "the file " + config, svcShell, true},
	} {
		closed := os.FileMode(0o755)
		if lvl.file {
			closed = 0o644
		}
		conds := []struct {
			name string
			app  bool
			mode os.FileMode
		}{
			{"owned by example-app", true, closed},
			{"group-writable", false, closed | 0o020},
			{"world-writable", false, closed | 0o002},
		}
		if !lvl.file {
			conds = append(conds, struct {
				name string
				app  bool
				mode os.FileMode
			}{"sticky", false, os.ModeSticky | 0o755})
		}
		for _, c := range conds {
			t.Run(lvl.name+" "+c.name, func(t *testing.T) {
				uid := lvl.uid
				if c.app {
					uid = exampleApp
				}
				before := repoState(t)
				setDir(t, lvl.path, uid, uid, c.mode)
				defer setDir(t, lvl.path, lvl.uid, lvl.uid, closed)
				for _, o := range gitOpArgs() {
					r := hard(t, o.op, o.args)
					if r.code() != "path_denied" || !strings.Contains(r.Error.Message, lvl.entry+" is ") || !strings.Contains(r.Error.Message, "owner uid ") ||
						!strings.Contains(r.Error.Message, "nothing was run") {
						t.Fatalf("%s: %s %+v, want path_denied naming %s and its owner", o.op, r.code(), r.Error, lvl.entry)
					}
				}
				if after := repoState(t); after != before {
					t.Fatalf("a refused git operation changed the repository:\nbefore %s\nafter  %s", before, after)
				}
			})
		}
	}

	for _, s := range []struct {
		name         string
		make, remove func(t *testing.T)
	}{
		{"gitfile", func(t *testing.T) {
			if err := os.Rename(gitDir, hardRepo+"/real.git"); err != nil {
				t.Fatal(err)
			}
			ownFile(t, gitDir, "gitdir: "+hardRepo+"/real.git\n", svcShell, 0o644)
		}, func(t *testing.T) {
			if err := os.Remove(gitDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(hardRepo+"/real.git", gitDir); err != nil {
				t.Fatal(err)
			}
		}},
		{"commondir", func(t *testing.T) { ownFile(t, gitDir+"/commondir", opsBare+"\n", svcShell, 0o644) },
			func(t *testing.T) { _ = os.Remove(gitDir + "/commondir") }},
		{"config.worktree", func(t *testing.T) { ownFile(t, gitDir+"/config.worktree", "[core]\n\tbare = false\n", svcShell, 0o644) },
			func(t *testing.T) { _ = os.Remove(gitDir + "/config.worktree") }},
	} {
		t.Run(s.name, func(t *testing.T) {
			s.make(t)
			defer s.remove(t)
			for _, o := range gitOpArgs() {
				if r := hard(t, o.op, o.args); r.code() != "policy_denied" {
					t.Fatalf("%s with a %s: %s %+v, want policy_denied", o.op, s.name, r.code(), r.Error)
				}
			}
		})
	}

	// Closed again: the operations run.
	if r := hard(t, "git_status", map[string]any{"repo": hardRepo}); !r.OK {
		t.Fatalf("status once closed again: %+v", r.Error)
	}
}
