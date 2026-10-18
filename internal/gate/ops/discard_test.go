//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// git_discard and git_discard_preview (POLICY §7, "Discarding changes"):
// what is restored and removed, the preview binding, the refusals, hooks,
// git's index lock, and changes made after the preview, which must never be
// discarded. Repositories, paths and contents are invented.

type discardEntry struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Action string `json:"action"`
}

type discardPlan struct {
	Repo             string         `json:"repo"`
	Head             string         `json:"head"`
	IncludeUntracked bool           `json:"include_untracked"`
	Restore          int            `json:"restore"`
	Remove           int            `json:"remove"`
	Untracked        int            `json:"untracked"`
	UntrackedEntries int            `json:"untracked_entries"`
	Entries          int            `json:"entries"`
	First            []discardEntry `json:"first"`
	Skipped          []string       `json:"skipped"`
	Truncated        bool           `json:"truncated"`
	PreviewSHA256    string         `json:"preview_sha256"`
	Applied          bool           `json:"applied"`
	CleanAfter       *bool          `json:"clean_after"`
}

// discardRepo adds tracked files of every kind to the fixture repository
// (committed locally) and returns the fixture.
func discardRepo(t *testing.T) *gitFixture {
	t.Helper()
	g := newGitFixture(t, "destructive")
	gatetest.WriteFile(t, filepath.Join(g.repo, "d", "a.txt"), "a\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "run.sh"), "echo run\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "gone.txt"), "gone\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "unstage.txt"), "u\n", 0o644)
	if err := os.Symlink("app.conf", filepath.Join(g.repo, "lnk")); err != nil {
		t.Fatal(err)
	}
	gatetest.Git(t, g.repo, "add", "-A")
	gatetest.Git(t, g.repo, "commit", "-q", "-m", "kinds")
	return g
}

// dirty makes one change of every kind the discard handles.
func dirty(t *testing.T, g *gitFixture) {
	t.Helper()
	r := g.repo
	gatetest.WriteFile(t, filepath.Join(r, "app.conf"), "port=9999\n", 0o644) // modified, unstaged
	gatetest.WriteFile(t, filepath.Join(r, "d", "a.txt"), "staged\n", 0o644)
	gatetest.Git(t, r, "add", "d/a.txt")                                                 // modified, staged
	gatetest.WriteFile(t, filepath.Join(r, "d", "a.txt"), "staged then edited\n", 0o644) // and edited again
	if err := os.Chmod(filepath.Join(r, "run.sh"), 0o755); err != nil {                  // mode change
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(r, "gone.txt")); err != nil { // deleted
		t.Fatal(err)
	}
	gatetest.Git(t, r, "rm", "-q", "--cached", "unstage.txt") // staged deletion, file kept
	if err := os.Remove(filepath.Join(r, "lnk")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("d/a.txt", filepath.Join(r, "lnk")); err != nil { // symlink retargeted
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(r, "new.txt"), "new\n", 0o644)
	gatetest.Git(t, r, "add", "new.txt")                                         // staged new file
	gatetest.WriteFile(t, filepath.Join(r, "untracked.txt"), "u\n", 0o644)       // untracked
	gatetest.WriteFile(t, filepath.Join(r, "udir", "x.txt"), "x\n", 0o644)       // untracked directory
	gatetest.WriteFile(t, filepath.Join(r, "keep.log"), "ignored\n", 0o644)      // ignored
	gatetest.WriteFile(t, filepath.Join(r, "udir2", "keep.log"), "ign\n", 0o644) // ignored in a directory
	gatetest.WriteFile(t, filepath.Join(r, "udir2", "y.txt"), "y\n", 0o644)      // untracked next to it
}

// refs is everything a discard must leave alone: HEAD, every ref and the
// stash.
func refs(t *testing.T, g *gitFixture) string {
	t.Helper()
	return gatetest.Git(t, g.repo, "rev-parse", "HEAD") + gatetest.Git(t, g.repo, "symbolic-ref", "HEAD") +
		gatetest.Git(t, g.repo, "for-each-ref") + gatetest.Git(t, g.repo, "stash", "list")
}

func (g *gitFixture) preview(t *testing.T, untracked bool) discardPlan {
	t.Helper()
	var pv discardPlan
	g.ok("git_discard_preview", m{"repo": g.repo, "include_untracked": untracked}, &pv)
	return pv
}

func (g *gitFixture) discard(pv *discardPlan) response {
	return g.call("git_discard", m{"repo": g.repo, "include_untracked": pv.IncludeUntracked, "expected_preview_sha256": pv.PreviewSHA256})
}

func actions(pv *discardPlan) map[string]string {
	out := map[string]string{}
	for _, e := range pv.First {
		out[e.Path] = e.Status + " " + e.Action
	}
	return out
}

func TestGitDiscardPreviewReports(t *testing.T) {
	g := discardRepo(t)
	// A stash entry that must survive, made before the tree is dirtied.
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "stashed\n", 0o644)
	gatetest.Git(t, g.repo, "stash", "-q")
	dirty(t, g)

	pv := g.preview(t, false)
	if pv.Repo != g.repo || pv.Head != g.head(t) || pv.IncludeUntracked || len(pv.PreviewSHA256) != 64 || pv.Applied || pv.CleanAfter != nil {
		t.Fatalf("preview %+v", pv)
	}
	want := map[string]string{
		"app.conf": ".M restore", "d/a.txt": "MM restore", "run.sh": ".M restore", "gone.txt": ".D restore",
		"unstage.txt": "D. restore", "lnk": ".M restore", "new.txt": "A. remove",
	}
	if got := actions(&pv); !mapsEqual(got, want) {
		t.Fatalf("entries\n got %v\nwant %v", got, want)
	}
	if pv.Restore != 6 || pv.Remove != 1 || pv.Untracked != 0 || pv.Entries != 7 || pv.Truncated {
		t.Fatalf("counts %+v", pv)
	}
	if !slices.IsSortedFunc(pv.First, func(a, b discardEntry) int { return strings.Compare(a.Path, b.Path) }) {
		t.Fatalf("entries not sorted: %v", pv.First)
	}
	// The same state previews the same; include_untracked changes it.
	if again := g.preview(t, false); again.PreviewSHA256 != pv.PreviewSHA256 {
		t.Fatal("the same state hashed differently")
	}
	pu := g.preview(t, true)
	got := actions(&pu)
	for p, w := range map[string]string{"untracked.txt": "?? remove", "udir": "?? remove", "udir2/y.txt": "?? remove"} {
		if got[p] != w {
			t.Fatalf("untracked %s = %q (all %v)", p, got[p], got)
		}
	}
	for _, p := range []string{"keep.log", "udir2/keep.log", "udir2", "udir/x.txt"} {
		if _, ok := got[p]; ok {
			t.Fatalf("%s is listed: %v", p, got)
		}
	}
	if pu.Untracked != 3 || pu.UntrackedEntries != 4 || pu.Entries != 10 || pu.PreviewSHA256 == pv.PreviewSHA256 || !pu.IncludeUntracked {
		t.Fatalf("with untracked %+v", pu)
	}
}

func TestGitDiscardRestoresExactlyThePreview(t *testing.T) {
	for _, untracked := range []bool{false, true} {
		t.Run(fmt.Sprintf("include_untracked=%v", untracked), func(t *testing.T) {
			g := discardRepo(t)
			gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "stashed\n", 0o644)
			gatetest.Git(t, g.repo, "stash", "-q")
			dirty(t, g)
			before := refs(t, g)
			pv := g.preview(t, untracked)
			r := g.discard(&pv)
			if !r.OK {
				t.Fatalf("discard: %+v", r.Error)
			}
			var d discardPlan
			if err := json.Unmarshal(r.Data, &d); err != nil {
				t.Fatal(err)
			}
			if !d.Applied || d.CleanAfter == nil || d.PreviewSHA256 != pv.PreviewSHA256 || d.Entries != pv.Entries {
				t.Fatalf("result %+v", d)
			}
			if got := refs(t, g); got != before {
				t.Fatalf("HEAD, refs or the stash changed:\n%s\n%s", before, got)
			}
			for p, want := range map[string]string{"app.conf": "port=8080\n", "d/a.txt": "a\n", "gone.txt": "gone\n", "unstage.txt": "u\n", "keep.log": "ignored\n", "udir2/keep.log": "ign\n"} {
				if got := contentOf(t, filepath.Join(g.repo, p)); got != want {
					t.Fatalf("%s = %q, want %q", p, got, want)
				}
			}
			if fi, err := os.Stat(filepath.Join(g.repo, "run.sh")); err != nil || fi.Mode().Perm()&0o111 != 0 {
				t.Fatalf("run.sh mode %v %v", fi, err)
			}
			if tgt, err := os.Readlink(filepath.Join(g.repo, "lnk")); err != nil || tgt != "app.conf" {
				t.Fatalf("lnk -> %q %v", tgt, err)
			}
			if exists(filepath.Join(g.repo, "new.txt")) {
				t.Fatal("the staged new file was not removed")
			}
			for _, p := range []string{"untracked.txt", "udir/x.txt", "udir2/y.txt"} {
				if exists(filepath.Join(g.repo, p)) == untracked {
					t.Fatalf("%s exists=%v with include_untracked=%v", p, exists(filepath.Join(g.repo, p)), untracked)
				}
			}
			// The index is HEAD's tree.
			if st := gatetest.Git(t, g.repo, "status", "--porcelain=v2", "--untracked-files=no"); st != "" {
				t.Fatalf("status after discard: %q", st)
			}
			if diff := gatetest.Git(t, g.repo, "diff", "--cached", "--name-only"); diff != "" {
				t.Fatalf("index differs from HEAD: %q", diff)
			}
			if *d.CleanAfter != untracked {
				t.Fatalf("clean_after %v with include_untracked=%v", *d.CleanAfter, untracked)
			}
			assertNoGateLeftovers(t, g)
		})
	}
}

// assertNoGateLeftovers: no lock, temporary index or set-aside entry is
// left after a discard that finished.
func assertNoGateLeftovers(t *testing.T, g *gitFixture) {
	t.Helper()
	if exists(filepath.Join(g.repo, ".git", "index.lock")) {
		t.Fatal("index.lock was left")
	}
	ents, err := os.ReadDir(filepath.Join(g.repo, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".shell-mcp-") {
			t.Fatalf(".git/%s was left", e.Name())
		}
	}
	if aside := setAsideUnder(t, g.repo); len(aside) != 0 {
		t.Fatalf("set-aside entries left: %v", aside)
	}
}

func setAsideUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if strings.HasPrefix(d.Name(), ".shell-mcp-delete-") {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGitDiscardBindsThePreview(t *testing.T) {
	g := discardRepo(t)
	dirty(t, g)
	pv := g.preview(t, true)
	repo := g.repo
	// The preview takes no expected hash; the discard requires a valid one.
	g.fail("git_discard_preview", m{"repo": repo, "expected_preview_sha256": pv.PreviewSHA256}, "bad_request")
	g.fail("git_discard", m{"repo": repo, "include_untracked": true}, "bad_request")
	g.fail("git_discard", m{"repo": repo, "include_untracked": true, "expected_preview_sha256": strings.ToUpper(pv.PreviewSHA256)}, "bad_request")
	g.fail("git_discard", m{"repo": repo, "include_untracked": true, "expected_preview_sha256": 7}, "bad_request")
	// The flag is bound: the same hash with the other flag is a mismatch.
	g.fail("git_discard", m{"repo": repo, "include_untracked": false, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	// Every kind of change after the preview refuses, and changes nothing.
	for name, change := range map[string]func(){
		"tracked edited":    func() { gatetest.WriteFile(t, filepath.Join(repo, "app.conf"), "port=1\n", 0o644) },
		"untracked created": func() { gatetest.WriteFile(t, filepath.Join(repo, "udir", "late.txt"), "late\n", 0o644) },
		"staged":            func() { gatetest.Git(t, repo, "add", "app.conf") },
		"file replaced":     func() { replaceWith(t, filepath.Join(repo, "d", "a.txt"), "replaced\n") },
		"mode changed":      func() { _ = os.Chmod(filepath.Join(repo, "app.conf"), 0o600) },
		"commit":            func() { gatetest.Git(t, repo, "commit", "-q", "--allow-empty", "-m", "late") },
	} {
		pv = g.preview(t, true)
		snap := treeSnapshot(t, repo)
		change()
		after := treeSnapshot(t, repo)
		r := g.discard(&pv)
		if r.OK || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, "nothing was changed") {
			t.Fatalf("%s: %+v", name, r.Error)
		}
		if got := treeSnapshot(t, repo); got != after {
			t.Fatalf("%s: the tree changed (before the change:\n%s)\n%s\n%s", name, snap, after, got)
		}
		assertNoGateLeftovers(t, g)
	}
}

// treeSnapshot is every work-tree path with its content or link target and
// mode, and the index, as one string.
func treeSnapshot(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			tgt, _ := os.Readlink(p)
			fmt.Fprintf(&b, "%s -> %s\n", rel, tgt)
		case fi.Mode().IsRegular():
			c, _ := os.ReadFile(p) //nolint:gosec // G304: the test's own tree
			fmt.Fprintf(&b, "%s %o %q\n", rel, fi.Mode().Perm(), c)
		default:
			fmt.Fprintf(&b, "%s/\n", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String() + gatetest.Git(t, root, "ls-files", "-s")
}

func replaceWith(t *testing.T, p, content string) {
	t.Helper()
	tmp := p + ".racer-tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
}

func TestGitDiscardRefusals(t *testing.T) {
	g := discardRepo(t)
	repo := g.repo
	both := func(name string, args m, code, msg string) {
		t.Helper()
		r := g.call("git_discard_preview", args)
		if r.OK || r.Error.Code != code || !strings.Contains(r.Error.Message, msg) {
			t.Fatalf("%s: preview %+v", name, r.Error)
		}
		a := m{"expected_preview_sha256": strings.Repeat("a", 64)}
		for k, v := range args {
			a[k] = v
		}
		r = g.call("git_discard", a)
		if r.OK || r.Error.Code != code || !strings.Contains(r.Error.Message, msg) {
			t.Fatalf("%s: discard %+v", name, r.Error)
		}
	}
	both("not listed", m{"repo": filepath.Join(g.write, "other")}, "policy_denied", "git.repos")
	r := g.call("git_discard", m{"repo": filepath.Join(g.read, "readonly"), "expected_preview_sha256": strings.Repeat("a", 64)})
	if r.OK || r.Error.Code != "policy_denied" {
		t.Fatalf("read-only repo: %+v", r.Error)
	}

	gatetest.WriteFile(t, filepath.Join(repo, "app.conf"), "x\n", 0o644)
	for _, st := range []struct{ name, file string }{
		{"merge", "MERGE_HEAD"}, {"cherry-pick", "CHERRY_PICK_HEAD"}, {"revert", "REVERT_HEAD"}, {"bisect", "BISECT_LOG"},
		{"rebase", "rebase-merge/head-name"}, {"rebase (apply)", "rebase-apply/applying"}, {"sequencer", "sequencer/todo"},
	} {
		p := filepath.Join(repo, ".git", st.file)
		gatetest.WriteFile(t, p, g.head(t)+"\n", 0o644)
		both(st.name, m{"repo": repo}, "policy_denied", "in progress")
		top := filepath.Join(repo, ".git", strings.Split(st.file, "/")[0])
		if err := os.RemoveAll(top); err != nil {
			t.Fatal(err)
		}
	}
	// A lock git holds (or left) is reported and never removed.
	lock := filepath.Join(repo, ".git", "index.lock")
	gatetest.WriteFile(t, lock, "", 0o644)
	both("git lock", m{"repo": repo}, "exists", "locked by another git process")
	if !exists(lock) {
		t.Fatal("the gate removed a lock it did not create")
	}
	_ = os.Remove(lock)
	// A lock a gate left (it died holding it) says so, with the recovery.
	gatetest.WriteFile(t, lock, "shell-mcp-gate git_discard\n", 0o644)
	both("gate lock", m{"repo": repo}, "exists", "a gate that stopped while discarding")
	if !exists(lock) {
		t.Fatal("the gate removed a stale lock by itself")
	}
	_ = os.Remove(lock)

	// An unmerged entry.
	sha := strings.TrimSpace(gatetest.Git(t, repo, "hash-object", "-w", "app.conf"))
	cmd := exec.CommandContext(t.Context(), gatetest.GitBin, "update-index", "--index-info") //nolint:gosec // G204: test setup
	cmd.Dir, cmd.Env = repo, []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + repo}
	cmd.Stdin = strings.NewReader(fmt.Sprintf("0 %s\tapp.conf\n100644 %s 1\tapp.conf\n100644 %s 2\tapp.conf\n", strings.Repeat("0", 40), sha, sha))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("index-info: %v %s", err, out)
	}
	both("unmerged", m{"repo": repo}, "policy_denied", "unmerged")
	gatetest.Git(t, repo, "reset", "-q", "--hard")

	// A submodule (gitlink) change.
	gatetest.Git(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+g.head(t)+",sub")
	both("submodule", m{"repo": repo}, "policy_denied", "submodule")
	gatetest.Git(t, repo, "reset", "-q")

	// A directory where a tracked file was: refused without
	// include_untracked (with a hint), discarded with it.
	if err := os.Remove(filepath.Join(repo, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(repo, "gone.txt", "inner.txt"), "i\n", 0o644)
	both("dir in the way", m{"repo": repo}, "bad_request", "include_untracked")
	pv := g.preview(t, true)
	if r := g.discard(&pv); !r.OK || contentOf(t, filepath.Join(repo, "gone.txt")) != "gone\n" {
		t.Fatalf("dir in the way with include_untracked: %+v", r.Error)
	}
	// A file where a tracked directory was.
	if err := os.RemoveAll(filepath.Join(repo, "d")); err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(repo, "d"), "file\n", 0o644)
	both("file in the way", m{"repo": repo}, "bad_request", "include_untracked")
	pv = g.preview(t, true)
	if r := g.discard(&pv); !r.OK || contentOf(t, filepath.Join(repo, "d", "a.txt")) != "a\n" {
		t.Fatalf("file in the way with include_untracked: %+v", r.Error)
	}
	// A directory holding ignored files where a tracked file was: never
	// resolved, since ignored files are never removed.
	if err := os.Remove(filepath.Join(repo, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(repo, "gone.txt", "x.log"), "ignored\n", 0o644)
	r = g.call("git_discard_preview", m{"repo": repo, "include_untracked": true})
	if r.OK || r.Error.Code != "bad_request" || !strings.Contains(r.Error.Message, "gone.txt") {
		t.Fatalf("ignored in the way: %+v", r.Error)
	}
	_ = os.RemoveAll(filepath.Join(repo, "gone.txt"))
	gatetest.Git(t, repo, "checkout", "--", "gone.txt")

	// An untracked symlink is never removed.
	if err := os.Symlink("app.conf", filepath.Join(repo, "ulink")); err != nil {
		t.Fatal(err)
	}
	r = g.call("git_discard_preview", m{"repo": repo, "include_untracked": true})
	if r.OK || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, "ulink") {
		t.Fatalf("untracked symlink: %+v", r.Error)
	}
	g.ok("git_discard_preview", m{"repo": repo}, nil) // untracked entries are not considered without the flag
	_ = os.Remove(filepath.Join(repo, "ulink"))

	// A repository without commits.
	empty := filepath.Join(g.write, "empty")
	gatetest.Mkdir(t, empty, 0o755)
	gatetest.Git(t, empty, "init", "-q")
	g.policy("destructive", "    - path: {W}/empty\n      remote: {REMOTE}\n")
	both("no commits", m{"repo": empty}, "bad_request", "no commits")

	// The tier ceiling and max_tier.
	g.deniedAt("operator", "git_discard", m{"repo": repo, "expected_preview_sha256": strings.Repeat("a", 64)}, "ceiling operator")
	g.policy("operator", "")
	g.fail("git_discard", m{"repo": repo, "expected_preview_sha256": strings.Repeat("a", 64)}, "tier_denied")
	g.ok("git_discard_preview", m{"repo": repo}, nil)
}

// TestGitDiscardHooksNeverRun is two-sided. Control: hooks planted in the
// repository run when git writes an index the way the discard does, but
// without the gate's flags. Gated: neither the preview nor the discard
// runs any of them.
func TestGitDiscardHooksNeverRun(t *testing.T) {
	g := discardRepo(t)
	marker := filepath.Join(g.dir, "hook-ran")
	for _, h := range []string{"post-index-change", "post-checkout", "reference-transaction", "pre-commit", "post-rewrite"} {
		gatetest.WriteFile(t, filepath.Join(g.repo, ".git", "hooks", h), "#!/bin/sh\necho "+h+" >> "+marker+"\n", 0o755)
	}
	// Control: git's own read-tree into a scratch index runs post-index-change.
	scratch := filepath.Join(g.dir, "scratch-index")
	cmd := exec.CommandContext(t.Context(), gatetest.GitBin, "read-tree", "HEAD") //nolint:gosec // G204: test control
	cmd.Dir = g.repo
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + g.dir, "GIT_INDEX_FILE=" + scratch}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("control read-tree: %v %s", err, out)
	}
	if !exists(marker) {
		t.Fatal("control: the planted hook did not run without the gate's flags; the check below would prove nothing")
	}
	// The test's own setup (git add, git rm) runs the hooks too; only what
	// the gate does from here on counts.
	dirty(t, g)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	pv := g.preview(t, true)
	if r := g.discard(&pv); !r.OK {
		t.Fatalf("discard: %+v", r.Error)
	}
	if exists(marker) {
		b, _ := os.ReadFile(marker) //nolint:gosec // G304: the test's own marker
		t.Fatalf("a hook ran during git_discard_preview or git_discard: %s", b)
	}
}

// TestGitDiscardHoldsTheIndexLock: while the discard runs it holds git's
// index lock, so a concurrent git add fails rather than being undone, and
// the lock is released afterwards, also when the discard stops.
func TestGitDiscardHoldsTheIndexLock(t *testing.T) {
	g := discardRepo(t)
	dirty(t, g)
	pv := g.preview(t, false)
	lock := filepath.Join(g.repo, ".git", "index.lock")
	other := filepath.Join(g.repo, "unstage.txt")
	var addOut string
	var addErr error
	fired := false
	g.opts.InjectDiscardStep = func(s fsx.DiscardStep, _ string) {
		if s != fsx.DiscardStepAfterCompare {
			return
		}
		fired = true
		if !exists(lock) {
			t.Error("no index.lock while the discard runs")
		}
		gatetest.WriteFile(t, filepath.Join(g.repo, "late.txt"), "late\n", 0o644)
		cmd := exec.CommandContext(t.Context(), gatetest.GitBin, "add", "late.txt") //nolint:gosec // G204: the concurrent git
		cmd.Dir, cmd.Env = g.repo, []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + g.dir}
		var b []byte
		b, addErr = cmd.CombinedOutput()
		addOut = string(b)
	}
	r := g.discard(&pv)
	g.opts.InjectDiscardStep = nil
	if !fired || !r.OK {
		t.Fatalf("fired %v discard %+v", fired, r.Error)
	}
	if addErr == nil || !strings.Contains(addOut, "index.lock") {
		t.Fatalf("the concurrent git add did not fail on the lock: %v %q", addErr, addOut)
	}
	if exists(lock) {
		t.Fatal("the lock was not released")
	}
	// The newcomer the failed add would have staged is untouched.
	if contentOf(t, filepath.Join(g.repo, "late.txt")) != "late\n" || !exists(other) {
		t.Fatal("an unseen file was touched")
	}
	// A discard that stops releases the lock too.
	dirty(t, g)
	pv = g.preview(t, false)
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "after preview\n", 0o644)
	if r := g.discard(&pv); r.OK {
		t.Fatal("a changed tree was discarded")
	}
	if exists(lock) {
		t.Fatal("the lock was not released after a refusal")
	}
}

// TestGitDiscardStaleGateLock: a gate that dies holding the lock leaves it
// marked; the next preview and discard report it and never remove it.
func TestGitDiscardStaleGateLock(t *testing.T) {
	g := discardRepo(t)
	dirty(t, g)
	pv := g.preview(t, false)
	lock := filepath.Join(g.repo, ".git", "index.lock")
	var kept []byte
	g.opts.InjectDiscardStep = func(s fsx.DiscardStep, _ string) {
		if s == fsx.DiscardStepBeforeCheckout {
			// What a gate killed here leaves: its lock file.
			b, err := os.ReadFile(lock) //nolint:gosec // G304: the test's repository
			if err != nil {
				t.Error(err)
			}
			kept = b
		}
	}
	if r := g.discard(&pv); !r.OK {
		t.Fatalf("discard %+v", r.Error)
	}
	g.opts.InjectDiscardStep = nil
	if len(kept) == 0 {
		t.Fatal("the gate's lock carries no marker")
	}
	gatetest.WriteFile(t, lock, string(kept), 0o644)
	for _, c := range []struct {
		op   string
		args m
	}{
		{"git_discard_preview", m{"repo": g.repo}},
		{"git_discard", m{"repo": g.repo, "expected_preview_sha256": strings.Repeat("b", 64)}},
	} {
		r := g.call(c.op, c.args)
		if r.OK || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, "a gate that stopped while discarding") ||
			!strings.Contains(r.Error.Message, "remove .git/index.lock") {
			t.Fatalf("%s over a stale gate lock: %+v", c.op, r.Error)
		}
		if !exists(lock) {
			t.Fatalf("%s removed the stale lock by itself", c.op)
		}
	}
}

// discardWindowReps is how many times each step and change kind runs.
const discardWindowReps = 6

// TestGitDiscardWindow: a change made after the preview — a tracked file
// edited in place, an untracked file created, or a file replaced — at every
// point of a discard, must survive in every run.
func TestGitDiscardWindow(t *testing.T) {
	g := discardRepo(t)
	type point struct {
		name    string
		discard fsx.DiscardStep
		del     fsx.DeleteStep
	}
	points := []point{
		{name: "before the call"},
		{name: "after compare", discard: fsx.DiscardStepAfterCompare},
		{name: "before entry", del: fsx.DeleteStepBeforeEntry},
		{name: "before rename", del: fsx.DeleteStepBeforeRename},
		{name: "after rename", del: fsx.DeleteStepAfterRename},
		{name: "before unlink", del: fsx.DeleteStepBeforeUnlink},
		{name: "before untracked", discard: fsx.DiscardStepBeforeUntracked},
		{name: "before checkout", discard: fsx.DiscardStepBeforeCheckout},
		{name: "after checkout", discard: fsx.DiscardStepAfterCheckout},
		{name: "before commit", discard: fsx.DiscardStepBeforeCommit},
	}
	kinds := []string{"edit", "create", "replace"}
	outcomes := map[string]int{}
	runs := 0
	victim := filepath.Join(g.repo, "app.conf")
	for rep := range discardWindowReps {
		for _, pt := range points {
			for _, kind := range kinds {
				runs++
				i := runs
				resetRepo(t, g)
				dirty(t, g)
				pv := g.preview(t, true)
				marker := fmt.Sprintf("racer %d %s %s\n", i, pt.name, kind)
				created := filepath.Join(g.repo, "udir", fmt.Sprintf("racer-%d.txt", i))
				fired := false
				race := func() {
					if fired {
						return
					}
					fired = true
					switch kind {
					case "edit":
						appendTo(t, victim, marker)
					case "create":
						if !exists(filepath.Dir(created)) {
							created = filepath.Join(g.repo, fmt.Sprintf("racer-%d.txt", i))
						}
						gatetest.WriteFile(t, created, marker, 0o644)
					case "replace":
						replaceWith(t, victim, marker)
					}
				}
				g.opts.InjectDiscardStep = func(s fsx.DiscardStep, _ string) {
					if pt.discard != 0 && s == pt.discard {
						race()
					}
				}
				g.opts.InjectDeleteStep = func(s fsx.DeleteStep, p string) {
					if pt.del != 0 && s == pt.del && p == victim {
						race()
					}
				}
				if pt.name == "before the call" {
					race()
				}
				r := g.discard(&pv)
				g.opts.InjectDiscardStep, g.opts.InjectDeleteStep = nil, nil
				if !fired {
					t.Fatalf("run %d (%s, %s): the discard never reached the point", i, pt.name, kind)
				}
				out := "ok"
				if !r.OK {
					out = r.Error.Code
				}
				outcomes[pt.name+"/"+kind+"/"+out]++
				switch kind {
				case "edit":
					if c := contentOf(t, victim); !strings.Contains(c, marker) {
						t.Fatalf("run %d (rep %d, %s): the edit was discarded: %q (result %+v)", i, rep, pt.name, c, r.Error)
					}
				case "create":
					if c := contentOf(t, created); c != marker {
						t.Fatalf("run %d (rep %d, %s): the created file was removed or changed: %q", i, rep, pt.name, c)
					}
				case "replace":
					if c := contentOf(t, victim); c != marker {
						t.Fatalf("run %d (rep %d, %s): the replacement was discarded: %q (result %+v)", i, rep, pt.name, c, r.Error)
					}
				}
				if exists(filepath.Join(g.repo, ".git", "index.lock")) {
					t.Fatalf("run %d: the lock was left", i)
				}
			}
		}
	}
	keys := make([]string, 0, len(outcomes))
	for k := range outcomes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		t.Logf("%-40s %d", k, outcomes[k])
	}
	t.Logf("git discard window: %d runs, every change made after the preview survived", runs)
}

// TestGitDiscardConcurrentRacer: no hooks; a goroutine replaces a tracked
// file and creates untracked files until the discard returns, starting
// after a random delay. Every replacement and every created file survives.
func TestGitDiscardConcurrentRacer(t *testing.T) {
	g := discardRepo(t)
	victim := filepath.Join(g.repo, "app.conf")
	const runs = 100
	outcomes := map[string]int{}
	racerFiles := 0
	for i := range runs {
		resetRepo(t, g)
		dirty(t, g)
		pv := g.preview(t, true)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var last string
		var made []string
		wg.Go(func() {
			time.Sleep(time.Duration(rand.IntN(20)) * time.Millisecond) //nolint:gosec // G404: test timing
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				content := fmt.Sprintf("run %d replacement %d\n", i, n)
				tmp := filepath.Join(g.dir, "racer-tmp")
				if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
					t.Error(err)
					return
				}
				if err := os.Rename(tmp, victim); err != nil {
					t.Error(err)
					return
				}
				last = content
				p := filepath.Join(g.repo, fmt.Sprintf("racer-%d-%d.txt", i, n))
				if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
					t.Error(err)
					return
				}
				made = append(made, p)
				time.Sleep(200 * time.Microsecond)
			}
		})
		r := g.discard(&pv)
		close(stop)
		wg.Wait()
		out := "ok"
		if !r.OK {
			out = r.Error.Code
		}
		outcomes[out]++
		if last != "" && contentOf(t, victim) != last {
			t.Fatalf("run %d: a replacement was discarded (%q, last %q, result %+v)", i, contentOf(t, victim), last, r.Error)
		}
		for _, p := range made {
			if !exists(p) {
				t.Fatalf("run %d: %s was removed", i, p)
			}
		}
		racerFiles += len(made)
	}
	t.Logf("concurrent racer: %d runs, outcomes %v, %d racer files, every one survived", runs, outcomes, racerFiles)
}

// TestGitDiscardNamesAStrandedEntry: an entry set aside whose name is taken
// before it can be put back stays under its temporary name; the refusal
// and the audit line name it, the index is unchanged, and a later preview
// with include_untracked refuses to remove it.
func TestGitDiscardNamesAStrandedEntry(t *testing.T) {
	g := discardRepo(t)
	next := g.auditTo(t)
	dirty(t, g)
	indexBefore := gatetest.Git(t, g.repo, "ls-files", "-s")
	pv := g.preview(t, false)
	_ = next()
	victim := filepath.Join(g.repo, "app.conf")
	g.opts.InjectDiscardStep = func(s fsx.DiscardStep, _ string) {
		if s == fsx.DiscardStepAfterCheckout {
			replaceWith(t, victim, "newcomer\n")
		}
	}
	r := g.discard(&pv)
	g.opts.InjectDiscardStep = nil
	if r.OK || r.Error.Code != "exists" {
		t.Fatalf("discard: %+v", r.Error)
	}
	aside := setAsideUnder(t, g.repo)
	if len(aside) != 1 || contentOf(t, aside[0]) != "port=9999\n" || contentOf(t, victim) != "newcomer\n" {
		t.Fatalf("set aside %v, victim %q", aside, contentOf(t, victim))
	}
	if !strings.Contains(r.Error.Message, aside[0]) || !strings.Contains(r.Error.Message, "the index was not changed") {
		t.Fatalf("message: %q", r.Error.Message)
	}
	if line := next(); !strings.Contains(line, `"set_aside":"`+aside[0]+`"`) {
		t.Fatalf("audit: %s", line)
	}
	if got := gatetest.Git(t, g.repo, "ls-files", "-s"); got != indexBefore {
		t.Fatalf("the index changed:\n%s\n%s", indexBefore, got)
	}
	rr := g.call("git_discard_preview", m{"repo": g.repo, "include_untracked": true})
	if rr.OK || rr.Error.Code != "path_denied" || !strings.Contains(rr.Error.Message, "set aside") {
		t.Fatalf("preview over a stranded entry: %+v", rr.Error)
	}
}

func resetRepo(t *testing.T, g *gitFixture) {
	t.Helper()
	gatetest.Git(t, g.repo, "reset", "-q", "--hard")
	gatetest.Git(t, g.repo, "clean", "-q", "-f", "-f", "-d", "-x")
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644) //nolint:gosec // G302/G304: the test's own tree
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
