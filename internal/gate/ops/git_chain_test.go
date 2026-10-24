//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
)

// The gate's git repositories are closed and git's configuration isolated
// (POLICY §7, handoff docs/handoff/S4C-PRIVILEGED.md N-20). Before any git
// process starts, every git operation requires every directory from / to
// the repository, the repository, .git and .git/config to be owned by root
// or the service account and neither group- nor world-writable nor sticky,
// .git to be a real directory and .git/commondir and .git/config.worktree
// not to exist. And every git process gets command-line overrides and
// environment variables for every program-running configuration key with a
// fixed name. An unprivileged test cannot give a directory to another
// account, so here "another account can write it" is an open mode; e2e-host
// runs the owners. Repositories, paths and contents are invented.

// gitHookEvents are gitx's hook events (githooks(5)), each disabled.
var gitHookEvents = gitx.HookEvents

// gitOverrides are the -c values every git process must carry, in order:
// the hardening flags of #26 and before, then N-20's program-running keys
// and hook events from gitx's table (TestGitProgramKeysCovered checks the
// table against the installed git), each once. safe.directory is not among
// them: git applies no ownership check to a repository GIT_DIR names, the
// gate's or a submodule's, so it did nothing (POLICY §7).
func gitOverrides() []string {
	o := []string{"core.fsmonitor=false", "core.hooksPath=/dev/null", "core.pager=cat", "core.sshCommand=/bin/false", "credential.helper=",
		"protocol.file.allow=never", "protocol.ext.allow=never", "maintenance.auto=false", "gc.auto=0",
		"gc.autoDetach=false", "core.ignorecase=false"}
	for _, p := range gitx.ProgramOverrides() {
		if !slices.Contains(o, p) {
			o = append(o, p)
		}
	}
	return o
}

// gitProgramEnv are the environment variables every git process must get,
// so that none can name a program (N-20; gitx's table).
var gitProgramEnv = gitx.ProgramEnv()

// gitOps is every git operation with arguments that pass its own checks.
func gitOps(repo string) []struct {
	op   string
	args m
} {
	return []struct {
		op   string
		args m
	}{
		{"git_status", m{"repo": repo}}, {"git_log", m{"repo": repo}}, {"git_diff", m{"repo": repo}}, {"git_pull", m{"repo": repo}},
		{"git_discard_preview", m{"repo": repo, "include_untracked": true}},
		{"git_discard", m{"repo": repo, "include_untracked": true, "expected_preview_sha256": strings.Repeat("a", 64)}},
	}
}

// smallChange edits a tracked file and adds an untracked one, for a discard
// to restore and remove.
func smallChange(t *testing.T, g *gitFixture) {
	t.Helper()
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "port=9999\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "untracked.txt"), "u\n", 0o644)
}

// gitState is everything a refused git operation must leave alone: the work
// tree and index, HEAD and every ref, and .git's top-level names.
func gitState(t *testing.T, g *gitFixture) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(g.repo, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return treeSnapshot(t, g.repo) + refs(t, g) + strings.Join(names, " ")
}

// TestGitRepoChain: with the read root, the write root, the repository,
// .git or .git/config group-writable, world-writable or (a directory)
// sticky, every git operation is refused with path_denied naming the entry,
// its owner and its mode, before any git process starts, and nothing
// changes; closed again, each runs.
func TestGitRepoChain(t *testing.T) {
	g := newGitFixture(t, "destructive")
	gatetest.Push(t, g.work, "upstream.txt", "from upstream\n", "upstream change")
	smallChange(t, g)
	gitDir := filepath.Join(g.repo, ".git")
	config := filepath.Join(gitDir, "config")
	for _, lvl := range []struct {
		name, path, entry string
		modes             []os.FileMode
	}{
		{"read root", g.read, "the directory " + g.read, []os.FileMode{0o775, os.ModeSticky | 0o755}},
		{"write root", g.write, "the directory " + g.write, []os.FileMode{0o777, os.ModeSticky | 0o777}},
		{"repository", g.repo, "the directory " + g.repo, []os.FileMode{0o775, 0o757, os.ModeSticky | 0o755}},
		{".git", gitDir, "the directory " + gitDir, []os.FileMode{0o775, 0o777, os.ModeSticky | 0o755}},
		{".git/config", config, "the file " + config, []os.FileMode{0o664, 0o646}},
	} {
		fi, err := os.Lstat(lvl.path)
		if err != nil {
			t.Fatal(err)
		}
		closed := fi.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		for _, mode := range lvl.modes {
			t.Run(lvl.name+" "+mode.String(), func(t *testing.T) {
				before := gitState(t, g)
				if err := os.Chmod(lvl.path, mode); err != nil {
					t.Fatal(err)
				}
				gatetest.ExactMode(t, lvl.path, mode)
				defer func() {
					if err := os.Chmod(lvl.path, closed); err != nil {
						t.Error(err)
					}
				}()
				for _, c := range gitOps(g.repo) {
					r := g.call(c.op, c.args)
					if r.OK || r.Error == nil || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, lvl.entry+" is ") ||
						!strings.Contains(r.Error.Message, "owner uid ") || !strings.Contains(r.Error.Message, "nothing was run") {
						t.Fatalf("%s: %+v, want path_denied naming %s, its owner and its mode", c.op, r.Error, lvl.entry)
					}
				}
				if after := gitState(t, g); after != before {
					t.Fatalf("a refused git operation changed the repository:\nbefore %s\nafter  %s", before, after)
				}
			})
		}
	}
	// Closed: every operation passes the check (the pull refuses the dirty
	// tree, the discard the stale hash: both after the check).
	for _, c := range gitOps(g.repo) {
		if r := g.call(c.op, c.args); r.Error != nil && r.Error.Code == "path_denied" {
			t.Fatalf("closed: %s refused: %+v", c.op, r.Error)
		}
	}
	pv := g.preview(t, true)
	if r := g.discard(&pv); !r.OK {
		t.Fatalf("closed: discard: %+v", r.Error)
	}
	g.ok("git_pull", m{"repo": g.repo}, nil)
}

// TestGitRepoStructure: a gitfile .git, an existing .git/commondir and an
// existing .git/config.worktree are refused for every git operation
// (policy_denied), and nothing changes.
func TestGitRepoStructure(t *testing.T) {
	g := discardRepo(t)
	gitDir := filepath.Join(g.repo, ".git")
	for _, c := range []struct {
		name         string
		make, remove func(t *testing.T)
	}{
		{"gitfile", func(t *testing.T) {
			if err := os.Rename(gitDir, filepath.Join(g.repo, "real.git")); err != nil {
				t.Fatal(err)
			}
			gatetest.WriteFile(t, gitDir, "gitdir: "+filepath.Join(g.repo, "real.git")+"\n", 0o644)
		}, func(t *testing.T) {
			if err := os.Remove(gitDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(g.repo, "real.git"), gitDir); err != nil {
				t.Fatal(err)
			}
		}},
		{"commondir", func(t *testing.T) {
			gatetest.WriteFile(t, filepath.Join(gitDir, "commondir"), filepath.Join(g.read, "readonly", ".git")+"\n", 0o644)
		}, func(t *testing.T) {
			if err := os.Remove(filepath.Join(gitDir, "commondir")); err != nil {
				t.Fatal(err)
			}
		}},
		{"config.worktree", func(t *testing.T) {
			gatetest.WriteFile(t, filepath.Join(gitDir, "config.worktree"), "[core]\n\tbare = false\n", 0o644)
		}, func(t *testing.T) {
			if err := os.Remove(filepath.Join(gitDir, "config.worktree")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.make(t)
			defer c.remove(t)
			for _, o := range gitOps(g.repo) {
				r := g.call(o.op, o.args)
				if r.OK || r.Error == nil || r.Error.Code != "policy_denied" {
					t.Fatalf("%s with a %s: %+v %s, want policy_denied", o.op, c.name, r.Error, r.Data)
				}
			}
		})
	}
	g.ok("git_status", m{"repo": g.repo}, nil)
}

// gitRun is one git process the gate started, as the recorder logged it.
type gitRun struct{ argv, env []string }

// recordedGits reads the recorder's log: argv and environment lines in
// pairs.
func recordedGits(t *testing.T, logp string) []gitRun {
	t.Helper()
	b, err := os.ReadFile(logp) //nolint:gosec // G304: the test's own log
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines)%2 != 0 {
		t.Fatalf("log has %d lines, want argv and environment pairs", len(lines))
	}
	var out []gitRun
	for i := 0; i < len(lines); i += 2 {
		var r gitRun
		if json.Unmarshal([]byte(lines[i]), &r.argv) != nil || json.Unmarshal([]byte(lines[i+1]), &r.env) != nil {
			t.Fatalf("log lines %q %q", lines[i], lines[i+1])
		}
		out = append(out, r)
	}
	return out
}

// TestGitEveryProcessIsolated: every git process every git operation
// starts (seven for a pull, more for a discard) carries every -c override,
// before its subcommand, and every environment setting above. The gate's
// git is a recorder that logs each run and then executes the real git.
func TestGitEveryProcessIsolated(t *testing.T) {
	g := newGitFixture(t, "destructive")
	logp := filepath.Join(g.dir, "git.log")
	g.opts.Git = gatetest.BuildGitRecorder(t, g.bin, logp, ops.GitPath)
	gatetest.Push(t, g.work, "upstream.txt", "from upstream\n", "upstream change")
	counts := map[string]int{}
	seen := 0
	run := func(op string, args m) {
		t.Helper()
		g.ok(op, args, nil)
		all := recordedGits(t, logp)
		counts[op] = len(all) - seen
		seen = len(all)
	}
	run("git_pull", m{"repo": g.repo})
	smallChange(t, g)
	run("git_status", m{"repo": g.repo})
	run("git_log", m{"repo": g.repo})
	run("git_diff", m{"repo": g.repo})
	var pv discardPlan
	g.ok("git_discard_preview", m{"repo": g.repo, "include_untracked": true}, &pv)
	counts["git_discard_preview"] = len(recordedGits(t, logp)) - seen
	seen += counts["git_discard_preview"]
	run("git_discard", m{"repo": g.repo, "include_untracked": true, "expected_preview_sha256": pv.PreviewSHA256})
	if counts["git_pull"] < 7 || counts["git_discard"] < 8 {
		t.Fatalf("git processes per operation %v: the recorder did not see every run", counts)
	}
	for op, n := range counts {
		if n < 1 {
			t.Fatalf("%s started no git process (%v)", op, counts)
		}
	}
	want := gitOverrides()
	for i, r := range recordedGits(t, logp) {
		if slices.ContainsFunc(r.argv, func(a string) bool { return strings.Contains(a, "safe.directory") }) {
			t.Fatalf("git run %d carries safe.directory, which does nothing for a repository GIT_DIR names: %q", i, r.argv)
		}
		var got []string
		for j := 0; j+1 < len(r.argv); j++ {
			if r.argv[j] == "-c" {
				got = append(got, r.argv[j+1])
				j++
			}
		}
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Fatalf("git run %d %q lacks -c %s", i, r.argv, w)
			}
		}
		// Every override is one of git's own options, in order, after -C
		// <repo> --no-pager --no-optional-locks and before the subcommand.
		if k := slices.Index(r.argv, "-c"); k != 4 || len(r.argv) < 4+2*len(want) || !slices.Equal(r.argv[4:4+2*len(want)], interleave(want)) {
			t.Fatalf("git run %d: the overrides are not git's options before the subcommand: %q", i, r.argv)
		}
		for _, e := range gitProgramEnv {
			if !slices.Contains(r.env, e) {
				t.Fatalf("git run %d %q lacks %s in its environment %q", i, r.argv, e, r.env)
			}
		}
	}
	t.Logf("git processes per operation: %v", counts)
}

// interleave returns "-c", v for each value.
func interleave(vals []string) []string {
	out := make([]string, 0, 2*len(vals))
	for _, v := range vals {
		out = append(out, "-c", v)
	}
	return out
}

// TestGitConfigHooksDisabled is two-sided. Control: git 2.55 runs a hook
// defined in configuration (hook.<name>.command and .event) although
// core.hooksPath is /dev/null. Gated: with the gate's argv and environment
// it runs none. The gate's own operations refuse such configuration
// outright (policy_denied, POLICY §7); this proves the second layer.
func TestGitConfigHooksDisabled(t *testing.T) {
	g := newGitFixture(t, "read")
	marker := filepath.Join(g.dir, "MARKER")
	script := filepath.Join(g.dir, "mark.sh")
	gatetest.WriteFile(t, script, "#!/bin/sh\necho \"$0 $*\" >> "+marker+"\n", 0o755)
	gatetest.Git(t, g.repo, "config", "hook.marker.command", script)
	for _, e := range gitHookEvents {
		gatetest.Git(t, g.repo, "config", "--add", "hook.marker.event", e)
	}
	control := exec.CommandContext(t.Context(), ops.GitPath, "-c", "core.hooksPath=/dev/null", "update-ref", "refs/heads/control", "HEAD") //nolint:gosec // G204: test control, fixed git
	control.Dir = g.repo
	control.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + g.dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	out, err := control.CombinedOutput()
	ver := strings.TrimSpace(gatetest.Git(t, g.dir, "version"))
	if err != nil {
		t.Fatalf("control update-ref (%s): %v %s", ver, err, out)
	}
	if !exists(marker) {
		t.Skipf("%s runs no hooks defined in configuration (git 2.55 does); nothing to disable", ver)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	runLikeGate(t, g, "update-ref", "refs/heads/gated", "HEAD")
	if strings.TrimSpace(gatetest.Git(t, g.repo, "rev-parse", "refs/heads/gated")) == "" {
		t.Fatal("the gated update-ref did not run")
	}
	if exists(marker) {
		b, _ := os.ReadFile(marker) //nolint:gosec // G304: the test's own marker
		t.Fatalf("%s ran a configured hook with the gate's argv: %s", ver, b)
	}
	g.fail("git_status", m{"repo": g.repo}, "policy_denied")
	t.Logf("%s: configured hooks run without the gate's flags and not with them", ver)
}
