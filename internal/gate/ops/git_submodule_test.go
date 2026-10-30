//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
)

// No git process the gate starts enters a submodule (handoff
// docs/handoff/S4C-PRIVILEGED.md N-23, POLICY §7). Git's status and diff
// check each populated gitlink by starting `git status` inside it, under
// that repository's own configuration, which neither the allowlist nor the
// closed repository rule covers. Here the gitlink vendor/lib holds a
// repository whose configuration names a clean filter that only creates a
// marker file in the test's directory, applied to a file whose stat data
// changed, so that any git status run inside it runs the filter. No gate
// operation may create the marker; each still works, minus the
// submodule's own state. Repositories, names and contents are invented.

// gitlinkFixture is a gitFixture whose repository has the gitlink
// vendor/lib, committed upstream and fast-forwarded into the repository,
// populated with a clone of lib-src configured with the marker filter.
type gitlinkFixture struct {
	*gitFixture
	src    string // lib-src: the submodule's own upstream
	lib    string // <repo>/vendor/lib
	marker string
	bare   string // the superproject's bare upstream
}

// gitmodulesNone is a .gitmodules that names vendor/lib with ignore = none,
// which beats diff.ignoreSubmodules=all on its own (git 2.55,
// set_diffopt_flags_from_submodule_config).
const gitmodulesNone = "[submodule \"lib\"]\n\tpath = vendor/lib\n\turl = https://lib.example.test/lib.git\n\tignore = none\n"

func newGitlinkFixture(t *testing.T, tier string, gitmodules bool) *gitlinkFixture {
	t.Helper()
	g := newGitFixture(t, tier)
	l := &gitlinkFixture{gitFixture: g, src: filepath.Join(g.dir, "lib-src"), lib: filepath.Join(g.repo, "vendor", "lib"),
		marker: filepath.Join(g.dir, "MARKER"), bare: filepath.Join(g.srv.Root, "deploy.git")}
	gatetest.Mkdir(t, l.src, 0o755)
	gatetest.Git(t, l.src, "init", "-q")
	gatetest.WriteFile(t, filepath.Join(l.src, "data.txt"), "data\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(l.src, ".gitattributes"), "data.txt filter=marker\n", 0o644)
	gatetest.Git(t, l.src, "add", "-A")
	gatetest.Git(t, l.src, "commit", "-q", "-m", "lib")
	// The seed working copy keeps an empty directory at the gitlink, so
	// that its later `add -A` leaves the gitlink alone.
	gatetest.Mkdir(t, filepath.Join(g.work, "vendor", "lib"), 0o755)
	gatetest.Git(t, g.work, "update-index", "--add", "--cacheinfo", "160000,"+l.srcHead(t)+",vendor/lib")
	if gitmodules {
		gatetest.WriteFile(t, filepath.Join(g.work, ".gitmodules"), gitmodulesNone, 0o644)
		gatetest.Git(t, g.work, "add", ".gitmodules")
	}
	gatetest.Git(t, g.work, "commit", "-q", "-m", "add lib")
	gatetest.Git(t, g.work, "push", "-q", "origin", "main")
	gatetest.Git(t, g.repo, "pull", "-q", "--ff-only", "--no-recurse-submodules", l.bare, "main")
	gatetest.Git(t, filepath.Dir(l.lib), "clone", "-q", l.src, "lib")
	gatetest.Git(t, l.lib, "config", "filter.marker.clean", "touch "+l.marker+"; cat")
	l.statDirty(t)
	return l
}

// srcHead is lib-src's HEAD.
func (l *gitlinkFixture) srcHead(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(gatetest.Git(t, l.src, "rev-parse", "HEAD"))
}

// statDirty changes data.txt's stat data in the submodule, not its
// content: a git status inside it must then read the file through the
// filter to compare it.
func (l *gitlinkFixture) statDirty(t *testing.T) {
	t.Helper()
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(l.lib, "data.txt"), old, old); err != nil {
		t.Fatal(err)
	}
}

// noMarker fails when the submodule's filter ran.
func (l *gitlinkFixture) noMarker(t *testing.T, what string) {
	t.Helper()
	if exists(l.marker) {
		t.Fatalf("%s entered the submodule: the filter its own configuration names ran", what)
	}
}

// TestGitNeverEntersSubmodule: no git operation runs the submodule's
// filter, with or without a .gitmodules that sets ignore = none, and each
// answers.
func TestGitNeverEntersSubmodule(t *testing.T) {
	for _, gm := range []bool{false, true} {
		for _, op := range []string{"git_status", "git_log", "git_diff", "git_diff_staged", "git_pull", "git_discard_preview", "git_discard"} {
			name := op
			if gm {
				name += "/gitmodules ignore=none"
			}
			t.Run(name, func(t *testing.T) {
				l := newGitlinkFixture(t, "destructive", gm)
				args := m{"repo": l.repo}
				call := op
				switch op {
				case "git_diff_staged":
					call, args["staged"] = "git_diff", true
				case "git_pull":
					gatetest.Push(t, l.work, "upstream.txt", "from upstream\n", "upstream change")
				case "git_discard_preview", "git_discard":
					smallChange(t, l.gitFixture)
					args["include_untracked"] = true
					if op == "git_discard" {
						var pv discardPlan
						l.ok("git_discard_preview", m{"repo": l.repo, "include_untracked": true}, &pv)
						args["expected_preview_sha256"] = pv.PreviewSHA256
					}
				}
				// Only the operation counts.
				_ = os.Remove(l.marker)
				l.statDirty(t)
				r := l.call(call, args)
				l.noMarker(t, op)
				if !r.OK {
					t.Fatalf("%s with a populated submodule: %+v", op, r.Error)
				}
			})
		}
	}
}

// TestGitSubmoduleFlagBeatsConfig is two-sided, with the gate's argv and
// environment and a .gitmodules setting ignore = none for vendor/lib.
// Control: diff.ignoreSubmodules=all on its own loses to the submodule's
// ignore setting, and status and diff enter the submodule (the filter
// runs). Gated: --ignore-submodules=all on the command line wins over both,
// and neither enters it.
func TestGitSubmoduleFlagBeatsConfig(t *testing.T) {
	l := newGitlinkFixture(t, "read", true)
	ver := strings.TrimSpace(gatetest.Git(t, l.dir, "version"))
	for _, sub := range [][]string{
		{"status", "--porcelain=v2", "-z"},
		{"diff", "--no-color", "--no-ext-diff", "--no-textconv"},
	} {
		_ = os.Remove(l.marker)
		l.statDirty(t)
		runLikeGate(t, l.gitFixture, append([]string{"-c", "diff.ignoreSubmodules=all"}, sub...)...)
		if !exists(l.marker) {
			t.Fatalf("control (%s): git %s with only diff.ignoreSubmodules=all did not enter the submodule; the premise does not hold", ver, sub[0])
		}
		_ = os.Remove(l.marker)
		l.statDirty(t)
		runLikeGate(t, l.gitFixture, append(append([]string{"-c", "diff.ignoreSubmodules=all"}, sub...), "--ignore-submodules=all")...)
		l.noMarker(t, ver+": git "+sub[0]+" --ignore-submodules=all")
	}
	t.Logf("%s: submodule.<name>.ignore beats diff.ignoreSubmodules; --ignore-submodules=all beats both", ver)
}

type statusEntry struct {
	Kind string `json:"kind"`
	XY   string `json:"xy"`
	Path string `json:"path"`
}

func (l *gitlinkFixture) status(t *testing.T) []statusEntry {
	t.Helper()
	var st struct {
		Entries []statusEntry `json:"entries"`
	}
	l.ok("git_status", m{"repo": l.repo}, &st)
	return st.Entries
}

func (l *gitlinkFixture) diff(t *testing.T, staged bool) string {
	t.Helper()
	var d struct {
		Diff string `json:"diff"`
	}
	l.ok("git_diff", m{"repo": l.repo, "staged": staged}, &d)
	return d.Diff
}

// TestGitWithSubmodules: a repository with a submodule works for every
// git operation, minus the submodule's own state. The submodule's work
// tree (its own commits, edits and untracked files) is never shown or
// refused; a staged gitlink change, which is the repository's own index,
// still shows in git_status and git_diff --cached, and still refuses a pull
// and a discard; a pull still counts a gitlink it moves.
func TestGitWithSubmodules(t *testing.T) {
	l := newGitlinkFixture(t, "destructive", false)
	recorded := l.srcHead(t)
	// The submodule's own state: a new commit, an edit and an untracked
	// file, none of which the superproject records.
	gatetest.WriteFile(t, filepath.Join(l.lib, "more.txt"), "more\n", 0o644)
	gatetest.Git(t, l.lib, "add", "more.txt")
	gatetest.Git(t, l.lib, "-c", "filter.marker.clean=cat", "commit", "-q", "-m", "local lib commit")
	gatetest.WriteFile(t, filepath.Join(l.lib, "more.txt"), "edited\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(l.lib, "scratch.txt"), "x\n", 0o644)
	// And a change of the superproject's own.
	gatetest.WriteFile(t, filepath.Join(l.repo, "app.conf"), "port=9999\n", 0o644)
	_ = os.Remove(l.marker)

	if got := l.status(t); len(got) != 1 || got[0] != (statusEntry{"changed", ".M", "app.conf"}) {
		t.Fatalf("status with a submodule's own changes: %+v, want only app.conf", got)
	}
	if d := l.diff(t, false); !strings.Contains(d, "+port=9999") || strings.Contains(d, "Subproject commit") || strings.Contains(d, "vendor/lib") {
		t.Fatalf("work-tree diff shows the submodule's own state, or not app.conf: %q", d)
	}
	if d := l.diff(t, true); d != "" {
		t.Fatalf("staged diff with nothing staged: %q", d)
	}
	l.ok("git_log", m{"repo": l.repo}, nil)
	var pv discardPlan
	l.ok("git_discard_preview", m{"repo": l.repo, "include_untracked": true}, &pv)
	if pv.Entries != 1 || len(pv.First) != 1 || pv.First[0].Path != "app.conf" {
		t.Fatalf("discard preview with a submodule's own changes: %+v, want app.conf only", pv)
	}
	var res struct {
		Applied    bool  `json:"applied"`
		CleanAfter *bool `json:"clean_after"`
	}
	r := l.discard(&pv)
	if !r.OK {
		t.Fatalf("discard with a submodule's own changes: %+v", r.Error)
	}
	if err := json.Unmarshal(r.Data, &res); err != nil || !res.Applied || res.CleanAfter == nil || !*res.CleanAfter {
		t.Fatalf("discard result %s (%v), want applied and clean_after true", r.Data, err)
	}
	wantFile(t, filepath.Join(l.repo, "app.conf"), "port=8080\n")
	// The submodule is as it was.
	if h := strings.TrimSpace(gatetest.Git(t, l.lib, "rev-parse", "HEAD")); h == recorded {
		t.Fatal("the discard moved the submodule's HEAD back")
	}
	wantFile(t, filepath.Join(l.lib, "more.txt"), "edited\n")
	wantFile(t, filepath.Join(l.lib, "scratch.txt"), "x\n")

	// A pull with the submodule's own changes still in place; upstream
	// moves the gitlink and one file, and changed_files counts both.
	gatetest.Git(t, l.work, "update-index", "--cacheinfo", "160000,"+l.srcHeadAfter(t)+",vendor/lib")
	gatetest.Push(t, l.work, "upstream.txt", "from upstream\n", "move lib and add a file")
	var pull struct {
		Updated      bool `json:"updated"`
		ChangedFiles int  `json:"changed_files"`
	}
	l.ok("git_pull", m{"repo": l.repo}, &pull)
	if !pull.Updated || pull.ChangedFiles != 2 {
		t.Fatalf("pull %+v, want updated with 2 changed files (the gitlink and upstream.txt)", pull)
	}

	// A staged gitlink change: the repository's own index.
	staged := strings.TrimSpace(gatetest.Git(t, l.lib, "rev-parse", "HEAD~1"))
	gatetest.Git(t, l.repo, "update-index", "--cacheinfo", "160000,"+staged+",vendor/lib")
	if got := l.status(t); len(got) != 1 || got[0] != (statusEntry{"changed", "M.", "vendor/lib"}) {
		t.Fatalf("status with a staged gitlink change: %+v, want vendor/lib M.", got)
	}
	if d := l.diff(t, true); !strings.Contains(d, "-Subproject commit ") || !strings.Contains(d, "+Subproject commit "+staged) {
		t.Fatalf("staged diff does not show the staged gitlink change: %q", d)
	}
	if d := l.diff(t, false); strings.Contains(d, "Subproject commit") {
		t.Fatalf("work-tree diff shows the submodule: %q", d)
	}
	l.fail("git_pull", m{"repo": l.repo}, "policy_denied")
	l.fail("git_discard_preview", m{"repo": l.repo, "include_untracked": true}, "policy_denied")
	r = l.call("git_discard_preview", m{"repo": l.repo})
	if r.Error == nil || !strings.Contains(r.Error.Message, "vendor/lib") {
		t.Fatalf("discard preview refusal %+v, want it to name vendor/lib", r.Error)
	}
	if got := strings.TrimSpace(gatetest.Git(t, l.repo, "ls-files", "-s", "vendor/lib")); !strings.Contains(got, staged) {
		t.Fatalf("a refused discard changed the staged gitlink: %q", got)
	}
	l.noMarker(t, "an operation")
}

// srcHeadAfter is the submodule's own new commit (the one TestGitWithSubmodules made).
func (l *gitlinkFixture) srcHeadAfter(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(gatetest.Git(t, l.lib, "rev-parse", "HEAD"))
}

// gitSubcommand returns a recorded run's subcommand and its arguments: the
// gate's argv is -C <repo> --no-pager --no-optional-locks, -c pairs, then
// the subcommand.
func gitSubcommand(argv []string) (sub string, args []string) {
	i := 4
	for i+1 < len(argv) && argv[i] == "-c" {
		i += 2
	}
	if i >= len(argv) {
		return "", nil
	}
	return argv[i], argv[i+1:]
}

// readsWorkTree: a diff with --cached or --staged, or comparing two
// commits (two operands), reads no work tree; any other run of a command
// the table marks as reading it can.
func readsWorkTree(c *gitx.GitCommand, args []string) bool {
	if !c.WorkTree {
		return false
	}
	if c.TreeForms {
		operands := 0
		for _, a := range args {
			if a == "--cached" || a == "--staged" {
				return false
			}
			if !strings.HasPrefix(a, "-") {
				operands++
			}
		}
		return operands < 2
	}
	return true
}

// workTreeGaps returns every recorded run that gitx.GitCommands does not
// cover: a subcommand it does not list; a run that can read the work tree
// without the command's flag (or, for a command that takes none, without
// the reason); a status or diff without an explicit --ignore-submodules (so
// the configuration would decide); a tree-form diff with anything but
// =dirty or =none; a diff printing a patch without --submodule=short; and
// a run without one of the submodule -c values.
func workTreeGaps(table []gitx.GitCommand, keys []gitx.SubmoduleKey, runs [][]string) []string {
	var gaps []string
	var cvals []string
	for _, k := range keys {
		cvals = append(cvals, k.Args...)
	}
	for _, argv := range runs {
		sub, args := gitSubcommand(argv)
		i := slices.IndexFunc(table, func(c gitx.GitCommand) bool { return c.Name == sub })
		if i < 0 {
			gaps = append(gaps, "git "+sub+": not in gitx.GitCommands")
			continue
		}
		c := &table[i]
		has := func(a string) bool { return slices.Contains(args, a) }
		ignore := slices.IndexFunc(args, func(a string) bool { return strings.HasPrefix(a, "--ignore-submodules") })
		switch {
		case readsWorkTree(c, args) && c.Flag != "" && !has(c.Flag):
			gaps = append(gaps, "git "+sub+" "+strings.Join(args, " ")+": can read the work tree and lacks "+c.Flag)
		case readsWorkTree(c, args) && c.Flag == "" && c.Why == "":
			gaps = append(gaps, "git "+sub+": can read the work tree, takes no flag, and gitx.GitCommands gives no reason")
		case !c.WorkTree && c.Why == "":
			gaps = append(gaps, "git "+sub+": gitx.GitCommands says it reads no work tree without saying why")
		}
		if (sub == "status" || sub == "diff") && ignore < 0 {
			gaps = append(gaps, "git "+sub+" "+strings.Join(args, " ")+": no --ignore-submodules, so the configuration decides")
		}
		if c.TreeForms && !readsWorkTree(c, args) && ignore >= 0 && args[ignore] != "--ignore-submodules=dirty" && args[ignore] != "--ignore-submodules=none" {
			gaps = append(gaps, "git "+sub+" "+strings.Join(args, " ")+": reads no work tree but hides gitlink commit changes")
		}
		if sub == "diff" && !has("--name-only") && !has("--raw") && !has("--submodule=short") {
			gaps = append(gaps, "git diff "+strings.Join(args, " ")+": prints a patch without --submodule=short")
		}
		for _, v := range cvals {
			if !containsC(argv, v) {
				gaps = append(gaps, "git "+sub+": lacks -c "+v)
			}
		}
	}
	return gaps
}

// containsC reports whether argv carries -c v.
func containsC(argv []string, v string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "-c" && argv[i+1] == v {
			return true
		}
	}
	return false
}

// TestGitWorkTreeCommandsIgnoreSubmodules: every git process every git
// operation starts, in a repository with a populated submodule, a staged
// file and a pull to make, is one gitx.GitCommands lists and carries what
// keeps it out of submodules (see workTreeGaps). The gate's git is a
// recorder that logs each run and then executes the real git.
func TestGitWorkTreeCommandsIgnoreSubmodules(t *testing.T) {
	l := newGitlinkFixture(t, "destructive", true)
	logp := filepath.Join(l.dir, "git.log")
	l.opts.Git = gatetest.BuildGitRecorder(t, l.bin, logp, ops.GitPath)
	gatetest.Push(t, l.work, "upstream.txt", "from upstream\n", "upstream change")
	l.ok("git_pull", m{"repo": l.repo}, nil)
	smallChange(t, l.gitFixture)
	l.ok("git_status", m{"repo": l.repo}, nil)
	l.ok("git_log", m{"repo": l.repo}, nil)
	l.ok("git_diff", m{"repo": l.repo}, nil)
	l.ok("git_diff", m{"repo": l.repo, "staged": true}, nil)
	pv := l.preview(t, true)
	if r := l.discard(&pv); !r.OK {
		t.Fatalf("discard: %+v", r.Error)
	}
	var runs [][]string
	seen := map[string]bool{}
	for _, r := range recordedGits(t, logp) {
		runs = append(runs, r.argv)
		sub, args := gitSubcommand(r.argv)
		if sub == "diff" && slices.Contains(args, "--cached") {
			sub = "diff --cached"
		}
		seen[sub] = true
	}
	for _, want := range []string{"status", "diff", "diff --cached", "update-index", "pull", "clean", "checkout-index", "read-tree", "log"} {
		if !seen[want] {
			t.Fatalf("no recorded git %s: the recorder did not see every kind of run (%v)", want, seen)
		}
	}
	if gaps := workTreeGaps(gitx.GitCommands, gitx.SubmoduleKeys, runs); len(gaps) > 0 {
		t.Fatalf("git processes that could enter a submodule:\n%s", strings.Join(gaps, "\n"))
	}
	t.Logf("%d git processes, every one covered", len(runs))
}

// TestGitWorkTreeGapsFound: the check reports what it is for.
func TestGitWorkTreeGapsFound(t *testing.T) {
	var cvals []string
	for _, k := range gitx.SubmoduleKeys {
		cvals = append(cvals, k.Args...)
	}
	argv := func(sub ...string) []string {
		a := []string{"-C", "/srv/app/deploy", "--no-pager", "--no-optional-locks"}
		for _, v := range cvals {
			a = append(a, "-c", v)
		}
		return append(a, sub...)
	}
	good := [][]string{
		argv("status", "--porcelain=v2", "-z", "--ignore-submodules=all"),
		argv("diff", "--no-color", "--submodule=short", "--ignore-submodules=all"),
		argv("diff", "--cached", "--raw", "-z", "--ignore-submodules=dirty"),
		argv("diff", "--name-only", "-z", "--ignore-submodules=none", "aaaa", "bbbb"),
		argv("update-index", "-q", "--refresh", "--ignore-submodules"),
		argv("clean", "-n", "-d"),
		argv("log", "-n", "1"),
	}
	if g := workTreeGaps(gitx.GitCommands, gitx.SubmoduleKeys, good); len(g) != 0 {
		t.Fatalf("covered runs reported: %q", g)
	}
	for _, c := range []struct {
		run  []string
		want string
	}{
		{argv("status", "--porcelain=v2", "-z"), "lacks --ignore-submodules=all"},
		{argv("status", "--porcelain=v2", "-z", "--ignore-submodules=none"), "lacks --ignore-submodules=all"},
		{argv("diff", "--no-color", "--submodule=short"), "lacks --ignore-submodules=all"},
		{argv("diff", "--cached", "--raw"), "no --ignore-submodules"},
		{argv("diff", "--cached", "--raw", "--ignore-submodules=all"), "hides gitlink commit changes"},
		{argv("diff", "--cached", "--ignore-submodules=dirty"), "without --submodule=short"},
		{argv("update-index", "-q", "--refresh"), "lacks --ignore-submodules"},
		{argv("blame", "x"), "not in gitx.GitCommands"},
		{[]string{"-C", "/srv/app/deploy", "--no-pager", "--no-optional-locks", "log"}, "lacks -c"},
	} {
		if g := workTreeGaps(gitx.GitCommands, gitx.SubmoduleKeys, [][]string{c.run}); len(g) == 0 || !strings.Contains(strings.Join(g, "\n"), c.want) {
			t.Fatalf("run %q: gaps %q, want one saying %q", c.run[4+2*len(cvals):], g, c.want)
		}
	}
	noWhy := slices.Clone(gitx.GitCommands)
	for i := range noWhy {
		if noWhy[i].Name == "clean" {
			noWhy[i].Why = ""
		}
	}
	if g := workTreeGaps(noWhy, gitx.SubmoduleKeys, [][]string{argv("clean", "-n", "-d")}); len(g) != 1 || !strings.Contains(g[0], "gives no reason") {
		t.Fatalf("a command without a flag or a reason: gaps %q", g)
	}
}

// wantFile fails unless p holds exactly want.
func wantFile(t *testing.T, p, want string) {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own file
	if err != nil || string(b) != want {
		t.Fatalf("%s: %q %v, want %q", p, b, err, want)
	}
}
