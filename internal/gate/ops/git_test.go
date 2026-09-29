//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
	"github.com/tyler-rich/shell-mcp/internal/gate/procfs"
)

// Git tests run the real git binary (ops.GitPath, root-owned in the test
// images) as the gate does, against a local HTTPS smart-HTTP server
// (gatetest.GitServer). The server's CA reaches git only through the test
// constructor (Options.TestGitCAFile); production code never relaxes TLS.
// Repositories, names and URLs are invented.

const gitPolicy = `version: 1
max_tier: {TIER}
sandbox:
  landlock: best-effort
  system_read_exec: [{BIN}]
  tcp_connect_ports: [{PORT}]
limits:
  max_output_bytes: 65536
paths:
  read: [{R}]
  write: [{W}]
redact:
  patterns: ['api_key=\S+']
git:
  repos:
    - path: {W}/deploy
      remote: {REMOTE}
    - path: {R}/readonly
      remote: {REMOTE}
{EXTRA}commands:
  - id: probe-op
    path: {BIN}/probe
    tier: operator
    templates: [["write", "{path:write}"]]
`

type gitFixture struct {
	*fixture
	srv          *gatetest.GitServer
	repo, remote string
	work         string // the upstream seed working copy
}

func newGitFixture(t *testing.T, tier string) *gitFixture {
	t.Helper()
	f := newFixture(t, tier)
	g := &gitFixture{fixture: f, srv: gatetest.NewGitServer(t), repo: filepath.Join(f.write, "deploy")}
	g.remote = g.srv.RepoURL("deploy.git")
	g.work = g.srv.Seed(t, "deploy.git", map[string]string{"app.conf": "port=8080\n", ".gitignore": "*.log\n"})
	g.srv.Clone(t, "deploy.git", g.repo)
	g.srv.Clone(t, "deploy.git", filepath.Join(f.read, "readonly"))
	ca := filepath.Join(f.read, "tls", "git-ca.pem")
	g.srv.WriteCA(t, ca)
	f.opts.Git = ops.GitPath
	f.opts.TestGitCAFile = ca
	g.policy(tier, "")
	return g
}

// policy writes gitPolicy; extra lists more repos ({R}, {W} and {REMOTE}
// are expanded in it too).
func (g *gitFixture) policy(tier, extra string) {
	y := strings.Replace(gitPolicy, "{EXTRA}", extra, 1)
	g.rawPolicy(strings.NewReplacer("{TIER}", tier, "{PORT}", g.srv.Port(), "{REMOTE}", g.remote).Replace(y))
}

func (g *gitFixture) head(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(gatetest.Git(t, g.repo, "rev-parse", "HEAD"))
}

func TestGitStatusLogDiff(t *testing.T) {
	g := newGitFixture(t, "read")
	var st struct {
		Branch   string `json:"branch"`
		Upstream string `json:"upstream"`
		Ahead    int    `json:"ahead"`
		Behind   int    `json:"behind"`
		Entries  []struct {
			Kind string `json:"kind"`
			XY   string `json:"xy"`
			Path string `json:"path"`
		} `json:"entries"`
	}
	g.ok("git_status", m{"repo": g.repo}, &st)
	if st.Branch != "main" || st.Upstream != "origin/main" || st.Ahead != 0 || len(st.Entries) != 0 {
		t.Fatalf("clean status %+v", st)
	}
	gatetest.Git(t, g.repo, "commit", "-q", "--allow-empty", "-m", "local")
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "port=9090\napi_key=hunter2\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "new file.txt"), "x", 0o644)
	g.ok("git_status", m{"repo": g.repo}, &st)
	if st.Ahead != 1 || len(st.Entries) != 2 || st.Entries[0].Kind != "changed" || st.Entries[0].Path != "app.conf" ||
		st.Entries[1].Kind != "untracked" || st.Entries[1].Path != "new file.txt" {
		t.Fatalf("dirty status %+v", st)
	}
	var diff struct {
		Diff      string `json:"diff"`
		Truncated bool   `json:"truncated"`
	}
	g.ok("git_diff", m{"repo": g.repo}, &diff)
	if !strings.Contains(diff.Diff, "+port=9090") || strings.Contains(diff.Diff, "hunter2") {
		t.Fatalf("diff %q", diff.Diff)
	}
	g.ok("git_diff", m{"repo": g.repo, "staged": true}, &diff)
	if diff.Diff != "" {
		t.Fatalf("staged diff %q", diff.Diff)
	}
	g.ok("git_diff", m{"repo": g.repo, "max_output_bytes": 10}, &diff)
	if !diff.Truncated || len(diff.Diff) > 10 {
		t.Fatalf("capped diff %+v", diff)
	}
	var lg struct {
		Commits []struct {
			Hash    string `json:"hash"`
			Author  string `json:"author"`
			Date    string `json:"date"`
			Subject string `json:"subject"`
		} `json:"commits"`
	}
	g.ok("git_log", m{"repo": g.repo, "limit": 1}, &lg)
	if len(lg.Commits) != 1 || lg.Commits[0].Subject != "local" || len(lg.Commits[0].Hash) != 40 || lg.Commits[0].Author != "Example" || lg.Commits[0].Date == "" {
		t.Fatalf("log %+v", lg)
	}
	g.ok("git_log", m{"repo": g.repo}, &lg)
	if len(lg.Commits) != 2 {
		t.Fatalf("log default %+v", lg)
	}
	g.fail("git_log", m{"repo": g.repo, "limit": 201}, "bad_request")
	g.fail("git_status", m{"repo": g.repo + "/"}, "bad_request")
	g.fail("git_status", m{"repo": filepath.Join(g.write, "other")}, "policy_denied")
	g.fail("git_status", m{}, "bad_request")
	g.ok("git_status", m{"repo": filepath.Join(g.read, "readonly")}, nil)
}

// TestGitEnvironment: the exact argv prefix and environment the gate gives
// git (POLICY §7), observed by a stand-in binary: the hardening flags, the
// repository pinned with GIT_DIR/GIT_WORK_TREE, no system or global config,
// and no other GIT_CONFIG_* variable.
func TestGitEnvironment(t *testing.T) {
	g := newGitFixture(t, "read")
	logp := filepath.Join(g.dir, "fakegit.log")
	g.opts.Git = gatetest.BuildFakeSys(t, g.bin, "git", logp)
	g.opts.TestGitCAFile = ""
	g.fail("git_status", m{"repo": g.repo}, "exec_failed")
	b, err := os.ReadFile(logp) //nolint:gosec // G304: the test's own log
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var argv, env []string
	if len(lines) != 2 || json.Unmarshal([]byte(lines[0]), &argv) != nil || json.Unmarshal([]byte(lines[1]), &env) != nil {
		t.Fatalf("log %q", b)
	}
	want := []string{"-C", g.repo, "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
		"-c", "core.pager=cat", "-c", "core.sshCommand=/bin/false", "-c", "credential.helper=", "-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never", "-c", "safe.directory=" + g.repo, "-c", "maintenance.auto=false", "-c", "gc.auto=0",
		"-c", "gc.autoDetach=false", "-c", "core.ignorecase=false", "config", "--local", "--no-includes", "--list", "-z"}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv\n got %q\nwant %q", argv, want)
	}
	wantEnv := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_DIR=" + g.repo + "/.git", "GIT_TERMINAL_PROMPT=0",
		"GIT_WORK_TREE=" + g.repo, "HOME=" + g.home, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "NO_COLOR=1", "PAGER=cat",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=", "TERM=dumb"}
	if !slices.Equal(env, wantEnv) {
		t.Fatalf("env\n got %q\nwant %q", env, wantEnv)
	}
}

// TestGitRepoPinning: <repo>/.git must be a real directory inside the
// root: a gitfile, a symlink or a commondir redirect is refused.
func TestGitRepoPinning(t *testing.T) {
	g := newGitFixture(t, "read")
	g.policy("read", "    - path: {R}/gitfile\n      remote: {REMOTE}\n    - path: {R}/linked\n      remote: {REMOTE}\n"+
		"    - path: {R}/common\n      remote: {REMOTE}\n    - path: {R}/nogit\n      remote: {REMOTE}\n")
	for _, d := range []string{"gitfile", "linked", "common", "nogit"} {
		gatetest.Mkdir(t, filepath.Join(g.read, d), 0o755)
	}
	gatetest.WriteFile(t, filepath.Join(g.read, "gitfile", ".git"), "gitdir: "+filepath.Join(g.read, "readonly", ".git")+"\n", 0o644)
	if err := os.Symlink(filepath.Join(g.read, "readonly", ".git"), filepath.Join(g.read, "linked", ".git")); err != nil {
		t.Fatal(err)
	}
	gatetest.Git(t, filepath.Join(g.read, "common"), "init", "-q")
	gatetest.WriteFile(t, filepath.Join(g.read, "common", ".git", "commondir"), filepath.Join(g.read, "readonly", ".git")+"\n", 0o644)
	g.fail("git_status", m{"repo": filepath.Join(g.read, "gitfile")}, "policy_denied")
	g.fail("git_status", m{"repo": filepath.Join(g.read, "linked")}, "policy_denied")
	g.fail("git_status", m{"repo": filepath.Join(g.read, "common")}, "policy_denied")
	g.fail("git_status", m{"repo": filepath.Join(g.read, "nogit")}, "not_found")
}

// runLikeGate runs git exactly as the gate would, but without the gate's
// repository-config check: the control half of the two-sided tests.
func runLikeGate(t *testing.T, g *gitFixture, sub ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), ops.GitPath, ops.GitArgs(g.repo, g.opts.TestGitCAFile, sub...)...) //nolint:gosec // G204: the gate's own argv, fixed git
	cmd.Env = ops.GitEnv(g.home, g.repo)
	_, _ = cmd.CombinedOutput()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// TestGitConfigAllowlist is two-sided. Control: with a textconv or clean
// filter driver in .git/config, git run with the gate's own argv and
// environment executes it (a marker file appears). Gated: the op refuses
// with policy_denied naming the key, and the marker does not appear.
func TestGitConfigAllowlist(t *testing.T) {
	g := newGitFixture(t, "read")
	marker := filepath.Join(g.dir, "MARKER")
	gatetest.WriteFile(t, filepath.Join(g.repo, ".gitattributes"), "*.conf diff=x filter=x\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "port=9090\n", 0o644)
	cases := []struct{ key, value, op, control string }{
		{"diff.x.textconv", "touch " + marker + "; cat", "git_diff", "diff"},
		{"filter.x.clean", "touch " + marker + "; cat", "git_diff", "diff --no-ext-diff --no-textconv"},
	}
	for _, c := range cases {
		gatetest.Git(t, g.repo, "config", c.key, c.value)
		runLikeGate(t, g, strings.Fields(c.control)...)
		if !exists(marker) {
			t.Fatalf("control: git did not run %s; the refusal below would prove nothing", c.key)
		}
		_ = os.Remove(marker)
		r := g.call(c.op, m{"repo": g.repo})
		if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, c.key) {
			t.Fatalf("%s: %+v", c.key, r.Error)
		}
		if exists(marker) {
			t.Fatalf("%s ran under the gate", c.key)
		}
		gatetest.Git(t, g.repo, "config", "--unset", c.key)
	}
	// Other exec-capable, including or redirecting keys are outside the
	// allowlist too.
	for _, kv := range [][2]string{{"include.path", "/dev/null"}, {"includeIf.gitdir:/.path", "/dev/null"}, {"core.askPass", "/bin/false"},
		{"remote.upstream.url", g.remote}, {"extensions.worktreeConfig", "true"}} {
		gatetest.Git(t, g.repo, "config", kv[0], kv[1])
		r := g.call("git_status", m{"repo": g.repo})
		if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, strings.ToLower(strings.SplitN(kv[0], ".", 2)[0])) {
			t.Fatalf("%s: %+v", kv[0], r.Error)
		}
		gatetest.Git(t, g.repo, "config", "--unset", kv[0])
	}
	g.ok("git_status", m{"repo": g.repo}, nil)
}

// dataKeys are repository-local keys git uses only as data for the gate's
// fixed commands (POLICY §7), with values that would matter if the gate's
// own flags did not override them: an interactive rebase, a non-ff merge,
// forced colors.
var dataKeys = [][2]string{
	{"user.name", "Example Dev"}, {"user.email", "dev@example.test"}, {"core.autocrlf", "input"}, {"core.eol", "lf"},
	{"core.safecrlf", "warn"}, {"core.ignorecase", "false"}, {"pull.rebase", "interactive"}, {"pull.ff", "false"},
	{"init.defaultBranch", "trunk"}, {"branch.main.rebase", "interactive"}, {"fetch.prune", "true"},
	{"remote.origin.prune", "true"}, {"remote.origin.tagOpt", "--no-tags"}, {"color.ui", "always"},
	{"color.status", "always"}, {"color.diff", "always"}, {"color.branch", "always"}, {"color.pager", "true"},
	{"color.diff.meta", "blue bold"}, {"advice.detachedHead", "false"}, {"advice.statusHints", "false"}, {"gc.auto", "0"},
}

// TestGitDataKeysAllowed: a repository carrying every data-only key still
// works with every git op, including a pull and a discard, and the
// output still parses (forced colors do not leak into what the gate reads).
func TestGitDataKeysAllowed(t *testing.T) {
	g := newGitFixture(t, "destructive")
	for _, kv := range dataKeys {
		gatetest.Git(t, g.repo, "config", kv[0], kv[1])
	}
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "port=9090\n", 0o644)
	var st struct {
		Branch  string `json:"branch"`
		Entries []struct {
			Path string `json:"path"`
		} `json:"entries"`
	}
	g.ok("git_status", m{"repo": g.repo}, &st)
	if st.Branch != "main" || len(st.Entries) != 1 || st.Entries[0].Path != "app.conf" {
		t.Fatalf("status %+v", st)
	}
	var diff struct {
		Diff string `json:"diff"`
	}
	g.ok("git_diff", m{"repo": g.repo}, &diff)
	if !strings.Contains(diff.Diff, "+port=9090") || strings.Contains(diff.Diff, "\x1b[") {
		t.Fatalf("diff %q", diff.Diff)
	}
	g.ok("git_log", m{"repo": g.repo}, nil)
	var pv struct {
		Reset []string `json:"reset"`
	}
	g.ok("git_discard_preview", m{"repo": g.repo}, &pv)
	if !slices.Equal(pv.Reset, []string{"app.conf"}) {
		t.Fatalf("preview %+v", pv)
	}
	g.ok("git_discard", m{"repo": g.repo}, nil)
	gatetest.Push(t, g.work, "extra.conf", "x\n", "upstream change")
	var d pullData
	g.ok("git_pull", m{"repo": g.repo}, &d)
	if !d.Updated || d.ChangedFiles != 1 || d.NewHead != g.head(t) {
		t.Fatalf("pull with pull.rebase=interactive and pull.ff=false in the repo config: %+v", d)
	}
}

// TestGitLFSRefusedActionably: a Git LFS repository (filter.lfs.*) is
// refused with a message that names the key, says how to remove it and
// that LFS is not supported; any other key outside the list still is.
func TestGitLFSRefusedActionably(t *testing.T) {
	g := newGitFixture(t, "read")
	for _, kv := range [][2]string{{"filter.lfs.clean", "git-lfs clean -- %f"}, {"filter.lfs.smudge", "git-lfs smudge -- %f"},
		{"filter.lfs.process", "git-lfs filter-process"}, {"filter.lfs.required", "true"}} {
		gatetest.Git(t, g.repo, "config", kv[0], kv[1])
	}
	r := g.call("git_status", m{"repo": g.repo})
	if r.OK || r.Error.Code != "policy_denied" {
		t.Fatalf("LFS repo: %+v", r.Error)
	}
	for _, want := range []string{"filter.lfs.clean", "git config --remove-section filter.lfs", "Git LFS", "not supported"} {
		if !strings.Contains(r.Error.Message, want) {
			t.Errorf("message %q lacks %q", r.Error.Message, want)
		}
	}
	gatetest.Git(t, g.repo, "config", "--remove-section", "filter.lfs")
	g.ok("git_status", m{"repo": g.repo}, nil)
	gatetest.Git(t, g.repo, "config", "core.editor", "vi")
	r = g.call("git_status", m{"repo": g.repo})
	if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, "git config --unset-all core.editor") {
		t.Fatalf("core.editor: %+v", r.Error)
	}
}

// maintenanceFlags are the POLICY §7 flags that keep git from starting
// (detached) maintenance and pin case sensitivity.
var maintenanceFlags = []string{"maintenance.auto=false", "gc.auto=0", "gc.autoDetach=false", "core.ignorecase=false"}

// withGitDefaults returns the gate's argv without maintenanceFlags: git's
// defaults for maintenance and whatever core.ignorecase the repo sets.
func withGitDefaults(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" && i+1 < len(args) && slices.Contains(maintenanceFlags, args[i+1]) {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// runGit runs git with argv and the gate's environment and returns stdout.
func runGit(t *testing.T, g *gitFixture, argv []string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), ops.GitPath, argv...) //nolint:gosec // G204: the gate's own argv, fixed git
	cmd.Env = ops.GitEnv(g.home, g.repo)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", argv, err)
	}
	return string(out)
}

// orphanGits lists git processes, alive or zombie, whose parent is this
// test process. With PR_SET_CHILD_SUBREAPER set, a daemonized descendant
// (fork, parent exits, setsid) is reparented here instead of to init, and
// stays visible as a zombie until reaped: Go reaps only its own children.
func orphanGits(t *testing.T) []int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat") //nolint:gosec // G304: a numeric /proc entry
		if err != nil {
			continue
		}
		st, err := procfs.ParsePIDStat(b)
		if err == nil && st.PPID == os.Getpid() && st.Comm == "git" {
			pids = append(pids, pid)
		}
	}
	return pids
}

// reap kills and reaps the given orphans.
func reap(pids []int) {
	for _, p := range pids {
		_ = unix.Kill(p, unix.SIGKILL)
		var ws unix.WaitStatus
		_, _ = unix.Wait4(p, &ws, 0, nil)
	}
}

// TestGitPullLeavesNoDetachedProcess is two-sided. Control: a pull run with
// the gate's argv minus the maintenance flags (git's defaults) leaves a
// daemonized `git maintenance` process behind, outside the caller's
// process group. Gated: after git_pull responds, no git process remains.
func TestGitPullLeavesNoDetachedProcess(t *testing.T) {
	g := newGitFixture(t, "operator")
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) }()
	reap(orphanGits(t))

	gatetest.Push(t, g.work, "one.conf", "1\n", "one")
	runGit(t, g, withGitDefaults(ops.GitArgs(g.repo, g.opts.TestGitCAFile, "pull", "--ff-only", "--no-rebase", "--no-recurse-submodules")))
	var orphans []int
	for deadline := time.Now().Add(3 * time.Second); len(orphans) == 0 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		orphans = orphanGits(t)
	}
	reap(orphans)
	if len(orphans) == 0 {
		t.Fatal("control: git's defaults left no detached process after a pull; the gated check below would prove nothing")
	}
	t.Logf("control: %d detached git process(es) outlived the pull", len(orphans))

	gatetest.Push(t, g.work, "two.conf", "2\n", "two")
	var d pullData
	g.ok("git_pull", m{"repo": g.repo}, &d)
	if !d.Updated {
		t.Fatalf("pull %+v", d)
	}
	time.Sleep(500 * time.Millisecond)
	if left := orphanGits(t); len(left) > 0 {
		reap(left)
		t.Fatalf("git_pull left %d git process(es) running after the response", len(left))
	}
}

// TestGitIgnoreCasePinned is two-sided. Control: with core.ignorecase=true
// in the repo's config, git hides an untracked APP.CONF next to the
// tracked app.conf. Gated: git_status lists it and git_discard_preview
// would remove it — the repository is treated as case-sensitive.
func TestGitIgnoreCasePinned(t *testing.T) {
	g := newGitFixture(t, "read")
	gatetest.Git(t, g.repo, "config", "core.ignorecase", "true")
	gatetest.WriteFile(t, filepath.Join(g.repo, "APP.CONF"), "x\n", 0o644)
	if out := runGit(t, g, withGitDefaults(ops.GitArgs(g.repo, "", "status", "--porcelain=v2", "-z"))); strings.Contains(out, "APP.CONF") {
		t.Fatalf("control: git with core.ignorecase=true listed APP.CONF (%q); the check below would prove nothing", out)
	}
	var st struct {
		Entries []struct {
			Kind string `json:"kind"`
			Path string `json:"path"`
		} `json:"entries"`
	}
	g.ok("git_status", m{"repo": g.repo}, &st)
	if len(st.Entries) != 1 || st.Entries[0].Kind != "untracked" || st.Entries[0].Path != "APP.CONF" {
		t.Fatalf("status under the gate %+v", st)
	}
	var pv struct {
		Remove []string `json:"remove"`
	}
	g.ok("git_discard_preview", m{"repo": g.repo}, &pv)
	if !slices.Equal(pv.Remove, []string{"APP.CONF"}) {
		t.Fatalf("preview %+v", pv)
	}
}

type pullData struct {
	OldHead      string `json:"old_head"`
	NewHead      string `json:"new_head"`
	ChangedFiles int    `json:"changed_files"`
	Updated      bool   `json:"updated"`
}

func TestGitPull(t *testing.T) {
	g := newGitFixture(t, "operator")
	old := g.head(t)
	var d pullData
	g.ok("git_pull", m{"repo": g.repo}, &d)
	if d.Updated || d.OldHead != old || d.NewHead != old || d.ChangedFiles != 0 {
		t.Fatalf("up to date %+v", d)
	}
	gatetest.Push(t, g.work, "app.conf", "port=8081\n", "bump port")
	gatetest.Push(t, g.work, "extra.conf", "x\n", "add extra")
	g.ok("git_pull", m{"repo": g.repo}, &d)
	if !d.Updated || d.OldHead != old || d.NewHead == old || d.NewHead != g.head(t) || d.ChangedFiles != 2 {
		t.Fatalf("pull %+v", d)
	}
	// Dirty tree.
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "local edit\n", 0o644)
	gatetest.Push(t, g.work, "b.conf", "b\n", "more")
	r := g.call("git_pull", m{"repo": g.repo})
	if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, "uncommitted") {
		t.Fatalf("dirty: %+v", r.Error)
	}
	gatetest.Git(t, g.repo, "checkout", "--", "app.conf")
	// Not a fast-forward: a local commit and an upstream commit diverge.
	gatetest.Git(t, g.repo, "commit", "-q", "--allow-empty", "-m", "local divergence")
	before := g.head(t)
	r = g.call("git_pull", m{"repo": g.repo})
	if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, "fast-forward") {
		t.Fatalf("non-ff: %+v", r.Error)
	}
	if g.head(t) != before {
		t.Fatal("non-ff pull moved HEAD")
	}
	gatetest.Git(t, g.repo, "reset", "-q", "--hard", "origin/main")
	// A remote other than the policy's.
	gatetest.Git(t, g.repo, "remote", "set-url", "origin", g.srv.RepoURL("other.git"))
	r = g.call("git_pull", m{"repo": g.repo})
	if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, "remote") {
		t.Fatalf("foreign remote: %+v", r.Error)
	}
	gatetest.Git(t, g.repo, "remote", "set-url", "origin", g.remote)
	// Only repos inside a write root can be pulled; only at operator tier.
	g.fail("git_pull", m{"repo": filepath.Join(g.read, "readonly")}, "policy_denied")
	g.policy("read", "")
	g.fail("git_pull", m{"repo": g.repo}, "tier_denied")
}

// TestGitPullInsteadOf is two-sided. Control: with url.<B>.insteadOf=<A>
// in .git/config, a pull run with the gate's argv lands commits from
// server B while remote.origin.url still names A. Gated: git_pull refuses
// with policy_denied naming the key.
func TestGitPullInsteadOf(t *testing.T) {
	g := newGitFixture(t, "operator")
	b := gatetest.NewGitServer(t)
	bwork := b.Seed(t, "deploy.git", map[string]string{"app.conf": "port=8080\n", ".gitignore": "*.log\n"})
	// B's history is unrelated to A's; start the clone from B's history so
	// that a redirected pull is a fast-forward.
	gatetest.Git(t, g.repo, "fetch", "-q", filepath.Join(b.Root, "deploy.git"), "main")
	gatetest.Git(t, g.repo, "reset", "-q", "--hard", "FETCH_HEAD")
	gatetest.Push(t, bwork, "evil.conf", "from B\n", "from server B")
	gatetest.Git(t, g.repo, "config", "url."+b.URL()+"/.insteadOf", g.srv.URL()+"/")

	r := g.call("git_pull", m{"repo": g.repo})
	if r.OK || r.Error.Code != "policy_denied" || !strings.Contains(r.Error.Message, "insteadof") {
		t.Fatalf("gated: %+v", r.Error)
	}
	if exists(filepath.Join(g.repo, "evil.conf")) {
		t.Fatal("the gated pull reached server B")
	}
	runLikeGate(t, g, "pull", "--ff-only", "--no-rebase", "--no-recurse-submodules")
	if !exists(filepath.Join(g.repo, "evil.conf")) {
		t.Fatal("control: insteadOf did not redirect the pull; the refusal proves nothing")
	}
}

// TestGitDirWriteDenied: fsx refuses writes to any path with a .git
// component (POLICY §3); the same writes elsewhere in the write root work.
func TestGitDirWriteDenied(t *testing.T) {
	g := newGitFixture(t, "destructive")
	cfg := filepath.Join(g.repo, ".git", "config")
	b64 := "W2NvcmVdCg==" // "[core]\n"
	g.ok("write_file", m{"path": filepath.Join(g.repo, "NOTES.md"), "content_b64": b64}, nil)
	g.fail("write_file", m{"path": cfg, "content_b64": b64}, "path_denied")
	g.fail("write_file", m{"path": filepath.Join(g.repo, ".git", "hooks", "post-merge"), "content_b64": b64}, "path_denied")
	g.fail("mkdir", m{"path": filepath.Join(g.repo, "sub", ".git"), "parents": true}, "path_denied")
	g.fail("copy", m{"source": filepath.Join(g.repo, "NOTES.md"), "destination": filepath.Join(g.repo, ".git", "info", "attributes")}, "path_denied")
	g.fail("move", m{"source": filepath.Join(g.repo, "NOTES.md"), "destination": filepath.Join(g.repo, ".git", "x")}, "path_denied")
	g.fail("chmod", m{"path": cfg, "mode": "0644"}, "path_denied")
	g.fail("delete", m{"path": cfg}, "path_denied")
	g.fail("delete", m{"path": g.repo, "recursive": true}, "path_denied")
	g.fail("exec", m{"command_id": "probe-op", "args": []string{"write", cfg}}, "path_denied")
	g.ok("read_file", m{"path": cfg}, nil)
}

func TestGitDiscard(t *testing.T) {
	g := newGitFixture(t, "destructive")
	gatetest.WriteFile(t, filepath.Join(g.repo, "app.conf"), "changed\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "staged.conf"), "s\n", 0o644)
	gatetest.Git(t, g.repo, "add", "staged.conf")
	gatetest.WriteFile(t, filepath.Join(g.repo, "untracked.txt"), "u\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "newdir", "f.txt"), "n\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "keep.log"), "ignored\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.repo, "spécial file.txt"), "q\n", 0o644)
	var pv struct {
		Reset  []string `json:"reset"`
		Remove []string `json:"remove"`
	}
	g.ok("git_discard_preview", m{"repo": g.repo}, &pv)
	if !slices.Equal(pv.Reset, []string{"app.conf", "staged.conf"}) ||
		!slices.Equal(pv.Remove, []string{"newdir/", "spécial file.txt", "untracked.txt"}) {
		t.Fatalf("preview %+v", pv)
	}
	var d struct {
		Reset  []string `json:"reset"`
		Remove []string `json:"remove"`
		Clean  bool     `json:"clean_after"`
	}
	g.ok("git_discard", m{"repo": g.repo}, &d)
	if !slices.Equal(d.Reset, pv.Reset) || !slices.Equal(d.Remove, pv.Remove) || !d.Clean {
		t.Fatalf("discard %+v", d)
	}
	if st := gatetest.Git(t, g.repo, "status", "--porcelain"); st != "" {
		t.Fatalf("tree not clean: %q", st)
	}
	if !exists(filepath.Join(g.repo, "keep.log")) {
		t.Fatal("an ignored file was removed")
	}
	g.fail("git_discard", m{"repo": filepath.Join(g.read, "readonly")}, "policy_denied")
	g.ok("git_discard_preview", m{"repo": filepath.Join(g.read, "readonly")}, nil)
	g.policy("operator", "")
	g.fail("git_discard", m{"repo": g.repo}, "tier_denied")
	g.ok("git_discard_preview", m{"repo": g.repo}, nil)
}
