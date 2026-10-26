//go:build linux

package ops_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
)

// The child memory limit (handoff N-30, N-25's memory half): every process
// the gate starts, declared commands, git and systemctl/journalctl alike,
// runs with RLIMIT_DATA at limits.max_memory_mb, soft and hard. Fixtures
// are invented and sparse (they take no disk space).

// memMB is the tests' limit: above what the Go probe and git need here,
// far below the host's memory.
const memMB = 192

// memData is the probe's "rlimits" line for memMB.
var memData = fmt.Sprintf("data=%d/%d", memMB<<20, memMB<<20)

// memPolicy is basePolicy with limits.max_memory_mb set and a command that
// reports, raises and tests the limit.
func (f *fixture) memPolicy(tier string) {
	f.t.Helper()
	y := strings.NewReplacer("{TIER}", tier, "{PRIV}", "", "  max_stdin_bytes: 16\n", fmt.Sprintf("  max_stdin_bytes: 16\n  max_memory_mb: %d\n", memMB)).Replace(basePolicy)
	y += "  - id: probe-mem\n    path: {BIN}/probe\n    tier: read\n" +
		"    templates: [[\"rlimits\"], [\"child-rlimits\"], [\"raise-data\"], [\"alloc\", \"{int:1-4096}\"]]\n"
	f.rawPolicy(y)
}

type memExec struct {
	ExitCode *int    `json:"exit_code"`
	Signal   *string `json:"signal"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
}

// TestExecMemoryLimit: a declared command runs with the policy's limit,
// cannot raise it, passes it on, and an allocation past it fails quickly
// and is reported as the command's own exit status (ok, with stderr).
func TestExecMemoryLimit(t *testing.T) {
	f := newFixture(t, "read")
	f.memPolicy("read")
	var d memExec
	f.ok("exec", m{"command_id": "probe-mem", "args": []string{"rlimits"}}, &d)
	if !strings.Contains(d.Stdout, memData) {
		t.Fatalf("rlimits %q, want %s", d.Stdout, memData)
	}
	f.ok("exec", m{"command_id": "probe-mem", "args": []string{"child-rlimits"}}, &d)
	if !strings.Contains(d.Stdout, memData) {
		t.Fatalf("the command's child: %q, want %s", d.Stdout, memData)
	}
	if os.Getuid() != 0 {
		f.ok("exec", m{"command_id": "probe-mem", "args": []string{"raise-data"}}, &d)
		if strings.TrimSpace(d.Stdout) != "raise=EPERM unlimited=EPERM" {
			t.Fatalf("raise-data %q", d.Stdout)
		}
	}
	start := time.Now()
	f.ok("exec", m{"command_id": "probe-mem", "args": []string{"alloc", "2048"}}, &d)
	if d.ExitCode == nil || *d.ExitCode == 0 || strings.Contains(d.Stdout, "allocated") || !goOOM(d.Stderr) {
		t.Fatalf("2048 MiB under %d MiB: %+v", memMB, d)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %v", el)
	}
	f.ok("exec", m{"command_id": "probe-mem", "args": []string{"alloc", "16"}}, &d)
	if d.ExitCode == nil || *d.ExitCode != 0 {
		t.Fatalf("16 MiB under %d MiB: %+v", memMB, d)
	}
}

// TestServicesMemoryLimit: systemctl and journalctl get the limit too.
func TestServicesMemoryLimit(t *testing.T) {
	f := newFixture(t, "read")
	f.fakeSystemd(t, "read")
	f.rawPolicy(strings.NewReplacer("{TIER}", "read", "  max_output_bytes: 65536\n", fmt.Sprintf("  max_output_bytes: 65536\n  max_memory_mb: %d\n", memMB)).Replace(servicesPolicy))
	f.ok("service_status", m{"unit": "example-app.service"}, nil)
	f.ok("journal", m{"unit": "example-app.service", "lines": 5}, nil)
	lines := limitLines(t, filepath.Join(f.dir, "fakesys.log.limits"))
	if len(lines) < 2 {
		t.Fatalf("limits log %q: want a line per systemctl and journalctl run", lines)
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, " "+memData) {
			t.Fatalf("%q, want %s", l, memData)
		}
	}
}

// limitLines reads a fakesys limits log.
func limitLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own log
	if err != nil {
		t.Fatalf("limits log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// gitMemPolicy writes gitPolicy with limits.max_memory_mb.
func (g *gitFixture) gitMemPolicy(tier string, mb int) {
	g.t.Helper()
	y := strings.Replace(gitPolicy, "  max_output_bytes: 65536\n", fmt.Sprintf("  max_output_bytes: 65536\n  max_memory_mb: %d\n", mb), 1)
	y = strings.Replace(y, "{EXTRA}", "", 1)
	g.rawPolicy(strings.NewReplacer("{TIER}", tier, "{PORT}", g.srv.Port(), "{REMOTE}", g.remote).Replace(y))
}

// TestGitEveryProcessMemoryLimit: every git process of every git operation
// (seven for a pull, more for a discard) starts with the limit.
func TestGitEveryProcessMemoryLimit(t *testing.T) {
	g := newGitFixture(t, "destructive")
	g.gitMemPolicy("destructive", memMB)
	logp := filepath.Join(g.dir, "git.log")
	g.opts.Git = gatetest.BuildGitRecorder(t, g.bin, logp, ops.GitPath)
	gatetest.Push(t, g.work, "upstream.txt", "from upstream\n", "upstream change")
	g.ok("git_pull", m{"repo": g.repo}, nil)
	smallChange(t, g)
	for _, op := range []string{"git_status", "git_log", "git_diff"} {
		g.ok(op, m{"repo": g.repo}, nil)
	}
	var pv discardPlan
	g.ok("git_discard_preview", m{"repo": g.repo, "include_untracked": true}, &pv)
	g.ok("git_discard", m{"repo": g.repo, "include_untracked": true, "expected_preview_sha256": pv.PreviewSHA256}, nil)
	lines := limitLines(t, logp+".limits")
	if len(lines) != len(recordedGits(t, logp)) || len(lines) < 15 {
		t.Fatalf("%d limit lines for %d git runs", len(lines), len(recordedGits(t, logp)))
	}
	for i, l := range lines {
		if l != "git "+memData {
			t.Fatalf("git run %d: %q, want git %s", i, l, memData)
		}
	}
}

// TestGitGitlinkSparseRef (N-25's memory half): a populated gitlink whose
// HEAD names a large sparse loose ref makes git read the whole ref into
// memory while it compares the gitlink (ce_compare_gitlink, before
// --ignore-submodules applies). Under the limit git fails within a second,
// and the gate reports exec_failed naming the limit; without it, git
// allocates the file's size.
func TestGitGitlinkSparseRef(t *testing.T) {
	l := newGitlinkFixture(t, "read", false)
	const mb = 128
	l.gitMemPolicy("read", mb)
	gitdir := filepath.Join(l.lib, ".git")
	gatetest.WriteFile(t, filepath.Join(gitdir, "HEAD"), "ref: refs/heads/x\n", 0o644)
	ref := filepath.Join(gitdir, "refs", "heads", "x")
	gatetest.WriteFile(t, ref, "", 0o644)
	if err := os.Truncate(ref, 512<<20); err != nil {
		t.Fatal(err)
	}
	// The gitlink's stat data no longer matches the index, so git
	// compares its HEAD.
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(l.lib, old, old); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := l.call("git_status", m{"repo": l.repo})
	if r.OK || r.Error == nil || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, fmt.Sprintf("limits.max_memory_mb (%d MiB)", mb)) {
		t.Fatalf("git_status with a 512 MiB sparse ref under %d MiB: %+v %s", mb, r.Error, r.Data)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %v", el)
	}
}

// TestPolicySummaryMaxMemory: the policy op reports the effective limit.
func TestPolicySummaryMaxMemory(t *testing.T) {
	f := newFixture(t, "read")
	var s struct {
		Limits struct {
			MaxMemoryMB int `json:"MaxMemoryMB"`
		} `json:"limits"`
	}
	f.ok("policy", m{}, &s)
	if s.Limits.MaxMemoryMB != 1024 {
		t.Fatalf("default max_memory_mb %d, want 1024", s.Limits.MaxMemoryMB)
	}
	f.memPolicy("read")
	f.ok("policy", m{}, &s)
	if s.Limits.MaxMemoryMB != memMB {
		t.Fatalf("max_memory_mb %d, want %d", s.Limits.MaxMemoryMB, memMB)
	}
}

// TestGitThreadsIndependentOfCPUs: with the gate's argv and environment, no
// git command starts more threads on a host with more CPUs, so its memory
// need (each thread's stack counts against RLIMIT_DATA) does not grow with
// the host. git counts CPUs with sysconf(_SC_NPROCESSORS_ONLN), which CPU
// affinity (taskset) does not change, so a preloaded shim
// (testdata/cpushim) sets the count git sees, 2 or 64, and logs every
// pthread_create. Needs gcc (as CI and ci-local have).
func TestGitThreadsIndependentOfCPUs(t *testing.T) {
	const gcc = "/usr/bin/gcc"
	if _, err := os.Stat(gcc); err != nil {
		t.Fatalf("this test builds a preloaded shim with %s: %v", gcc, err)
	}
	g := newGitFixture(t, "read")
	shim := filepath.Join(g.dir, "cpushim.so")
	if out, err := exec.CommandContext(t.Context(), gcc, "-shared", "-fPIC", "-O2", "-o", shim, filepath.Join("testdata", "cpushim", "cpushim.c"), "-ldl").CombinedOutput(); err != nil { //nolint:gosec // G204: fixed compiler and the test's own source
		t.Fatalf("building the shim: %v\n%s", err, out)
	}
	// Enough entries for preload-index to use threads (500 per thread),
	// with similar contents so the pack holds deltas for index-pack.
	base := strings.Repeat("line of shared configuration text\n", 128)
	for i := range 3000 {
		gatetest.WriteFile(t, filepath.Join(g.repo, "src", fmt.Sprintf("d%02d", i%30), fmt.Sprintf("f%04d.conf", i)), base+strconv.Itoa(i)+"\n", 0o644)
	}
	gatetest.Git(t, g.repo, "add", "-A")
	gatetest.Git(t, g.repo, "commit", "-q", "-m", "many files")
	for i := range 100 {
		gatetest.WriteFile(t, filepath.Join(g.repo, "src", "d00", fmt.Sprintf("f%04d.conf", i*30)), "changed\n", 0o644)
	}
	packDir := filepath.Join(g.dir, "pack")
	gatetest.Mkdir(t, packDir, 0o755)
	pack := filepath.Join(packDir, "x.pack")
	pk := exec.CommandContext(t.Context(), ops.GitPath, "-C", g.repo, "pack-objects", "--all", "--stdout") //nolint:gosec // G204: the fixed git binary
	pk.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + g.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	out, err := pk.Output()
	if err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	gatetest.WriteFile(t, pack, string(out), 0o644)

	cmds := map[string][]string{
		"status":       {"status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=all", "--branch"},
		"diff":         {"diff", "--no-color", "--no-ext-diff", "--no-textconv", "--submodule=short", "--ignore-submodules=all"},
		"update-index": {"update-index", "-q", "--refresh", "--ignore-submodules"},
		"log":          {"log", "--no-color", "-n", "100"},
		"index-pack":   {"index-pack", "-o", filepath.Join(packDir, "x.idx"), pack},
	}
	threads := func(name string, cpus int) int {
		t.Helper()
		logp := filepath.Join(g.dir, fmt.Sprintf("threads-%s-%d.log", name, cpus))
		_ = os.Remove(filepath.Join(packDir, "x.idx"))
		c := exec.CommandContext(t.Context(), ops.GitPath, ops.GitArgs(g.repo, "", cmds[name]...)...) //nolint:gosec // G204: the fixed git binary with the gate's argv
		c.Env = append(ops.GitEnv(g.home, g.repo), "LD_PRELOAD="+shim, "CPUSHIM_CPUS="+strconv.Itoa(cpus), "CPUSHIM_LOG="+logp)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %s at %d CPUs: %v\n%s", name, cpus, err, out)
		}
		b, _ := os.ReadFile(logp) //nolint:gosec // G304: the test's own log
		return strings.Count(string(b), "\n")
	}
	var report []string
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range cmds {
			if !yield(k) {
				return
			}
		}
	}) {
		two, many := threads(name, 2), threads(name, 64)
		report = append(report, fmt.Sprintf("%s %d/%d", name, two, many))
		if two != many {
			t.Errorf("git %s starts %d threads at 2 CPUs and %d at 64: its memory need grows with the host", name, two, many)
		}
	}
	t.Logf("threads started at 2/64 CPUs: %s", strings.Join(report, ", "))
}

// goOOM reports a Go program's fatal error at its memory limit: "out of
// memory" when the heap cannot grow, "cannot allocate memory" when the
// runtime's own metadata cannot (where the limit is met decides which).
func goOOM(stderr string) bool {
	return strings.Contains(stderr, "fatal error: runtime: out of memory") || strings.Contains(stderr, "fatal error: out of memory") ||
		strings.Contains(stderr, "fatal error: runtime: cannot allocate memory")
}
