//go:build linux

package ops_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
		"    templates: [[\"rlimits\"], [\"child-rlimits\"], [\"raise-data\"], [\"alloc\", \"{int:1-4096}\"], [\"alloc-report\", \"{int:1-4096}\"]]\n"
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
	f.ok("exec", m{"command_id": "probe-mem", "args": []string{"alloc-report", "2048"}}, &d)
	if err := memLimitStop(d, memMB); err != nil {
		t.Fatalf("2048 MiB under %d MiB: %v: %+v", memMB, err, d)
	}
	t.Logf("stopped at the limit: %s, holding %d MiB", memStopKind(d.Stderr), lastHeld(d.Stderr))
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

// memLimitStop reports why an exec result of `probe alloc-report` does not
// show the probe stopped at its memory limit by its own runtime, or nil when
// it does (POLICY §4a, "What a command sees at the limit"). The probe must
// have ended by itself with Go's fatal exit status 2 (no signal), never
// finished the allocation, and last reported holding between half the limit
// and the limit: it was stopped near the limit, and not past it. Its stderr
// must be Go's out-of-memory error (goOOM) or the fault Go 1.27's garbage
// collector has at the limit (gcSpanQueueFault).
func memLimitStop(d memExec, limitMB int) error {
	switch {
	case d.Signal != nil:
		return fmt.Errorf("ended by signal %s", *d.Signal)
	case d.ExitCode == nil || *d.ExitCode != 2:
		return fmt.Errorf("exit status %v, want Go's fatal 2", d.ExitCode)
	case strings.Contains(d.Stdout, "allocated"):
		return fmt.Errorf("the allocation completed")
	}
	held := lastHeld(d.Stderr)
	if held < limitMB/2 || held > limitMB {
		return fmt.Errorf("last held %d MiB, want %d to %d", held, limitMB/2, limitMB)
	}
	if memStopKind(d.Stderr) == "" {
		return fmt.Errorf("neither Go's out-of-memory error nor its GC span-queue fault")
	}
	return nil
}

// heldRE is the probe's alloc-report line.
var heldRE = regexp.MustCompile(`(?m)^held (\d+) MiB$`)

// lastHeld is the MiB of the probe's last "held" line, -1 without one.
func lastHeld(stderr string) int {
	l := heldRE.FindAllStringSubmatch(stderr, -1)
	if len(l) == 0 {
		return -1
	}
	n, _ := strconv.Atoi(l[len(l)-1][1])
	return n
}

// gcSpanQueueFault is the fault Go 1.27's garbage collector has at
// RLIMIT_DATA: newSpanSPMC stores sysAlloc's result unchecked, sysAlloc
// returns nil when the limit refuses the mapping, and the next tryDrain
// (called by drain) writes slot 0 of that nil ring. So: a SIGSEGV at
// address 0, SEGV_MAPERR, whose faulting goroutine's first frame is
// tryDrain in mgcmark_greenteagc.go and its second drain.
//
// Accepted only while the Go runtime has that bug (Go 1.27.3,
// runtime/mgcmark_greenteagc.go:520; docs/handoff/POST-RELEASE.md N-37).
// TestGCSpanQueueBugInRuntime fails once a Go release fixes it: then remove
// this acceptance (gcSpanQueueFault, its case in memStopKind, the
// TestMemLimitStop cases that expect it, TestGCSpanQueueBugInRuntime) and
// the fault's sentence in POLICY §4a, in that same PR, and close N-37.
var gcSpanQueueFault = regexp.MustCompile(`(?m)^SIGSEGV: segmentation violation\nPC=0x[0-9a-f]+ m=\d+ sigcode=1 addr=0x0\n\ngoroutine \d+ [^\n]*:\nruntime\.\(\*spanQueue\)\.tryDrain\([^\n]*\n\truntime/mgcmark_greenteagc\.go:\d+ [^\n]*\nruntime\.\(\*spanQueue\)\.drain\(`)

// memStopKind names how a Go child stopped at its limit, "" for neither way.
func memStopKind(stderr string) string {
	switch {
	case goOOM(stderr):
		return "out of memory"
	case gcSpanQueueFault.MatchString(stderr):
		return "the GC's span-queue fault (Go 1.27, POLICY §4a)"
	}
	return ""
}

// TestMemLimitStop: which results count as a Go child stopped at its
// memory limit (invented outputs, shaped as the probe's and Go 1.27's).
func TestMemLimitStop(t *testing.T) {
	held := func(to int) string {
		var b strings.Builder
		for k := 4; k <= to; k += 4 {
			fmt.Fprintf(&b, "held %d MiB\n", k)
		}
		return b.String()
	}
	oom := "fatal error: runtime: out of memory\n\nruntime stack:\nruntime.throw({0x5a0b1c?, 0x0?})\n"
	cannot := "fatal error: runtime: cannot allocate memory\n\ngoroutine 1 gp=0xc000002380 m=0 mp=0x6a1e40 [running]:\n"
	segv := func(addr, frame, caller string) string {
		return "SIGSEGV: segmentation violation\nPC=0x431b7c m=4 sigcode=1 addr=" + addr + "\n\n" +
			"goroutine 0 gp=0xc000184380 m=4 mp=0xc000180008 [idle]:\n" +
			frame + "(0xc000400400?, 0x4662ab?, 0x44155a?)\n\truntime/mgcmark_greenteagc.go:520 +0x5c fp=0xc0001a7bb0 sp=0xc0001a7b90 pc=0x431b7c\n" +
			caller + "(0xc0001cf278, 0x6)\n\truntime/mgcmark_greenteagc.go:473 +0x66 fp=0xc0001a7be0 sp=0xc0001a7bb0 pc=0x431a66\n"
	}
	gcSegv := segv("0x0", "runtime.(*spanQueue).tryDrain", "runtime.(*spanQueue).drain")
	two, one, zero := 2, 1, 0
	kill := "killed"
	cases := []struct {
		name string
		d    memExec
		ok   bool
	}{
		{"out of memory near the limit", memExec{ExitCode: &two, Stderr: held(148) + oom}, true},
		{"cannot allocate memory near the limit", memExec{ExitCode: &two, Stderr: held(152) + cannot}, true},
		{"the GC's span queue at the limit", memExec{ExitCode: &two, Stderr: held(152) + gcSegv}, true},
		{"the GC's span queue at the limit, the last report at the limit", memExec{ExitCode: &two, Stderr: held(192) + gcSegv}, true},
		{"a SIGSEGV in another frame", memExec{ExitCode: &two, Stderr: held(152) + segv("0x0", "main.allocMiB", "main.main")}, false},
		{"a SIGSEGV in the span queue at another address", memExec{ExitCode: &two, Stderr: held(152) + segv("0x18", "runtime.(*spanQueue).tryDrain", "runtime.(*spanQueue).drain")}, false},
		{"a SIGSEGV in tryDrain from another caller", memExec{ExitCode: &two, Stderr: held(152) + segv("0x0", "runtime.(*spanQueue).tryDrain", "runtime.(*spanQueue).steal")}, false},
		{"the GC's span queue far below the limit", memExec{ExitCode: &two, Stderr: held(12) + gcSegv}, false},
		{"out of memory far below the limit", memExec{ExitCode: &two, Stderr: held(20) + oom}, false},
		{"out of memory past the limit", memExec{ExitCode: &two, Stderr: held(300) + oom}, false},
		{"out of memory with no report", memExec{ExitCode: &two, Stderr: oom}, false},
		{"another exit status", memExec{ExitCode: &one, Stderr: held(148) + oom}, false},
		{"killed by a signal", memExec{Signal: &kill, Stderr: held(148)}, false},
		{"the whole allocation", memExec{ExitCode: &zero, Stdout: "allocated 2048 MiB\n", Stderr: held(2048)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := memLimitStop(c.d, memMB)
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// newSpanSPMCUnchecked reports whether a runtime/mgcmark_greenteagc.go's
// newSpanSPMC stores sysAlloc's result in r.ring with no check between
// (the Go 1.27.3 bug gcSpanQueueFault describes).
func newSpanSPMCUnchecked(src string) (bool, error) {
	i := strings.Index(src, "\nfunc newSpanSPMC(")
	if i < 0 && !strings.HasPrefix(src, "func newSpanSPMC(") {
		return false, fmt.Errorf("no newSpanSPMC")
	}
	body := src[i+1:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	return spanSPMCUncheckedRE.MatchString(body), nil
}

// spanSPMCUncheckedRE: sysAlloc's result stored as the ring on the next line.
var spanSPMCUncheckedRE = regexp.MustCompile(`(?m)^\tring := sysAlloc\([^\n]*\)\n\tatomic\.StorepNoWB\(unsafe\.Pointer\(&r\.ring\), ring\)$`)

// TestNewSpanSPMCUnchecked: the source check, on invented excerpts shaped
// as Go 1.27.3's newSpanSPMC and as a fixed one.
func TestNewSpanSPMCUnchecked(t *testing.T) {
	const head = "func newSpanSPMC(cap uint32) *spanSPMC {\n\tlock(&work.spanSPMCs.lock)\n\tr.cap = cap\n"
	cases := []struct {
		name, src string
		bug, err  bool
	}{
		{"Go 1.27.3", head + "\tring := sysAlloc(uintptr(cap)*unsafe.Sizeof(objptr(0)), &memstats.gcMiscSys, \"GC span queue\")\n\tatomic.StorepNoWB(unsafe.Pointer(&r.ring), ring)\n\treturn r\n}\n", true, false},
		{"a nil check", head + "\tring := sysAlloc(uintptr(cap)*unsafe.Sizeof(objptr(0)), &memstats.gcMiscSys, \"GC span queue\")\n\tif ring == nil {\n\t\tthrow(\"out of memory\")\n\t}\n\tatomic.StorepNoWB(unsafe.Pointer(&r.ring), ring)\n\treturn r\n}\n", false, false},
		{"another allocator", head + "\tring := persistentalloc(uintptr(cap)*unsafe.Sizeof(objptr(0)), 0, &memstats.gcMiscSys)\n\tatomic.StorepNoWB(unsafe.Pointer(&r.ring), ring)\n\treturn r\n}\n", false, false},
		{"no newSpanSPMC", "func other() {\n}\n", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bug, err := newSpanSPMCUnchecked(c.src)
			if (err != nil) != c.err || (err == nil && bug != c.bug) {
				t.Fatalf("bug %v err %v, want bug %v err %v", bug, err, c.bug, c.err)
			}
		})
	}
}

// TestGCSpanQueueBugInRuntime: the Go runtime these tests are built with
// still has the bug memLimitStop accepts the fault of; when it does not,
// remove that acceptance (see gcSpanQueueFault).
func TestGCSpanQueueBugInRuntime(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "env", "GOROOT", "GOVERSION").Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || f[1] != runtime.Version() {
		t.Fatalf("go env GOROOT GOVERSION %q, want this test's %s", out, runtime.Version())
	}
	src, err := os.ReadFile(filepath.Join(f[0], "src", "runtime", "mgcmark_greenteagc.go"))
	if err != nil {
		t.Fatalf("the runtime's source: %v", err)
	}
	bug, err := newSpanSPMCUnchecked(string(src))
	if err != nil {
		t.Fatalf("%s: %v; check by hand whether Go still has the bug gcSpanQueueFault accepts (POST-RELEASE N-37)", runtime.Version(), err)
	}
	if !bug {
		t.Fatalf("%s's newSpanSPMC checks its allocation: remove the GC span-queue fault's acceptance and POLICY §4a's sentence on it, and close POST-RELEASE N-37 (see gcSpanQueueFault)", runtime.Version())
	}
}

// goOOM reports a Go program's fatal error at its memory limit: "out of
// memory" when the heap cannot grow, "cannot allocate memory" when the
// runtime's own metadata cannot (where the limit is met decides which).
func goOOM(stderr string) bool {
	return strings.Contains(stderr, "fatal error: runtime: out of memory") || strings.Contains(stderr, "fatal error: out of memory") ||
		strings.Contains(stderr, "fatal error: runtime: cannot allocate memory")
}
