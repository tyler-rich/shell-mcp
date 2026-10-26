//go:build linux

package execx_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

var (
	probeDir  string
	probeOnce sync.Once
	probe     string
	// self is this test binary; execx's init makes it the trampoline.
	self string
)

// relayEnv makes this test binary start the trampoline itself, passing on
// the fd 3 it inherited: the trampoline's peer is then not its parent.
const relayEnv = "EXECX_TEST_RELAY"

func TestMain(m *testing.M) {
	if exe, err := os.Executable(); err == nil {
		self, _ = filepath.EvalSymlinks(exe)
	}
	if os.Getenv(relayEnv) == "1" {
		cmd := exec.CommandContext(context.Background(), self, execx.TrampolineArg) //nolint:gosec // G204: this test binary
		cmd.Env = []string{}
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = []*os.File{os.NewFile(3, "relayed")}
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				os.Exit(ee.ExitCode())
			}
			os.Exit(1)
		}
		os.Exit(0)
	}
	d, err := os.MkdirTemp("", "execx-probe")
	if err != nil {
		panic(err)
	}
	probeDir = d
	code := m.Run()
	_ = os.RemoveAll(d)
	os.Exit(code)
}

func probePath(t *testing.T) string {
	t.Helper()
	probeOnce.Do(func() { probe = gatetest.BuildProbe(t, probeDir, "probe", "/nonexistent") })
	if probe == "" {
		t.Fatal("probe build failed earlier")
	}
	return probe
}

func run(t *testing.T, s *execx.Spec) execx.Result {
	t.Helper()
	if s.Timeout == 0 {
		s.Timeout = 10 * time.Second
	}
	if s.MaxOutput == 0 {
		s.MaxOutput = 1 << 20
	}
	if s.Env == nil {
		s.Env = execx.Environment("/nonexistent-home")
	}
	if s.Trampoline == "" {
		s.Trampoline = gatetest.Trampoline(t)
	}
	r, err := execx.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func lines(b []byte) []string { return strings.Split(strings.TrimSpace(string(b)), "\n") }

func TestEnvironmentExact(t *testing.T) {
	p := probePath(t)
	t.Setenv("SHOULD_NOT_LEAK", "1")
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"env"}, Env: execx.Environment("/home/svc-shell")})
	want := []string{
		"GIT_TERMINAL_PROMPT=0", "HOME=/home/svc-shell", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "NO_COLOR=1", "PAGER=cat",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=", "TERM=dumb",
	}
	if got := lines(r.Stdout); !slices.Equal(got, want) {
		t.Fatalf("env:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestArgvIsLiteral(t *testing.T) {
	p := probePath(t)
	args := []string{"echo", "a b", "$HOME", "; rm -rf /", "`id`", "*"}
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: args})
	if got := lines(r.Stdout); !slices.Equal(got, args[1:]) {
		t.Fatalf("argv %q", got)
	}
}

func TestCwdStdinExit(t *testing.T) {
	p := probePath(t)
	d, _ := filepath.EvalSymlinks(t.TempDir())
	if r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"pwd"}, Dir: d}); strings.TrimSpace(string(r.Stdout)) != d {
		t.Fatalf("pwd %q", r.Stdout)
	}
	if r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"pwd"}}); strings.TrimSpace(string(r.Stdout)) != "/" {
		t.Fatalf("default cwd %q", r.Stdout)
	}
	if r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"stdin"}, Stdin: []byte("in\x00put")}); string(r.Stdout) != "in\x00put" {
		t.Fatalf("stdin %q", r.Stdout)
	}
	if r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"stdin"}}); len(r.Stdout) != 0 {
		t.Fatalf("no stdin must be /dev/null: %q", r.Stdout)
	}
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"exit", "3"}})
	if r.ExitCode == nil || *r.ExitCode != 3 || r.Signal != "" || r.TimedOut {
		t.Fatalf("exit %+v", r)
	}
}

func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// Field 3 is the state; Z (zombie) or X (dead) are not alive. The
	// orphan is reparented to whatever the container's PID 1 is, which may
	// never reap it.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && len(s) > i+2 && s[i+2] != 'Z' && s[i+2] != 'X'
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still alive", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	p := probePath(t)
	start := time.Now()
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"fork-sleep", "60s"}, Timeout: 500 * time.Millisecond, KillGrace: 300 * time.Millisecond})
	if !r.TimedOut || r.ExitCode != nil || r.Signal == "" {
		t.Fatalf("timeout %+v", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	grandchild, err := strconv.Atoi(strings.TrimSpace(string(r.Stdout)))
	if err != nil {
		t.Fatalf("grandchild pid: %q", r.Stdout)
	}
	waitDead(t, grandchild)
}

func TestTimeoutEscalatesToKill(t *testing.T) {
	p := probePath(t)
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"ignore-term", "60s"}, Timeout: 300 * time.Millisecond, KillGrace: 300 * time.Millisecond})
	if !r.TimedOut || r.Signal != "SIGKILL" {
		t.Fatalf("escalation %+v", r)
	}
}

func TestOrphanHoldingPipesCannotHang(t *testing.T) {
	p := probePath(t)
	start := time.Now()
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"orphan", "60s"}, KillGrace: 300 * time.Millisecond})
	if time.Since(start) > 5*time.Second {
		t.Fatalf("hung for %v", time.Since(start))
	}
	if r.ExitCode == nil || *r.ExitCode != 0 || r.TimedOut {
		t.Fatalf("orphan %+v", r)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(r.Stdout)))
	if err != nil {
		t.Fatalf("orphan pid %q", r.Stdout)
	}
	waitDead(t, pid)
}

func TestOutputCap(t *testing.T) {
	p := probePath(t)
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"flood", "10000000"}, MaxOutput: 1000, Lookahead: 100})
	if !r.StdoutTruncated || len(r.Stdout) > 1100 || r.OutputCeilingHit || r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("cap: truncated=%v len=%d ceiling=%v exit=%v", r.StdoutTruncated, len(r.Stdout), r.OutputCeilingHit, r.ExitCode)
	}
	r = run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"flood-err", "5000"}, MaxOutput: 1000, Lookahead: 100})
	if !r.StderrTruncated || r.StdoutTruncated || len(r.Stderr) > 1100 {
		t.Fatalf("stderr cap: %+v", r.StderrTruncated)
	}
	r = run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"echo", "short"}, MaxOutput: 1000})
	if r.StdoutTruncated || string(r.Stdout) != "short\n" {
		t.Fatalf("short: %+v", r)
	}
}

func TestHardCeilingKills(t *testing.T) {
	p := probePath(t)
	start := time.Now()
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"flood", "100000000000"}, MaxOutput: 1000, HardCeiling: 1 << 20})
	if !r.OutputCeilingHit || !r.StdoutTruncated || len(r.Stdout) > 1000+execx.DefaultLookahead {
		t.Fatalf("ceiling %+v", r.OutputCeilingHit)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestChildRlimits(t *testing.T) {
	p := probePath(t)
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"rlimits"}})
	got := map[string]string{}
	for _, l := range lines(r.Stdout) {
		k, v, _ := strings.Cut(l, "=")
		got[k] = v
	}
	if got["core"] != "0/0" {
		t.Fatalf("core %q", got["core"])
	}
	cur, _, _ := strings.Cut(got["nofile"], "/")
	if n, err := strconv.Atoi(cur); err != nil || n > execx.ChildNofile {
		t.Fatalf("nofile %q", got["nofile"])
	}
	cur, _, _ = strings.Cut(got["nproc"], "/")
	if n, err := strconv.ParseUint(cur, 10, 64); err != nil || n == 0 || n > 1<<22 {
		t.Fatalf("nproc must be bounded: %q", got["nproc"])
	}
	// The memory limit (N-30): RLIMIT_DATA at the Spec's value, soft and
	// hard, so that the command cannot raise it.
	if want := fmt.Sprintf("%d/%d", testMemoryMB<<20, testMemoryMB<<20); got["data"] != want {
		t.Fatalf("data %q, want %s", got["data"], want)
	}
}

// testMemoryMB is the memory limit of the tests' commands: above what the
// Go probe needs to start (about 45 MiB), well below the host's.
const testMemoryMB = 256

// TestChildMemoryLimitStopsAllocation: a command that allocates past its
// limit fails at the limit (the Go probe: a fatal runtime error, exit 2) and does
// so quickly, while one that stays under it is unaffected (N-30).
func TestChildMemoryLimitStopsAllocation(t *testing.T) {
	p := probePath(t)
	if r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"alloc", "32"}}); r.ExitCode == nil || *r.ExitCode != 0 ||
		!strings.Contains(string(r.Stdout), "allocated 32 MiB") {
		t.Fatalf("32 MiB under a %d MiB limit: exit %v, %q %q", testMemoryMB, r.ExitCode, r.Stdout, r.Stderr)
	}
	start := time.Now()
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"alloc", "2048"}, Timeout: 30 * time.Second})
	if r.ExitCode == nil || *r.ExitCode == 0 || strings.Contains(string(r.Stdout), "allocated") || !goOOM(string(r.Stderr)) {
		t.Fatalf("2048 MiB under a %d MiB limit: exit %v signal %q, %q %q", testMemoryMB, r.ExitCode, r.Signal, r.Stdout, firstLine(r.Stderr))
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("stopping the allocation took %v", d)
	}
}

// TestChildCannotRaiseMemoryLimit: the hard limit is set too, so the
// command (without CAP_SYS_RESOURCE) can neither raise it nor remove it.
func TestChildCannotRaiseMemoryLimit(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root may hold CAP_SYS_RESOURCE")
	}
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: probePath(t), Args: []string{"raise-data"}})
	if got := strings.TrimSpace(string(r.Stdout)); got != "raise=EPERM unlimited=EPERM" {
		t.Fatalf("raising RLIMIT_DATA: %q", got)
	}
}

// TestChildMemoryLimitInherited: what the command starts gets the same
// limit (fork and execve keep it).
func TestChildMemoryLimitInherited(t *testing.T) {
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: probePath(t), Args: []string{"child-rlimits"}})
	if err := childLimitsError(r.Stdout); err != nil {
		t.Fatalf("the command's child: %v (%q)", err, r.Stdout)
	}
}

// TestIgnoreRLimitData reads the kernel's ignore_rlimit_data parameter
// (Y or N); a missing parameter is an error, never "not set".
func TestIgnoreRLimitData(t *testing.T) {
	d := t.TempDir()
	for _, c := range []struct {
		content string
		want    bool
	}{{"Y\n", true}, {"N\n", false}, {"1\n", true}, {"0\n", false}} {
		p := filepath.Join(d, "param")
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := execx.IgnoreRLimitData(p); err != nil || got != c.want {
			t.Fatalf("%q: %v %v, want %v", c.content, got, err, c.want)
		}
	}
	if _, err := execx.IgnoreRLimitData(filepath.Join(d, "missing")); err == nil {
		t.Fatal("a missing parameter read as not set")
	}
	if err := os.WriteFile(filepath.Join(d, "bad"), []byte("maybe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execx.IgnoreRLimitData(filepath.Join(d, "bad")); err == nil {
		t.Fatal("an unknown value read as a setting")
	}
}

// firstLine is the first line of b, for messages.
func firstLine(b []byte) string {
	l, _, _ := strings.Cut(string(b), "\n")
	return l
}

// raiseOwnLimits sets this process's soft core, open-file and process
// limits to their hard limits (unprivileged), so that a child that still
// carries the parent's limits is told apart from one that got the child
// limits. It returns the parent's limits after raising them.
func raiseOwnLimits(t *testing.T) map[string]syscall.Rlimit {
	t.Helper()
	got := map[string]syscall.Rlimit{}
	for name, res := range map[string]int{"core": unix.RLIMIT_CORE, "nofile": unix.RLIMIT_NOFILE, "nproc": unix.RLIMIT_NPROC, "data": unix.RLIMIT_DATA} {
		var l syscall.Rlimit
		if err := syscall.Getrlimit(res, &l); err != nil {
			t.Fatalf("getrlimit %s: %v", name, err)
		}
		l.Cur = l.Max
		// syscall.Setrlimit (not x/sys/unix) so that os/exec children
		// inherit the raised RLIMIT_NOFILE instead of Go's saved original.
		if err := syscall.Setrlimit(res, &l); err != nil {
			t.Fatalf("setrlimit %s: %v", name, err)
		}
		got[name] = l
	}
	return got
}

// nprocBound is the highest RLIMIT_NPROC a child may have: the user's
// tasks now plus the child's allowance, with slack for tasks that come and
// go while the tests run.
func nprocBound() uint64 {
	return execx.UserTasks(os.Getuid()) + execx.ChildExtraTasks + 1024
}

// requireDiscriminating fails the test when no limit the child gets differs
// from the parent's, because the limit tests could then pass vacuously.
func requireDiscriminating(t *testing.T, parent map[string]syscall.Rlimit) {
	t.Helper()
	if parent["core"].Max == 0 && parent["nofile"].Max <= execx.ChildNofile && parent["nproc"].Max <= nprocBound() &&
		parent["data"].Max <= uint64(testMemoryMB)<<20 {
		t.Fatalf("this host's hard limits (%+v) equal the child limits; the rlimit tests cannot tell them apart", parent)
	}
}

// childLimitsError checks the probe's "rlimits" output against the child
// limits: core 0/0, both open-file limits ≤ ChildNofile, both process
// limits ≤ nprocBound.
func childLimitsError(out []byte) error {
	got := map[string][2]uint64{}
	for _, l := range lines(out) {
		k, v, _ := strings.Cut(l, "=")
		c, m, _ := strings.Cut(v, "/")
		cur, err1 := strconv.ParseUint(c, 10, 64)
		maxv, err2 := strconv.ParseUint(m, 10, 64)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("unparsable probe output %q", out)
		}
		got[k] = [2]uint64{cur, maxv}
	}
	if len(got) != 4 {
		return fmt.Errorf("unparsable probe output %q", out)
	}
	if n, b := got["data"], uint64(testMemoryMB)<<20; n[0] != b || n[1] != b {
		return fmt.Errorf("data %d/%d, want %d/%d (the Spec's MaxMemoryMB, soft and hard)", n[0], n[1], b, b)
	}
	var errs []string
	if got["core"] != [2]uint64{0, 0} {
		errs = append(errs, fmt.Sprintf("core %d/%d, want 0/0", got["core"][0], got["core"][1]))
	}
	if n := got["nofile"]; n[0] > execx.ChildNofile || n[1] > execx.ChildNofile {
		errs = append(errs, fmt.Sprintf("nofile %d/%d, want ≤ %d", n[0], n[1], execx.ChildNofile))
	}
	if n, b := got["nproc"], nprocBound(); n[0] > b || n[1] > b {
		errs = append(errs, fmt.Sprintf("nproc %d/%d, want ≤ %d", n[0], n[1], b))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// TestChildRlimitsBeforeFirstInstruction: the child's limits are in force
// before it runs its first instruction, however long the parent takes after
// starting it. The probe reads its limits as its first action, and the
// parent pauses right after the start; limits applied by the parent after
// the start (prlimit) reach the probe only after it has read them.
func TestChildRlimitsBeforeFirstInstruction(t *testing.T) {
	p := probePath(t)
	requireDiscriminating(t, raiseOwnLimits(t))
	r, err := execx.RunWithStartDelay(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Trampoline: gatetest.Trampoline(t), Args: []string{"rlimits"},
		Env: execx.Environment("/nonexistent-home"), Timeout: 10 * time.Second, MaxOutput: 1 << 20}, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := childLimitsError(r.Stdout); err != nil {
		t.Fatalf("the child ran without its limits: %v", err)
	}
}

// TestChildRlimitsNeverRace runs the probe a few hundred times, four at a
// time, with no pause: not one run may read its limits before they apply.
func TestChildRlimitsNeverRace(t *testing.T) {
	p := probePath(t)
	requireDiscriminating(t, raiseOwnLimits(t))
	const runs, workers = 400, 4
	var (
		mu     sync.Mutex
		failed int
		first  error
		wg     sync.WaitGroup
	)
	next := make(chan struct{})
	for range workers {
		wg.Go(func() {
			for range next {
				r, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Trampoline: gatetest.Trampoline(t), Args: []string{"rlimits"},
					Env: execx.Environment("/nonexistent-home"), Timeout: 10 * time.Second, MaxOutput: 1 << 20})
				if err == nil {
					err = childLimitsError(r.Stdout)
				}
				if err != nil {
					mu.Lock()
					failed++
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}
		})
	}
	for range runs {
		next <- struct{}{}
	}
	close(next)
	wg.Wait()
	if failed > 0 {
		t.Fatalf("%d of %d runs ran without their limits; first: %v", failed, runs, first)
	}
}

// startTrampoline runs this test binary directly with args, env and, when
// fd3 is not nil, fd3 as fd 3, as something other than Run would start the
// trampoline. It returns the exit status and stderr.
func startTrampoline(t *testing.T, args, env []string, fd3 *os.File) (code int, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, args...) //nolint:gosec // G204: this test binary
	cmd.Env = env
	if fd3 != nil {
		cmd.ExtraFiles = []*os.File{fd3}
	}
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("trampoline run: %v (stderr %q)", err, errBuf.String())
	}
	return ee.ExitCode(), errBuf.String()
}

// socketEnd returns one end of an AF_UNIX socketpair of type typ made by
// this process; both ends stay open until cleanup.
func socketEnd(t *testing.T, typ int) *os.File {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return b
}

// TestTrampolineRefusesOutsiders: the trampoline runs only as Run starts
// it. Each way of starting it otherwise is refused before it reads
// anything, with exit status TrampolineRefused and the reason on stderr.
// (A terminal on fd 0–2 is covered by TestTrampolineRefusal, which needs
// no terminal.)
func TestTrampolineRefusesOutsiders(t *testing.T) {
	marker := execx.TrampolineArg
	good := socketEnd(t, unix.SOCK_STREAM)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	dgram := socketEnd(t, unix.SOCK_DGRAM)
	for _, c := range []struct {
		name string
		args []string
		env  []string
		fd3  *os.File
		want string
	}{
		{"extra argument", []string{marker, "serve"}, []string{}, good, "it takes exactly one argument"},
		{"environment", []string{marker}, []string{"SSH_ORIGINAL_COMMAND=x"}, good, "it must be started with an empty environment"},
		{"no fd 3", []string{marker}, []string{}, nil, "fd 3 is not"},
		{"pipe as fd 3", []string{marker}, []string{}, pr, "fd 3 is not a Unix stream socket"},
		{"datagram socket as fd 3", []string{marker}, []string{}, dgram, "fd 3 is not a Unix stream socket"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := startTrampoline(t, c.args, c.env, c.fd3)
			if code != execx.TrampolineRefused || !strings.Contains(stderr, "refusing to run the internal exec trampoline: "+c.want) {
				t.Fatalf("exit %d, stderr %q; want %d and %q", code, stderr, execx.TrampolineRefused, c.want)
			}
		})
	}
	t.Run("fd 3 from another process", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, self)
		cmd.Env = []string{relayEnv + "=1"}
		cmd.ExtraFiles = []*os.File{good}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != execx.TrampolineRefused || !strings.Contains(stderr.String(), "fd 3's peer is not the parent process") {
			t.Fatalf("relayed: %v, stderr %q", err, stderr.String())
		}
	})
}

// TestCommandCannotReachTrampoline: a command Run starts can run the gate's
// own binary with the trampoline argument, but it has neither an empty
// environment nor the control descriptor (fd 3 is close-on-exec), so the
// trampoline refuses.
// The command is this test binary, which under -race (ThreadSanitizer)
// maps hundreds of MiB of shadow memory as it starts: it gets the highest
// limit.
func TestCommandCannotReachTrampoline(t *testing.T) {
	r := run(t, &execx.Spec{MaxMemoryMB: execx.MaxMemoryMB, Path: self, Args: []string{execx.TrampolineArg}})
	if r.ExitCode == nil || *r.ExitCode != execx.TrampolineRefused || !strings.Contains(string(r.Stderr), "empty environment") {
		t.Fatalf("with the command environment: %+v, stderr %q", r.ExitCode, r.Stderr)
	}
	r = run(t, &execx.Spec{MaxMemoryMB: execx.MaxMemoryMB, Path: self, Args: []string{execx.TrampolineArg}, Env: []string{}})
	if r.ExitCode == nil || *r.ExitCode != execx.TrampolineRefused || !strings.Contains(string(r.Stderr), "fd 3 is not") {
		t.Fatalf("with an empty environment: %+v, stderr %q", r.ExitCode, r.Stderr)
	}
}

// procAttrs parses the probe's "procattrs" output (key=value lines).
func procAttrs(out []byte) map[string]string {
	a := map[string]string{}
	for _, l := range lines(out) {
		k, v, _ := strings.Cut(l, "=")
		a[k] = v
	}
	return a
}

// extraFDs returns the descriptors in a "fds=" value other than the Go
// runtime's own: since Go 1.25 the runtime keeps /sys/fs/cgroup/cpu.max open
// (close-on-exec) where the cgroup filesystem is readable, at the lowest free
// descriptor, so finding it at fd 3 also shows fd 3 was free.
func extraFDs(fds string) []string {
	var extra []string
	for _, fd := range strings.Split(fds, ",") {
		if fd != "" && !strings.HasPrefix(fd, "3:100000:/sys/fs/cgroup/") {
			extra = append(extra, fd)
		}
	}
	return extra
}

// TestCommandProcessAttributes: the command keeps what the trampoline was
// started with: Pdeathsig=SIGKILL across both execs, its own process group,
// no blocked signals, and no descriptor beyond stdin, stdout and stderr
// (the control socket does not leak).
func TestCommandProcessAttributes(t *testing.T) {
	p := probePath(t)
	a := procAttrs(run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"procattrs"}}).Stdout)
	if a["pdeathsig"] != "9" || a["pdeathsig_thread"] != "main" || a["pgid_is_pid"] != "true" || a["sigblk"] != "0000000000000000" {
		t.Fatalf("attributes %v", a)
	}
	if extra := extraFDs(a["fds"]); len(extra) > 0 {
		t.Fatalf("the command has descriptors it was not given: %v", extra)
	}
}

// TestPdeathsigIsPerThread: the parent-death signal belongs to a thread.
// The command's main thread, the one the trampoline's execve(2) kept, holds
// SIGKILL; another thread of the same process holds none (copy_process sets
// it to 0 for every new task). A read of PR_GET_PDEATHSIG from any thread
// but the main one therefore says 0 while the process is still covered: on
// the parent's death the kernel signals the whole thread group for any
// thread that holds a signal (forget_original_parent).
func TestPdeathsigIsPerThread(t *testing.T) {
	p := probePath(t)
	out := lines(run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"pdeathsig-threads"}}).Stdout)
	if want := []string{"main=9 main", "other=0 other"}; !slices.Equal(out, want) {
		t.Fatalf("pdeathsig-threads: %q, want %q", out, want)
	}
}

// TestCommandPdeathsigEveryRun runs the probe a few hundred times, eight at
// a time. Every run must find SIGKILL as its parent-death signal, read on
// its main thread, after other goroutines kept its processors busy.
func TestCommandPdeathsigEveryRun(t *testing.T) {
	p := probePath(t)
	const runs, workers = 400, 8
	var (
		mu     sync.Mutex
		failed int
		first  string
		wg     sync.WaitGroup
	)
	next := make(chan struct{})
	for range workers {
		wg.Go(func() {
			for range next {
				r, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Trampoline: gatetest.Trampoline(t), Args: []string{"procattrs"},
					Env: execx.Environment("/nonexistent-home"), Timeout: 10 * time.Second, MaxOutput: 1 << 20})
				var got string
				if err != nil {
					got = err.Error()
				} else if a := procAttrs(r.Stdout); a["pdeathsig"] != "9" || a["pdeathsig_thread"] != "main" {
					got = fmt.Sprintf("pdeathsig=%s read on the %s thread", a["pdeathsig"], a["pdeathsig_thread"])
				}
				if got != "" {
					mu.Lock()
					failed++
					if first == "" {
						first = got
					}
					mu.Unlock()
				}
			}
		})
	}
	for range runs {
		next <- struct{}{}
	}
	close(next)
	wg.Wait()
	if failed > 0 {
		t.Fatalf("%d of %d runs did not read pdeathsig=9 on the main thread; first: %s", failed, runs, first)
	}
}

// TestCommandGetsNoInheritedDescriptor: a descriptor the gate itself holds
// without close-on-exec (inherited from whatever started it) does not reach
// the command; os/exec alone would pass it on.
func TestCommandGetsNoInheritedDescriptor(t *testing.T) {
	p := probePath(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	if _, err = unix.FcntlInt(pw.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	leaked := strconv.Itoa(int(pw.Fd())) + ":"
	// Control: a child os/exec starts directly inherits it.
	out, err := exec.CommandContext(context.Background(), p, "procattrs").Output() //nolint:gosec // G204: the test probe
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(procAttrs(out)["fds"], leaked) {
		t.Fatalf("control: the direct child does not hold fd %s: %s", leaked, out)
	}
	a := procAttrs(run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"procattrs"}}).Stdout)
	if extra := extraFDs(a["fds"]); len(extra) > 0 {
		t.Fatalf("the command inherited descriptors: %v", extra)
	}
}

func TestTrampolineStartErrors(t *testing.T) {
	p := probePath(t)
	notExec := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(notExec, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		spec execx.Spec
		want string
	}{
		{"missing command", execx.Spec{Path: "/nonexistent/binary"}, "ENOENT"},
		{"missing directory", execx.Spec{Path: p, Args: []string{"pwd"}, Dir: "/nonexistent-dir"}, "ENOENT"},
		{"not executable", execx.Spec{Path: notExec}, "EACCES"},
		{"no trampoline", execx.Spec{Path: p, Trampoline: "relative"}, "no exec trampoline"},
		{"missing trampoline", execx.Spec{Path: p, Trampoline: "/nonexistent/trampoline"}, "ENOENT"},
		{"NUL in an argument", execx.Spec{Path: p, Args: []string{"echo", "a\x00b"}}, "EINVAL"},
		// Fail closed: no command runs without a memory limit (N-30).
		{"no memory limit", execx.Spec{Path: p, Args: []string{"echo", "x"}, MaxMemoryMB: -1}, "memory limit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := c.spec
			s.Timeout, s.MaxOutput, s.Env = 10*time.Second, 1<<20, execx.Environment("/")
			switch {
			case s.MaxMemoryMB == 0:
				s.MaxMemoryMB = testMemoryMB
			case s.MaxMemoryMB < 0:
				s.MaxMemoryMB = 0
			}
			if s.Trampoline == "" {
				s.Trampoline = gatetest.Trampoline(t)
			}
			_, err := execx.Run(context.Background(), &s)
			if !errors.Is(err, execx.ErrStart) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want ErrStart with %q", err, c.want)
			}
		})
	}
}

func TestStartFailure(t *testing.T) {
	_, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: "/nonexistent/binary", Trampoline: gatetest.Trampoline(t), Timeout: time.Second, MaxOutput: 10, Env: execx.Environment("/")})
	if !errors.Is(err, execx.ErrStart) {
		t.Fatalf("err %v", err)
	}
	if _, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: "relative", Trampoline: gatetest.Trampoline(t), Timeout: time.Second, MaxOutput: 10}); !errors.Is(err, execx.ErrStart) {
		t.Fatalf("relative path: %v", err)
	}
}

// TestUserTasksIn counts uid's tasks from <proc>/<pid>/status (Threads of
// every process whose real uid matches), skipping non-pid entries and a
// process that went away, and fails when /proc cannot be listed: never a
// silent 0, which would drop RLIMIT_NPROC (handoff N-30's audit).
func TestUserTasksIn(t *testing.T) {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "sys", "kernel"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "sys", "kernel", "pid_max"), []byte("32768\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for pid, s := range map[string]string{
		"100": "Name:\ta\nUid:\t4321\t4321\t4321\t4321\nThreads:\t3\n",
		"101": "Name:\tb\nUid:\t4321\t4321\t4321\t4321\nThreads:\t2\n",
		"102": "Name:\tc\nUid:\t7\t7\t7\t7\nThreads:\t9\n",
	} {
		if err := os.MkdirAll(filepath.Join(d, pid), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, pid, "status"), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"self", "103"} { // not a pid; a pid that went away
		if err := os.MkdirAll(filepath.Join(d, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := execx.UserTasksIn(d, 4321); err != nil || n != 5 {
		t.Fatalf("tasks of 4321: %d %v, want 5", n, err)
	}
	if n, err := execx.UserTasksIn(filepath.Join(d, "missing"), 4321); err == nil {
		t.Fatalf("a /proc that cannot be listed counted %d tasks", n)
	}
}

// TestUserTasksInBoundFromPidMax: the scan's bound follows the kernel's
// pid_max (<proc>/sys/kernel/pid_max), not a fixed cap: a /proc with more
// entries than 65,536 is counted when pid_max allows that many processes;
// more entries than pid_max allows, or a pid_max that cannot be read, is
// an error naming the reason.
func TestUserTasksInBoundFromPidMax(t *testing.T) {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "sys", "kernel"), 0o700); err != nil {
		t.Fatal(err)
	}
	pidMax := filepath.Join(d, "sys", "kernel", "pid_max")
	if err := os.WriteFile(pidMax, []byte("4194304\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const many = 1<<16 + 64 // more than the old fixed cap
	for i := range many {
		if err := os.Mkdir(filepath.Join(d, strconv.Itoa(1000+i)), 0o700); err != nil { // processes that went away
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(d, "1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "1", "status"), []byte("Uid:\t4321\t4321\t4321\t4321\nThreads:\t7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := execx.UserTasksIn(d, 4321); err != nil || n != 7 {
		t.Fatalf("%d entries under pid_max 4194304: %d %v, want 7", many+1, n, err)
	}
	// More entries than pid_max allows processes: the scan's own bound.
	if err := os.WriteFile(pidMax, []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execx.UserTasksIn(d, 4321); err == nil || !strings.Contains(err.Error(), "pid_max") {
		t.Fatalf("more entries than pid_max allows: %v", err)
	}
	if err := os.Remove(pidMax); err != nil {
		t.Fatal(err)
	}
	if _, err := execx.UserTasksIn(d, 4321); err == nil || !strings.Contains(err.Error(), "pid_max") {
		t.Fatalf("an unreadable pid_max: %v", err)
	}
}

// TestRunRefusesWithoutTaskCount: when the service account's tasks cannot
// be counted, Run refuses (ErrStart naming RLIMIT_NPROC) instead of starting
// the command without the limit. Root is exempt from RLIMIT_NPROC in the
// kernel, so the helper's commands do not need the count.
func TestRunRefusesWithoutTaskCount(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("uid 0 is exempt from RLIMIT_NPROC")
	}
	_, err := execx.RunWithProcDir(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: probePath(t), Args: []string{"echo", "x"},
		Trampoline: gatetest.Trampoline(t), Env: execx.Environment("/"), Timeout: 10 * time.Second, MaxOutput: 1 << 10}, filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, execx.ErrStart) || !strings.Contains(err.Error(), "RLIMIT_NPROC") {
		t.Fatalf("a command without its task count: %v, want ErrStart naming RLIMIT_NPROC", err)
	}
}

// goOOM reports a Go program's fatal error at its memory limit: "out of
// memory" when the heap cannot grow, "cannot allocate memory" when the
// runtime's own metadata cannot (where the limit is met decides which).
func goOOM(stderr string) bool {
	return strings.Contains(stderr, "fatal error: runtime: out of memory") || strings.Contains(stderr, "fatal error: out of memory") ||
		strings.Contains(stderr, "fatal error: runtime: cannot allocate memory")
}
