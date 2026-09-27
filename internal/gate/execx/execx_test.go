//go:build linux

package execx_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

var (
	probeDir  string
	probeOnce sync.Once
	probe     string
)

func TestMain(m *testing.M) {
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

func run(t *testing.T, s execx.Spec) execx.Result {
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
	r := run(t, execx.Spec{Path: p, Args: []string{"env"}, Env: execx.Environment("/home/svc-shell")})
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
	r := run(t, execx.Spec{Path: p, Args: args})
	if got := lines(r.Stdout); !slices.Equal(got, args[1:]) {
		t.Fatalf("argv %q", got)
	}
}

func TestCwdStdinExit(t *testing.T) {
	p := probePath(t)
	d, _ := filepath.EvalSymlinks(t.TempDir())
	if r := run(t, execx.Spec{Path: p, Args: []string{"pwd"}, Dir: d}); strings.TrimSpace(string(r.Stdout)) != d {
		t.Fatalf("pwd %q", r.Stdout)
	}
	if r := run(t, execx.Spec{Path: p, Args: []string{"pwd"}}); strings.TrimSpace(string(r.Stdout)) != "/" {
		t.Fatalf("default cwd %q", r.Stdout)
	}
	if r := run(t, execx.Spec{Path: p, Args: []string{"stdin"}, Stdin: []byte("in\x00put")}); string(r.Stdout) != "in\x00put" {
		t.Fatalf("stdin %q", r.Stdout)
	}
	if r := run(t, execx.Spec{Path: p, Args: []string{"stdin"}}); len(r.Stdout) != 0 {
		t.Fatalf("no stdin must be /dev/null: %q", r.Stdout)
	}
	r := run(t, execx.Spec{Path: p, Args: []string{"exit", "3"}})
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
	r := run(t, execx.Spec{Path: p, Args: []string{"fork-sleep", "60s"}, Timeout: 500 * time.Millisecond, KillGrace: 300 * time.Millisecond})
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
	r := run(t, execx.Spec{Path: p, Args: []string{"ignore-term", "60s"}, Timeout: 300 * time.Millisecond, KillGrace: 300 * time.Millisecond})
	if !r.TimedOut || r.Signal != "SIGKILL" {
		t.Fatalf("escalation %+v", r)
	}
}

func TestOrphanHoldingPipesCannotHang(t *testing.T) {
	p := probePath(t)
	start := time.Now()
	r := run(t, execx.Spec{Path: p, Args: []string{"orphan", "60s"}, KillGrace: 300 * time.Millisecond})
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
	r := run(t, execx.Spec{Path: p, Args: []string{"flood", "10000000"}, MaxOutput: 1000, Lookahead: 100})
	if !r.StdoutTruncated || len(r.Stdout) > 1100 || r.OutputCeilingHit || r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("cap: truncated=%v len=%d ceiling=%v exit=%v", r.StdoutTruncated, len(r.Stdout), r.OutputCeilingHit, r.ExitCode)
	}
	r = run(t, execx.Spec{Path: p, Args: []string{"flood-err", "5000"}, MaxOutput: 1000, Lookahead: 100})
	if !r.StderrTruncated || r.StdoutTruncated || len(r.Stderr) > 1100 {
		t.Fatalf("stderr cap: %+v", r.StderrTruncated)
	}
	r = run(t, execx.Spec{Path: p, Args: []string{"echo", "short"}, MaxOutput: 1000})
	if r.StdoutTruncated || string(r.Stdout) != "short\n" {
		t.Fatalf("short: %+v", r)
	}
}

func TestHardCeilingKills(t *testing.T) {
	p := probePath(t)
	start := time.Now()
	r := run(t, execx.Spec{Path: p, Args: []string{"flood", "100000000000"}, MaxOutput: 1000, HardCeiling: 1 << 20})
	if !r.OutputCeilingHit || !r.StdoutTruncated || len(r.Stdout) > 1000+execx.DefaultLookahead {
		t.Fatalf("ceiling %+v", r.OutputCeilingHit)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestChildRlimits(t *testing.T) {
	p := probePath(t)
	r := run(t, execx.Spec{Path: p, Args: []string{"rlimits"}})
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
}

func TestStartFailure(t *testing.T) {
	_, err := execx.Run(context.Background(), execx.Spec{Path: "/nonexistent/binary", Timeout: time.Second, MaxOutput: 10, Env: execx.Environment("/")})
	if !errors.Is(err, execx.ErrStart) {
		t.Fatalf("err %v", err)
	}
	if _, err := execx.Run(context.Background(), execx.Spec{Path: "relative", Timeout: time.Second, MaxOutput: 10}); !errors.Is(err, execx.ErrStart) {
		t.Fatalf("relative path: %v", err)
	}
}
