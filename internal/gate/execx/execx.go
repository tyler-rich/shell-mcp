//go:build linux

// Package execx is the gate's (and the helper's) execve engine: an absolute
// path, an exact argv and environment, a new process group with
// Pdeathsig=SIGKILL, per-child rlimits, bounded stdin, capped output on two
// pipes, and SIGTERM→SIGKILL on the process group at the timeout. It never
// uses a shell or a PATH search, and it inherits nothing from the caller's
// environment.
package execx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Defaults.
const (
	DefaultLookahead   = 64 << 10 // bytes kept past the cap so redaction sees secrets straddling it
	DefaultHardCeiling = 64 << 20 // bytes drained per stream before the group is killed
	DefaultKillGrace   = 2 * time.Second
	// ChildNofile is the RLIMIT_NOFILE applied to every child.
	ChildNofile = 1024
	// ChildExtraTasks bounds how many tasks a child and its descendants may
	// add to the service user's count (RLIMIT_NPROC = current + this).
	ChildExtraTasks = 256
	// maxProcScan bounds the /proc walk that counts the user's tasks.
	maxProcScan = 1 << 16
)

// Spec describes one process.
type Spec struct {
	Path        string   // absolute, already resolved
	Args        []string // argv[1:]; argv[0] is always Path
	Env         []string // the exact environment
	Dir         string   // working directory (real path); "" means "/"
	Stdin       []byte   // nil means /dev/null
	Timeout     time.Duration
	MaxOutput   int           // per stream
	Lookahead   int           // 0 means DefaultLookahead
	HardCeiling int64         // 0 means DefaultHardCeiling
	KillGrace   time.Duration // 0 means DefaultKillGrace
}

// Result reports what happened. Stdout and Stderr hold at most
// MaxOutput+Lookahead bytes; the caller redacts and cuts them to MaxOutput.
type Result struct {
	ExitCode         *int
	Signal           string
	TimedOut         bool
	Stdout           []byte
	Stderr           []byte
	StdoutTruncated  bool
	StderrTruncated  bool
	OutputCeilingHit bool
	Duration         time.Duration
}

// ErrStart is returned (wrapped) when the process could not be started.
var ErrStart = errors.New("process could not be started")

// Environment returns the exact child environment (POLICY §4).
func Environment(home string) []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"HOME=" + home,
		"PAGER=cat",
		"SYSTEMD_PAGER=",
		"SYSTEMD_COLORS=0",
		"GIT_TERMINAL_PROMPT=0",
		"NO_COLOR=1",
		"TERM=dumb",
	}
}

var errCeiling = errors.New("output ceiling exceeded")

// capWriter keeps the first keep bytes, counts the rest, and past the hard
// ceiling kills the process group and stops the copy.
type capWriter struct {
	mu        sync.Mutex
	keep      int
	ceiling   int64
	buf       []byte
	total     int64
	hit       bool
	onCeiling func()
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(p))
	if room := w.keep - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}
	if w.total > w.ceiling {
		if !w.hit {
			w.hit = true
			w.onCeiling()
		}
		return len(p), errCeiling
	}
	return len(p), nil
}

func (w *capWriter) result(limit int) (out []byte, truncated, hit bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf), w.total > int64(limit), w.hit
}

// Run starts the process and waits for it. The error is non-nil only if
// the process could not be started; everything after that is in Result.
//
// Timeout: SIGTERM to the process group, KillGrace, then SIGKILL to the
// child (os/exec) and to the whole group. After the child exits, WaitDelay
// bounds how long pipes held open by grandchildren can delay Wait, and the
// group is always sent SIGKILL so nothing the command started outlives it.
func Run(ctx context.Context, spec *Spec) (Result, error) {
	sc := *spec // defaults below must not change the caller's Spec
	s := &sc
	if !filepath.IsAbs(s.Path) {
		return Result{}, fmt.Errorf("%w: path is not absolute", ErrStart)
	}
	if s.Lookahead == 0 {
		s.Lookahead = DefaultLookahead
	}
	if s.HardCeiling == 0 {
		s.HardCeiling = DefaultHardCeiling
	}
	if s.KillGrace == 0 {
		s.KillGrace = DefaultKillGrace
	}
	dir := s.Dir
	if dir == "" {
		dir = "/"
	}
	env := s.Env
	if env == nil {
		env = []string{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// An absolute path: exec.CommandContext does no PATH lookup.
	cmd := exec.CommandContext(ctx, s.Path, s.Args...) //nolint:gosec // G204: the path is resolved and ownership-checked at policy load and the argv matched a policy template; no shell is involved
	cmd.Env = env
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}

	var pgid atomic.Int64
	killGroup := func(sig syscall.Signal) {
		if p := pgid.Load(); p > 0 {
			_ = syscall.Kill(-int(p), sig)
		}
	}
	keep := s.MaxOutput + s.Lookahead
	stdout := &capWriter{keep: keep, ceiling: s.HardCeiling, onCeiling: func() { killGroup(syscall.SIGKILL) }}
	stderr := &capWriter{keep: keep, ceiling: s.HardCeiling, onCeiling: func() { killGroup(syscall.SIGKILL) }}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if s.Stdin != nil {
		cmd.Stdin = bytes.NewReader(s.Stdin)
	}
	var timedOut atomic.Bool
	cmd.Cancel = func() error {
		timedOut.Store(true)
		killGroup(syscall.SIGTERM)
		return nil
	}
	cmd.WaitDelay = s.KillGrace

	start := time.Now()
	if err := cmd.Start(); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return Result{}, fmt.Errorf("%w: %s", ErrStart, unix.ErrnoName(errno))
		}
		return Result{}, fmt.Errorf("%w", ErrStart)
	}
	pid := cmd.Process.Pid
	pgid.Store(int64(pid)) // Setpgid: the child leads its own group
	applyChildRlimits(pid)
	_ = cmd.Wait()
	killGroup(syscall.SIGKILL)

	var r Result
	r.Duration = time.Since(start)
	r.TimedOut = timedOut.Load()
	var hitOut, hitErr bool
	r.Stdout, r.StdoutTruncated, hitOut = stdout.result(s.MaxOutput)
	r.Stderr, r.StderrTruncated, hitErr = stderr.result(s.MaxOutput)
	r.OutputCeilingHit = hitOut || hitErr
	if ps := cmd.ProcessState; ps != nil {
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
			switch {
			case ws.Exited():
				code := ws.ExitStatus()
				r.ExitCode = &code
			case ws.Signaled():
				r.Signal = unix.SignalName(ws.Signal())
			}
		}
	}
	return r, nil
}

// applyChildRlimits lowers the child's limits with prlimit(2) right after
// it started (os/exec has no pre-exec hook, and setting them on the gate
// itself would also constrain the gate's own threads): no core dumps,
// RLIMIT_NOFILE ≤ ChildNofile, and RLIMIT_NPROC = the service user's
// current task count + ChildExtraTasks. RLIMIT_NPROC counts every task of
// the real uid, so a fixed value would fail concurrent gates; relative to
// the current count it bounds what one command can add. Lowering needs no
// privilege; failures (the child already exited) are ignored.
func applyChildRlimits(pid int) {
	_ = unix.Prlimit(pid, unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}, nil)
	lowerTo(pid, unix.RLIMIT_NOFILE, ChildNofile)
	if n := userTasks(os.Getuid()); n > 0 {
		lowerTo(pid, unix.RLIMIT_NPROC, n+ChildExtraTasks)
	}
}

func lowerTo(pid, res int, v uint64) {
	var cur unix.Rlimit
	if err := unix.Prlimit(pid, res, nil, &cur); err != nil {
		return
	}
	nl := unix.Rlimit{Cur: min(cur.Cur, v), Max: min(cur.Max, v)}
	_ = unix.Prlimit(pid, res, &nl, nil)
}

// userTasks counts the tasks (threads) whose real uid is uid, from
// /proc/<pid>/status. It returns 0 if /proc cannot be read or the scan
// would exceed its bound.
func userTasks(uid int) uint64 {
	d, err := os.Open("/proc")
	if err != nil {
		return 0
	}
	defer func() { _ = d.Close() }()
	names, err := d.Readdirnames(maxProcScan + 1)
	if err != nil || len(names) > maxProcScan {
		return 0
	}
	want := strconv.Itoa(uid)
	var total uint64
	for _, n := range names {
		if n == "" || n[0] < '0' || n[0] > '9' {
			continue
		}
		f, err := os.Open("/proc/" + n + "/status") //nolint:gosec // G304: n is a numeric /proc entry name
		if err != nil {
			continue
		}
		var mine bool
		var threads uint64
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			switch k {
			case "Uid":
				fields := strings.Fields(v)
				mine = len(fields) > 0 && fields[0] == want
			case "Threads":
				threads, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			}
		}
		_ = f.Close()
		if mine {
			total += threads
		}
	}
	return total
}
