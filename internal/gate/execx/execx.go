//go:build linux

// Package execx is the gate's (and the helper's) execve engine: an absolute
// path, an exact argv and environment, a new process group with
// Pdeathsig=SIGKILL, per-child rlimits in force before the command's first
// instruction (applied by a re-exec trampoline, trampoline.go), bounded
// stdin, capped output on two pipes, and SIGTERM→SIGKILL on the process
// group at the timeout. It never uses a shell or a PATH search, and it
// inherits nothing from the caller's environment.
package execx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	// MaxMemoryMB bounds Spec.MaxMemoryMB (the policies' own ceiling,
	// limits.max_memory_mb ≤ 16384).
	MaxMemoryMB = 16384
	// procNonPIDEntries is the room the task count's /proc walk leaves above
	// pid_max for /proc's own entries that are not processes (self, sys,
	// meminfo, …; about 70 on Linux 6.x).
	procNonPIDEntries = 4096
	// procReadChunk is how many /proc entries the walk reads at a time.
	procReadChunk = 4096
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

	// MaxMemoryMB is the command's RLIMIT_DATA, soft and hard, in MiB
	// (the policy's limits.max_memory_mb). Required: Run refuses a Spec
	// without one.
	MaxMemoryMB int

	// Trampoline is the absolute path of the running binary (the gate or
	// the helper, resolved and ownership-checked by the caller). The
	// command is started through it; see trampoline.go.
	Trampoline string

	// Started, when set, is called with the command's process once the
	// trampoline has execve(2)d it (the pid is the command's own, which
	// leads its process group), before Run waits for it. The privileged
	// helper uses it to signal apt-get alone (PRIVILEGED §6); os.Process
	// refuses a signal once Run has waited for the process, so a reused pid
	// is never signalled.
	Started func(*os.Process)
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
	return run(ctx, spec, nil)
}

// hooks are test seams, set only through export_test.go; production passes
// nil.
type hooks struct {
	// afterStart runs in the parent right after the child started.
	afterStart func()
	// procDir replaces /proc for counting the user's tasks.
	procDir string
}

func run(ctx context.Context, spec *Spec, h *hooks) (Result, error) {
	sc := *spec // defaults below must not change the caller's Spec
	s := &sc
	if !filepath.IsAbs(s.Path) {
		return Result{}, fmt.Errorf("%w: path is not absolute", ErrStart)
	}
	// Fail closed: nothing runs without a memory limit (handoff N-30).
	if s.MaxMemoryMB < 1 || s.MaxMemoryMB > MaxMemoryMB {
		return Result{}, fmt.Errorf("%w: no valid memory limit (MaxMemoryMB %d)", ErrStart, s.MaxMemoryMB)
	}
	if !filepath.IsAbs(s.Trampoline) {
		return Result{}, fmt.Errorf("%w: no exec trampoline", ErrStart)
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
	limits, err := childLimits(s.MaxMemoryMB, procDirOf(h))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrStart, err)
	}
	cfg, err := encodeConfig(&trampolineConfig{Path: s.Path, Argv: append([]string{s.Path}, s.Args...), Env: env, Dir: dir, Limits: limits})
	if err != nil {
		return Result{}, startError(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return Result{}, startError(err)
	}
	ctl := os.NewFile(uintptr(fds[0]), "execx-control")
	defer func() { _ = ctl.Close() }()
	childCtl := os.NewFile(uintptr(fds[1]), "execx-control")
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// The trampoline (this binary, resolved and ownership-checked by the
	// caller) applies the child limits to itself and then execve(2)s
	// s.Path, which gets argv, environment and directory from the control
	// socket; see trampoline.go. Both paths are absolute: no PATH lookup.
	cmd := exec.CommandContext(ctx, s.Trampoline, TrampolineArg) //nolint:gosec // G204: the trampoline is the running binary, resolved and ownership-checked by the caller; the command's path was resolved and ownership-checked at policy load and its argv matched a policy template; no shell is involved
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{childCtl}
	// The parent-death signal fires when the thread that forked the child
	// exits (prctl(2)). That thread is whichever one runs this goroutine,
	// and it needs no pinning here: when the gate or helper dies, every
	// thread exits, so the signal always comes; and the Go runtime ends a
	// thread before then only when a goroutine locked to it exits, which
	// nothing in the gate or helper does around Run. The child keeps it on
	// its main thread, which the trampoline's execve keeps.
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
	err = cmd.Start()
	_ = childCtl.Close()
	if err != nil {
		return Result{}, startError(err)
	}
	pgid.Store(int64(cmd.Process.Pid)) // Setpgid: the child leads its own group
	if h != nil && h.afterStart != nil {
		h.afterStart()
	}
	if err := handshake(ctl, cfg); err != nil {
		// The command never ran; only the trampoline is in the group.
		killGroup(syscall.SIGKILL)
		_ = cmd.Wait()
		return Result{}, err
	}
	if s.Started != nil {
		s.Started(cmd.Process)
	}
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

// childLimits are the limits the trampoline puts in force before the
// command's first instruction (setting them on the gate itself would also
// constrain the gate's own threads): no core dumps, RLIMIT_NOFILE ≤
// ChildNofile, and RLIMIT_NPROC = the service user's current task count +
// ChildExtraTasks. RLIMIT_NPROC counts every task of the real uid, so a
// fixed value would fail concurrent gates; relative to the current count it
// bounds what one command can add. RLIMIT_DATA is the policy's
// limits.max_memory_mb (handoff N-30): it bounds the heap and every private
// writable mapping (mmap(2) since Linux 4.7), not read-only file mappings
// such as git's packs. Soft and hard limits are both set, so the command
// cannot raise them without CAP_SYS_RESOURCE. Each is only ever lowered,
// which needs no privilege.
//
// When the tasks cannot be counted, the command is refused rather than
// started without RLIMIT_NPROC (handoff N-30's audit), except for uid 0:
// the kernel never applies RLIMIT_NPROC to root's processes (copy_process
// exempts INIT_USER), and the helper's core unit may read only its own
// /proc/<pid>, so it is not counted there.
func childLimits(memoryMB int, procDir string) ([]childLimit, error) {
	l := []childLimit{{Resource: unix.RLIMIT_CORE, Max: 0}, {Resource: unix.RLIMIT_NOFILE, Max: ChildNofile},
		{Resource: unix.RLIMIT_DATA, Max: uint64(memoryMB) << 20}} //nolint:gosec // G115: memoryMB is checked to be 1..MaxMemoryMB by run
	if uid := os.Getuid(); uid != 0 {
		n, err := userTasksIn(procDir, uid)
		if err != nil {
			return nil, fmt.Errorf("cannot count the user's tasks for RLIMIT_NPROC: %w", err)
		}
		l = append(l, childLimit{Resource: unix.RLIMIT_NPROC, Max: n + ChildExtraTasks})
	}
	return l, nil
}

// handshake sends the encoded command to the trampoline, closes the
// sending direction, and reads the outcome: the accepted byte then EOF when
// the execve succeeded (fd 3 is close-on-exec), the accepted byte and an
// errno when the command could not be started, and nothing when the
// trampoline refused or died first.
func handshake(ctl *os.File, cfg []byte) error {
	refused := fmt.Errorf("%w: the exec trampoline did not start the command", ErrStart)
	if _, err := ctl.Write(cfg); err != nil {
		return refused
	}
	rc, err := ctl.SyscallConn()
	if err != nil {
		return refused
	}
	var serr error
	if cerr := rc.Control(func(fd uintptr) { serr = unix.Shutdown(int(fd), unix.SHUT_WR) }); cerr != nil || serr != nil {
		return refused
	}
	st, err := io.ReadAll(io.LimitReader(ctl, 8))
	switch {
	case err != nil || len(st) == 0 || st[0] != statusAccepted:
		return refused
	case len(st) == 1:
		return nil
	case len(st) == 5:
		return startError(syscall.Errno(binary.LittleEndian.Uint32(st[1:])))
	}
	return refused
}

// startError is ErrStart with the errno's name when there is one.
func startError(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Errorf("%w: %s", ErrStart, unix.ErrnoName(errno))
	}
	return fmt.Errorf("%w", ErrStart)
}

// procDirOf is the test hooks' /proc, or /proc.
func procDirOf(h *hooks) string {
	if h != nil && h.procDir != "" {
		return h.procDir
	}
	return "/proc"
}

// userTasks counts uid's tasks under /proc (userTasksIn).
func userTasks(uid int) uint64 {
	n, _ := userTasksIn("/proc", uid)
	return n
}

// userTasksIn counts the tasks (threads) whose real uid is uid, from
// procDir/<pid>/status. A process that went away, or whose status it
// cannot read, is not counted (a lower count only lowers RLIMIT_NPROC). The
// scan is bounded by the kernel's own limit on processes, pid_max
// (procDir/sys/kernel/pid_max), plus procNonPIDEntries for /proc's other
// entries, and it reads procDir in chunks; a pid_max it cannot read, a
// procDir it cannot list, or more entries than that bound is an error
// naming the reason, never a count of 0.
func userTasksIn(procDir string, uid int) (uint64, error) {
	b, err := os.ReadFile(procDir + "/sys/kernel/pid_max") //nolint:gosec // G304: /proc's own, or the tests' own directory
	if err != nil {
		return 0, fmt.Errorf("pid_max: %w", err)
	}
	pidMax, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || pidMax == 0 {
		return 0, fmt.Errorf("pid_max is %q, not a process count", strings.TrimSpace(string(b)))
	}
	bound := pidMax + procNonPIDEntries
	d, err := os.Open(procDir) //nolint:gosec // G304: /proc, or the tests' own directory
	if err != nil {
		return 0, err
	}
	defer func() { _ = d.Close() }()
	want := strconv.Itoa(uid)
	var total, seen uint64
	for {
		names, rerr := d.Readdirnames(procReadChunk)
		seen += uint64(len(names))
		if seen > bound {
			return 0, fmt.Errorf("%s has more than %d entries (pid_max %d)", procDir, bound, pidMax)
		}
		for _, n := range names {
			total += taskCount(procDir, n, want)
		}
		if errors.Is(rerr, io.EOF) || (rerr == nil && len(names) == 0) {
			return total, nil
		}
		if rerr != nil {
			return 0, rerr
		}
	}
}

// taskCount is the Threads of procDir/<n>/status when n is a process whose
// real uid is uid, else 0 (also for one that went away or cannot be read).
func taskCount(procDir, n, uid string) uint64 {
	if n == "" || n[0] < '0' || n[0] > '9' {
		return 0
	}
	f, err := os.Open(procDir + "/" + n + "/status") //nolint:gosec // G304: n is a numeric /proc entry name
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
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
			mine = len(fields) > 0 && fields[0] == uid
		case "Threads":
			threads, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	if !mine {
		return 0
	}
	return threads
}
