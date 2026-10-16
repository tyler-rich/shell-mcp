//go:build linux

// Command probe is a test child for the gate's exec and sandbox tests. It is
// built by the tests (CGO_ENABLED=0) and declared as a policy command; it is
// never part of a release. Every subcommand prints one result line.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// outside is set with -ldflags "-X main.outside=…": a path the gate's
// userspace checks never see.
var outside = ""

// The main goroutine stays on the main thread for the probe's lifetime
// (runtime.LockOSThread: called from an init function, main runs on that
// thread). Per-thread state such as the parent-death signal is then read
// where execve(2) left it, not on whichever thread the runtime picked.
func init() { runtime.LockOSThread() }

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage")
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "echo":
		fmt.Println(strings.Join(args, "\n"))
	case "env":
		env := os.Environ()
		sort.Strings(env)
		fmt.Println(strings.Join(env, "\n"))
	case "pwd":
		wd, _ := os.Getwd()
		fmt.Println(wd)
	case "stdin":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "exit":
		n, _ := strconv.Atoi(args[0])
		os.Exit(n)
	case "flood":
		n, _ := strconv.ParseInt(args[0], 10, 64)
		flood(os.Stdout, n)
	case "flood-err":
		n, _ := strconv.ParseInt(args[0], 10, 64)
		flood(os.Stderr, n)
	case "sleep":
		sleep(args[0])
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		sleep(args[0])
	case "drop-ignore-term":
		// Ignores SIGTERM, switches to uid and gid args[0] with no
		// supplementary groups (all threads: Go applies these to every
		// thread), and sleeps for args[1]. The credential change clears its
		// parent-death signal (commit_creds).
		signal.Ignore(syscall.SIGTERM)
		id, _ := strconv.Atoi(args[0])
		if err := syscall.Setgroups(nil); err != nil {
			report(err, "")
			os.Exit(1)
		}
		if err := syscall.Setresgid(id, id, id); err != nil {
			report(err, "")
			os.Exit(1)
		}
		if err := syscall.Setresuid(id, id, id); err != nil {
			report(err, "")
			os.Exit(1)
		}
		sleep(args[1])
	case "fork-sleep":
		// A grandchild in the same process group; print its pid, then sleep.
		pid := spawn("sleep", args[0])
		fmt.Println(pid)
		sleep(args[0])
	case "orphan":
		// A grandchild that inherits stdout and outlives this process.
		pid := spawn("sleep", args[0])
		fmt.Println(pid)
	case "read-outside":
		b, err := os.ReadFile(outside)
		report(err, "READ:"+strings.TrimSpace(string(b)))
	case "write":
		report(os.WriteFile(args[0], []byte("probe"), 0o600), "WROTE")
	case "nnp":
		fmt.Println(statusField("NoNewPrivs"))
	case "connect":
		c, err := net.DialTimeout("tcp4", "127.0.0.1:"+args[0], 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		report(err, "CONNECTED")
	case "bind":
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			_ = l.Close()
		}
		report(err, "BOUND")
	case "mptcp":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP)
		if err == nil {
			_ = unix.Close(fd)
		}
		report(err, "OPENED")
	case "signal":
		pid, _ := strconv.Atoi(args[0])
		report(syscall.Kill(pid, syscall.SIGTERM), "SIGNALLED")
	case "status":
		// Diagnostics: this process's credentials, capability sets,
		// NoNewPrivs and seccomp mode, and how its /proc is mounted.
		for _, k := range []string{"Uid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"} {
			fmt.Println(statusField(k))
		}
		if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if f := strings.Fields(l); len(f) > 4 && (f[4] == "/proc" || f[4] == "/run") {
					fmt.Println("mount:", l)
				}
			}
		}
	case "read-environ":
		// Another process's environment: reports only its size and whether
		// the e2e canary is in it, never the content.
		b, err := os.ReadFile("/proc/" + args[0] + "/environ")
		canary := ""
		if strings.Contains(string(b), "E2E_ENV_CANARY=") {
			canary = " CANARY"
		}
		report(err, fmt.Sprintf("READ:%d%s", len(b), canary))
	case "visible":
		// Whether /proc shows the process (ProtectProc=, hidepid).
		_, err := os.Stat("/proc/" + args[0])
		report(err, "VISIBLE")
	case "unix-connect":
		c, err := net.DialTimeout("unix", args[0], 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		report(err, "CONNECTED")
	case "abstract-connect":
		// An abstract Unix socket (a name, not a file), which belongs to a
		// network namespace.
		c, err := net.DialTimeout("unix", "@"+args[0], 2*time.Second)
		if err == nil {
			_ = c.Close()
		}
		report(err, "CONNECTED")
	case "procattrs":
		// What a command inherits from how it was started: open
		// descriptors above stderr (with their type; checked first, before
		// this program opens anything), its parent-death signal, whether
		// it leads its process group, and its blocked signals.
		var fds []string
		for fd := 3; fd < 1024; fd++ {
			var st unix.Stat_t
			if unix.Fstat(fd, &st) == nil {
				target, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
				fds = append(fds, fmt.Sprintf("%d:%o:%s", fd, st.Mode&unix.S_IFMT, target))
			}
		}
		// The parent-death signal is per thread (PR_GET_PDEATHSIG reads the
		// calling thread's; a thread the Go runtime starts has none), and
		// execve left it on the main thread. Other goroutines keep the
		// processors busy first, so a read from anywhere but the main
		// thread shows up as such.
		yieldThreads()
		sig, thread := pdeathsig()
		pgid, _ := unix.Getpgid(0)
		// prctl, not /proc: a sandbox may hide /proc/self.
		nnp, _ := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		seccomp, _ := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
		fmt.Printf("fds=%s\n", strings.Join(fds, ","))
		fmt.Printf("pdeathsig=%d\n", sig)
		fmt.Printf("pdeathsig_thread=%s\n", thread)
		fmt.Printf("pgid_is_pid=%v\n", pgid == os.Getpid())
		fmt.Printf("nnp=%d\n", nnp)
		fmt.Printf("seccomp=%d\n", seccomp)
		// The main thread's mask, as execve left it (Go keeps it).
		sigblk := "unreadable"
		b, _ := os.ReadFile("/proc/self/status")
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "SigBlk:"); ok {
				sigblk = strings.TrimSpace(v)
			}
		}
		fmt.Printf("sigblk=%s\n", sigblk)
	case "pdeathsig-threads":
		// The parent-death signal as the main thread holds it and as
		// another thread of this process holds it.
		runtime.LockOSThread()
		sig, thread := pdeathsig()
		other, otherThread := make(chan int32), make(chan string)
		go func() {
			// Locked to a thread of its own while the main goroutine
			// holds the main thread, and ended with it: the runtime
			// retires a thread whose goroutine exits locked.
			runtime.LockOSThread()
			s, th := pdeathsig()
			other <- s
			otherThread <- th
		}()
		fmt.Printf("main=%d %s\n", sig, thread)
		fmt.Printf("other=%d %s\n", <-other, <-otherThread)
	case "rlimits":
		for _, r := range []struct {
			name string
			res  int
		}{{"core", unix.RLIMIT_CORE}, {"nofile", unix.RLIMIT_NOFILE}, {"nproc", unix.RLIMIT_NPROC}} {
			var l unix.Rlimit
			_ = unix.Getrlimit(r.res, &l)
			fmt.Printf("%s=%d/%d\n", r.name, l.Cur, l.Max)
		}
	default:
		fmt.Println("unknown")
		os.Exit(2)
	}
}

func flood(w io.Writer, n int64) {
	buf := make([]byte, 64<<10)
	for i := range buf {
		buf[i] = 'x'
	}
	for n > 0 {
		k := min(n, int64(len(buf)))
		if _, err := w.Write(buf[:k]); err != nil {
			os.Exit(0)
		}
		n -= k
	}
}

// pdeathsig returns the calling thread's parent-death signal and whether
// that thread is the main thread ("main") or not ("other").
func pdeathsig() (int32, string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var sig int32
	_ = unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&sig)), 0, 0, 0)
	if unix.Gettid() == os.Getpid() {
		return sig, "main"
	}
	return sig, "other"
}

// yieldThreads sleeps a few times while other goroutines keep up to four
// processors busy: a goroutine that is not locked to its thread then
// usually resumes on another one.
func yieldThreads() {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), 4) {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					runtime.Gosched()
				}
			}
		})
	}
	for range 5 {
		time.Sleep(200 * time.Microsecond)
	}
	close(stop)
	wg.Wait()
}

func sleep(s string) {
	d, _ := time.ParseDuration(s)
	time.Sleep(d)
}

func spawn(args ...string) int {
	self, _ := os.Executable()
	cmd := exec.Command(self, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Println("spawn failed:", err)
		os.Exit(1)
	}
	return cmd.Process.Pid
}

// report prints ok on success, else the errno name (EACCES, EPERM, …).
func report(err error, ok string) {
	if err == nil {
		fmt.Println(ok)
		return
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fmt.Println(unix.ErrnoName(errno))
		return
	}
	fmt.Println("ERR:", err)
}

func statusField(name string) string {
	f, err := os.Open("/proc/thread-self/status")
	if err != nil {
		return "ERR"
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if k, v, ok := strings.Cut(s.Text(), ":"); ok && k == name {
			return name + ": " + strings.TrimSpace(v)
		}
	}
	return "MISSING"
}
