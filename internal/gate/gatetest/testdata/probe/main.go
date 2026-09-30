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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// outside is set with -ldflags "-X main.outside=…": a path the gate's
// userspace checks never see.
var outside = ""

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
