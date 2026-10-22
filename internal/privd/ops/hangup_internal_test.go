//go:build linux

package ops

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestConnHungUpRetriesEINTR: poll(2) is never restarted after a signal
// handler, whatever SA_RESTART says (signal(7)), and the Go runtime's own
// signals (goroutine preemption) can interrupt it. An interrupted poll must
// not be read as "the gate is still there": connHungUp polls again. Not
// parallel: it replaces pollFn.
func TestConnHungUpRetriesEINTR(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "helper")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = unix.Close(fds[1]) // the gate went away
	calls := 0
	old := pollFn
	pollFn = func(p []unix.PollFd, timeout int) (int, error) {
		calls++
		if calls == 1 {
			return -1, unix.EINTR
		}
		return old(p, timeout)
	}
	defer func() { pollFn = old }()
	if !connHungUp(c) {
		t.Fatalf("an interrupted poll was read as a gate still there (%d poll calls)", calls)
	}
	// Control: an open connection with nothing on it is not a hang-up.
	pollFn = old
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if connHungUp(a) {
		t.Fatal("a pipe without a syscall conn read as hung up")
	}
}
