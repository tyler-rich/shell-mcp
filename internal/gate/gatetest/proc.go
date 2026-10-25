//go:build linux

package gatetest

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Proc identifies a process by pid and start time (field 22 of
// /proc/<pid>/stat), so a reused pid is never taken for it.
type Proc struct {
	Pid   int
	start string
}

// procStat returns pid's state, parent pid and start time, or ok=false when
// /proc no longer has it.
func procStat(pid int) (state string, ppid int, start string, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, "", false
	}
	// The command name, field 2, is in parentheses and may hold anything.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", 0, "", false
	}
	f := strings.Fields(string(b[i+1:])) // f[0] is field 3
	if len(f) < 20 {
		return "", 0, "", false
	}
	ppid, _ = strconv.Atoi(f[1])
	return f[0], ppid, f[19], true
}

// FindChild waits up to 10 s for a child of parent (any process when
// parent is 0) whose arguments after argv[0] are args, and returns it.
func FindChild(t testing.TB, parent int, args ...string) Proc {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		ents, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			_, ppid, start, ok := procStat(pid)
			if !ok || (parent != 0 && ppid != parent) {
				continue
			}
			b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
			if err != nil {
				continue
			}
			argv := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
			if len(argv) > 0 && slices.Equal(argv[1:], args) {
				return Proc{Pid: pid, start: start}
			}
		}
	}
	t.Fatalf("no child of pid %d with arguments %q", parent, args)
	return Proc{}
}

// Alive reports whether p still runs: present in /proc with the same start
// time and not a zombie.
func (p Proc) Alive() bool {
	state, _, start, ok := procStat(p.Pid)
	return ok && start == p.start && state != "Z" && state != "X"
}

// Reaped reports whether p is gone from /proc altogether: not even a
// zombie waiting to be reaped (its pid absent, or reused by a process with
// another start time).
func (p Proc) Reaped() bool {
	_, _, start, ok := procStat(p.Pid)
	return !ok || start != p.start
}

// WaitReaped reports whether p is gone from /proc (Reaped) within d.
func (p Proc) WaitReaped(d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if p.Reaped() {
			return true
		}
	}
	return p.Reaped()
}

// Parent returns p's parent pid, or 0 once it is gone.
func (p Proc) Parent() int {
	_, ppid, start, ok := procStat(p.Pid)
	if !ok || start != p.start {
		return 0
	}
	return ppid
}

// WaitIgnoring waits up to 10 s until p ignores sig (SigIgn in
// /proc/<pid>/status).
func (p Proc) WaitIgnoring(t testing.TB, sig syscall.Signal) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(p.Pid) + "/status")
		if err != nil {
			break
		}
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "SigIgn:"); ok {
				if m, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64); err == nil && m&(1<<(uint(sig)-1)) != 0 {
					return
				}
			}
		}
	}
	t.Fatalf("pid %d does not ignore %v", p.Pid, sig)
}

// WaitGone reports whether p has stopped running within d.
func (p Proc) WaitGone(d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if !p.Alive() {
			return true
		}
	}
	return !p.Alive()
}

// Kill sends SIGKILL to p if it still runs (test cleanup).
func (p Proc) Kill() {
	if p.Alive() {
		_ = syscall.Kill(p.Pid, syscall.SIGKILL)
	}
}
