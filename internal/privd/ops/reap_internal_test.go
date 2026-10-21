//go:build linux

package ops

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeChildren is a process table for reapOrphans: live children, dead
// ones not yet reaped, and what a kill does to each pid.
type fakeChildren struct {
	mu     sync.Mutex
	live   []int
	dead   []int
	killed []int
	// onKill, when set, runs on a kill of pid and returns the children it
	// leaves (a child forked meanwhile, reparented to the reaper); a pid it
	// keeps in live never dies (uninterruptible sleep).
	onKill  func(pid int) (leaves []int, dies bool)
	listErr error
}

func (f *fakeChildren) list() ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Concat(f.live, f.dead), nil
}

func (f *fakeChildren) kill(pid int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, pid)
	if !slices.Contains(f.live, pid) {
		return
	}
	leaves, dies := []int(nil), true
	if f.onKill != nil {
		leaves, dies = f.onKill(pid)
	}
	if dies {
		f.live = slices.DeleteFunc(f.live, func(p int) bool { return p == pid })
		f.dead = append(f.dead, pid)
	}
	f.live = append(f.live, leaves...)
}

func (f *fakeChildren) wait() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dead) > 0 {
		pid := f.dead[0]
		f.dead = f.dead[1:]
		return pid, nil
	}
	if len(f.live) > 0 {
		return 0, nil
	}
	return 0, unix.ECHILD
}

// TestReapOrphans: the rounds go on until no child is left, so a child
// forked by one being killed is killed in the next round; reapOrphans fails
// closed when the children cannot be listed or outlive the bound.
func TestReapOrphans(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		f := &fakeChildren{}
		if err := reapOrphans(time.Second, f.list, f.kill, f.wait); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a child forks while it is killed", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}}
		f.onKill = func(pid int) ([]int, bool) {
			if pid < 103 {
				return []int{pid + 1}, true
			}
			return nil, true
		}
		if err := reapOrphans(time.Second, f.list, f.kill, f.wait); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(f.killed, []int{100, 101, 102, 103}) || len(f.live)+len(f.dead) != 0 {
			t.Fatalf("killed %v, left live %v dead %v", f.killed, f.live, f.dead)
		}
	})
	t.Run("the children cannot be listed", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}, listErr: errors.New("permission denied")}
		if err := reapOrphans(time.Second, f.list, f.kill, f.wait); err == nil {
			t.Fatal("an unreadable children list was a success")
		}
		f = &fakeChildren{listErr: errors.New("permission denied")}
		if err := reapOrphans(time.Second, f.list, f.kill, f.wait); err == nil {
			t.Fatal("an unreadable children list was a success, although wait4 found none")
		}
	})
	t.Run("a child outlives the bound", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}}
		f.onKill = func(int) ([]int, bool) { return nil, false }
		start := time.Now()
		if err := reapOrphans(100*time.Millisecond, f.list, f.kill, f.wait); err == nil {
			t.Fatal("a child that never ended was a success")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("gave up after %v under a 100 ms bound", d)
		}
	})
}
