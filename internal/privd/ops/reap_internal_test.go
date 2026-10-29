//go:build linux

package ops

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/procself"
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
	onKill func(pid int) (leaves []int, dies bool)
	// listErr is what a failing listing returns: every listing when
	// failAll, else the first failLists of them.
	listErr   error
	failAll   bool
	failLists int
}

func (f *fakeChildren) list() ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll {
		return nil, f.listErr
	}
	if f.failLists > 0 {
		f.failLists--
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

// one is f's listing alone.
func (f *fakeChildren) one() []func() ([]int, error) { return []func() ([]int, error){f.list} }

// TestReapOrphans: the rounds go on until no child is left, so a child
// forked by one being killed is killed in the next round; a listing that
// fails is tried again within the bound, and the next listing that works
// (the fallback, or the first again) is used; success needs wait4's ECHILD
// (no child left), which a failed listing does not change; reapOrphans
// fails closed, with the last listing's real error, when the children
// cannot be listed while some are left, or outlive the bound. Not
// parallel: it bounds how long reapOrphans takes to give up.
func TestReapOrphans(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		f := &fakeChildren{}
		if err := reapOrphans(time.Second, f.one(), f.kill, f.wait); err != nil {
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
		if err := reapOrphans(time.Second, f.one(), f.kill, f.wait); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(f.killed, []int{100, 101, 102, 103}) || len(f.live)+len(f.dead) != 0 {
			t.Fatalf("killed %v, left live %v dead %v", f.killed, f.live, f.dead)
		}
	})
	t.Run("the children cannot be listed while one is left", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}, listErr: errors.New("open /proc/self/task: permission denied"), failAll: true}
		start := time.Now()
		err := reapOrphans(200*time.Millisecond, f.one(), f.kill, f.wait)
		if err == nil {
			t.Fatal("an unreadable children list was a success while a child was left")
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("the error does not carry the listing's: %v", err)
		}
		if d := time.Since(start); d < 150*time.Millisecond {
			t.Fatalf("gave up after %v, before the 200 ms bound: the listing was not tried again", d)
		}
	})
	t.Run("a failed listing then ECHILD", func(t *testing.T) {
		// wait4 reports that no child is left: the kernel has confirmed it.
		f := &fakeChildren{listErr: errors.New("injected"), failAll: true}
		if err := reapOrphans(time.Second, f.one(), f.kill, f.wait); err != nil {
			t.Fatalf("ECHILD after a failed listing: %v", err)
		}
	})
	t.Run("a listing that fails once", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}, listErr: errors.New("injected"), failLists: 1}
		if err := reapOrphans(time.Second, f.one(), f.kill, f.wait); err != nil {
			t.Fatalf("a listing that failed once: %v", err)
		}
		if !slices.Equal(f.killed, []int{100}) || len(f.live)+len(f.dead) != 0 {
			t.Fatalf("killed %v, left live %v dead %v", f.killed, f.live, f.dead)
		}
	})
	t.Run("the fallback finds a live child", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}}
		broken := func() ([]int, error) { return nil, errors.New("no /proc/self/task/*/children file could be read") }
		if err := reapOrphans(time.Second, []func() ([]int, error){broken, f.list}, f.kill, f.wait); err != nil {
			t.Fatalf("with a working fallback: %v", err)
		}
		if !slices.Equal(f.killed, []int{100}) || len(f.live)+len(f.dead) != 0 {
			t.Fatalf("the fallback's child was not killed and reaped: killed %v, left live %v dead %v", f.killed, f.live, f.dead)
		}
	})
	t.Run("a child outlives the bound", func(t *testing.T) {
		f := &fakeChildren{live: []int{100}}
		f.onKill = func(int) ([]int, bool) { return nil, false }
		start := time.Now()
		if err := reapOrphans(100*time.Millisecond, f.one(), f.kill, f.wait); err == nil {
			t.Fatal("a child that never ended was a success")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("gave up after %v under a 100 ms bound", d)
		}
	})
}

// fakeTaskDir lays out dir/task/<tid>/children like the helper's own
// /proc/<pid> (invented thread and child ids; nil: a thread that ended,
// with no children file) and opens dir as childrenIn's directory.
func fakeTaskDir(t *testing.T, dir string, kids map[string]*string) *procself.Dir {
	t.Helper()
	for tid, k := range kids {
		if err := os.MkdirAll(filepath.Join(dir, "task", tid), 0o700); err != nil {
			t.Fatal(err)
		}
		if k == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "task", tid, "children"), []byte(*k), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := procself.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func kids(s string) *string { return &s }

// TestChildrenIn: the per-thread children files, with the real error. A
// thread whose directory went away is skipped; an unreadable task
// directory or children file is an error naming it (errno included); no
// readable file at all is an error.
func TestChildrenIn(t *testing.T) {
	dir := t.TempDir()
	d := fakeTaskDir(t, dir, map[string]*string{"10": kids("11 12 "), "13": kids(""), "14": nil})
	got, err := childrenIn(d)
	slices.Sort(got)
	if err != nil || !slices.Equal(got, []int{11, 12}) {
		t.Fatalf("children %v %v", got, err)
	}
	if _, err := childrenIn(fakeTaskDir(t, t.TempDir(), nil)); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("a missing task directory: %v", err)
	}
	if _, err := childrenIn(nil); err == nil {
		t.Fatal("no descriptor was a success")
	}
	if _, err := childrenIn(fakeTaskDir(t, t.TempDir(), map[string]*string{"x": kids("11")})); err == nil || !strings.Contains(err.Error(), "not a thread id") {
		t.Fatalf("a task entry that is not a thread id: %v", err)
	}
	if os.Getuid() != 0 {
		// Unreadable: what Landlock or a permission denies.
		lockedDir := t.TempDir()
		locked := fakeTaskDir(t, lockedDir, map[string]*string{"10": kids("11")})
		if err := os.Chmod(filepath.Join(lockedDir, "task"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(lockedDir, "task"), 0o700) }) //nolint:gosec // G302: the test's own directory, back to its mode for cleanup
		if _, err := childrenIn(locked); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("an unreadable task directory: %v (the error must carry the errno)", err)
		}
		if err := os.Chmod(filepath.Join(dir, "task", "10", "children"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := childrenIn(d); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("an unreadable children file: %v", err)
		}
	}
	if _, err := childrenIn(fakeTaskDir(t, t.TempDir(), map[string]*string{"10": nil})); err == nil {
		t.Fatal("no children file at all was a success")
	}
}

// TestChildrenInPinned: the listing reads the directory opened before the
// sandbox, not what /proc/self names afterwards. In the core unit, after
// memory pressure in the instance (an OOM kill), the path can reach the
// helper's /proc/<pid> through a new procfs inode that its Landlock rule
// does not cover, and every read through it is EACCES (handoff N-32,
// S7-5); here the directory is renamed away and its path replaced by one
// with no children, which a listing through the path would report.
func TestChildrenInPinned(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "proc-1234")
	d := fakeTaskDir(t, dir, map[string]*string{"10": kids("21 22"), "11": kids("23")})
	if err := os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	fakeTaskDir(t, dir, map[string]*string{"10": kids("")})
	got, err := childrenIn(d)
	slices.Sort(got)
	if err != nil || !slices.Equal(got, []int{21, 22, 23}) {
		t.Fatalf("children %v %v: listed through the path, not the descriptor", got, err)
	}
}

// TestChildrenByStatIn: the fallback listing scans <proc>/[0-9]*/stat for
// processes whose parent is ppid (a command name with spaces and
// parentheses included), skips a process that went away, and fails with
// the real error when /proc or a stat file cannot be read.
func TestChildrenByStatIn(t *testing.T) {
	d := t.TempDir()
	stat := func(pid, comm string, ppid int) string {
		return pid + " (" + comm + ") S " + strconv.Itoa(ppid) + " 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n"
	}
	for pid, s := range map[string]string{
		"200": stat("200", "example-probe", 50),
		"201": stat("201", "a (b) c", 50),
		"202": stat("202", "other", 7),
		"50":  stat("50", "shell-mcp-privd", 1),
	} {
		if err := os.MkdirAll(filepath.Join(d, pid), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, pid, "stat"), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"self", "sys", "203"} { // not a pid; a pid that went away
		if err := os.MkdirAll(filepath.Join(d, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := childrenByStatIn(d, 50)
	slices.Sort(got)
	if err != nil || !slices.Equal(got, []int{200, 201}) {
		t.Fatalf("children of 50: %v %v", got, err)
	}
	if _, err := childrenByStatIn(filepath.Join(d, "missing"), 50); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("a missing /proc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(d, "202", "stat"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := childrenByStatIn(d, 50); err == nil {
		t.Fatal("an unparsable stat file was skipped")
	}
	if os.Getuid() != 0 {
		if err := os.WriteFile(filepath.Join(d, "202", "stat"), []byte(stat("202", "other", 7)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(d, "202", "stat"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := childrenByStatIn(d, 50); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("an unreadable stat file: %v", err)
		}
	}
}
