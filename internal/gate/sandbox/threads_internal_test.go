//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/procself"
)

// fakeTasks lays out dir/task/<tid>/status like /proc/<pid> (invented
// values; "" for a thread that ended, which has no status file).
func fakeTasks(t *testing.T, dir string, status map[string]string) {
	t.Helper()
	for tid, s := range status {
		if err := os.MkdirAll(filepath.Join(dir, "task", tid), 0o700); err != nil {
			t.Fatal(err)
		}
		if s == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "task", tid, "status"), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// openProc opens dir as the thread check's /proc/<pid>.
func openProc(t *testing.T, dir string) *procself.Dir {
	t.Helper()
	d, err := procself.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

const goodStatus = "Name:\tgate\nNoNewPrivs:\t1\nSeccomp:\t2\n"

// TestAllThreadsNoNewPrivsIn: the self-check reads every thread's status.
// A thread that ended between the listing and the read (no status file) is
// skipped; a status file that exists but cannot be read is an error, never
// a thread checked; a thread without NoNewPrivs or the seccomp filter is an
// error; and having checked no thread at all is an error. Invented task
// directories.
func TestAllThreadsNoNewPrivsIn(t *testing.T) {
	tasks := func(t *testing.T, status map[string]string) *procself.Dir {
		t.Helper()
		d := t.TempDir()
		fakeTasks(t, d, status)
		return openProc(t, d)
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": goodStatus, "11": goodStatus, "12": ""}), true); err != nil {
		t.Fatalf("every live thread under no_new_privs and the filter: %v", err)
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": goodStatus, "11": "NoNewPrivs:\t0\nSeccomp:\t2\n"}), true); err == nil {
		t.Fatal("a thread without NoNewPrivs passed")
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": goodStatus, "11": "NoNewPrivs:\t1\nSeccomp:\t0\n"}), true); err == nil {
		t.Fatal("a thread without the seccomp filter passed")
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": "", "11": ""}), true); err == nil {
		t.Fatal("no thread checked at all passed")
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"x": goodStatus}), true); err == nil || !strings.Contains(err.Error(), "not a thread id") {
		t.Fatalf("a task entry that is not a thread id: %v", err)
	}
	if err := allThreadsNoNewPrivsIn(openProc(t, t.TempDir()), true); err == nil {
		t.Fatal("a missing task directory passed")
	}
	if os.Getuid() != 0 {
		d := t.TempDir()
		fakeTasks(t, d, map[string]string{"10": goodStatus, "11": "NoNewPrivs:\t0\n"})
		if err := os.Chmod(filepath.Join(d, "task", "11", "status"), 0); err != nil {
			t.Fatal(err)
		}
		err := allThreadsNoNewPrivsIn(openProc(t, d), true)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("a live thread whose status cannot be read: %v (it must fail, with the errno)", err)
		}
	}
}

// TestAllThreadsNoNewPrivsThroughDescriptor: the check reads the directory
// it was given, opened before the sandbox, not what its path names
// afterwards. In the core unit that path, after memory pressure, reaches
// the helper's /proc/<pid> through a new procfs inode its Landlock rule
// does not cover (procself). Here the path is renamed away and replaced by
// a directory whose threads would fail the check.
func TestAllThreadsNoNewPrivsThroughDescriptor(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "proc-1234")
	fakeTasks(t, dir, map[string]string{"10": goodStatus, "11": goodStatus})
	d := openProc(t, dir)
	if err := os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	fakeTasks(t, dir, map[string]string{"10": "NoNewPrivs:\t0\nSeccomp:\t0\n"})
	if err := allThreadsNoNewPrivsIn(d, true); err != nil {
		t.Fatalf("the check read the path, not the descriptor: %v", err)
	}
}
