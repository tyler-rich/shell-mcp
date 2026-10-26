//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllThreadsNoNewPrivsIn: the self-check reads every thread's status.
// A thread that ended between the listing and the read (no status file) is
// skipped; a status file that exists but cannot be read is an error, never
// a thread checked; a thread without NoNewPrivs or the seccomp filter is an
// error; and having checked no thread at all is an error. Invented task
// directories.
func TestAllThreadsNoNewPrivsIn(t *testing.T) {
	good := "Name:\tgate\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	tasks := func(t *testing.T, status map[string]string) string {
		t.Helper()
		d := t.TempDir()
		for tid, s := range status {
			if err := os.MkdirAll(filepath.Join(d, tid), 0o700); err != nil {
				t.Fatal(err)
			}
			if s == "" { // the thread ended: no status file
				continue
			}
			if err := os.WriteFile(filepath.Join(d, tid, "status"), []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": good, "11": good, "12": ""}), true); err != nil {
		t.Fatalf("every live thread under no_new_privs and the filter: %v", err)
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": good, "11": "NoNewPrivs:\t0\nSeccomp:\t2\n"}), true); err == nil {
		t.Fatal("a thread without NoNewPrivs passed")
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": good, "11": "NoNewPrivs:\t1\nSeccomp:\t0\n"}), true); err == nil {
		t.Fatal("a thread without the seccomp filter passed")
	}
	if err := allThreadsNoNewPrivsIn(tasks(t, map[string]string{"10": "", "11": ""}), true); err == nil {
		t.Fatal("no thread checked at all passed")
	}
	if err := allThreadsNoNewPrivsIn(filepath.Join(t.TempDir(), "missing"), true); err == nil {
		t.Fatal("a missing task directory passed")
	}
	if os.Getuid() != 0 {
		d := tasks(t, map[string]string{"10": good, "11": "NoNewPrivs:\t0\n"})
		if err := os.Chmod(filepath.Join(d, "11", "status"), 0); err != nil {
			t.Fatal(err)
		}
		err := allThreadsNoNewPrivsIn(d, true)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("a live thread whose status cannot be read: %v (it must fail, with the errno)", err)
		}
	}
}
