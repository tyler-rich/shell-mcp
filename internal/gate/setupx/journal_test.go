//go:build linux

package setupx_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/setuptest"
)

// TestJournalRollback: after a run that created a directory and a file,
// replaced one and removed another, a rollback leaves the filesystem
// exactly as it was, and a write that failed after its rename is rolled
// back too.
func TestJournalRollback(t *testing.T) {
	f := setuptest.New()
	f.Dir("/etc/ssh", 0o755, 0, 0)
	f.Put("/etc/ssh/old", "previous\n", 0o600, 0, 0)
	f.Put("/etc/ssh/gone", "removed\n", 0o640, 0, 4)
	before := f.Snapshot()
	j := setupx.NewJournal(f, nil)
	st := func(p string) setupx.FileState { s, _ := f.State(p, 1<<20); return s }
	if err := j.Mkdir("/etc/ssh/authorized_keys.d", 0o755, setupx.Root, &setupx.Record{Object: "directory"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Write("/etc/ssh/authorized_keys.d/svc-shell", st("/etc/ssh/authorized_keys.d/svc-shell"), []byte("line\n"), 0o644, setupx.Root, &setupx.Record{Object: "key"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Write("/etc/ssh/old", st("/etc/ssh/old"), []byte("new\n"), 0o644, setupx.Root, &setupx.Record{Object: "file"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Remove("/etc/ssh/gone", st("/etc/ssh/gone"), &setupx.Record{Object: "unit"}); err != nil {
		t.Fatal(err)
	}
	f.FailCommitted["/etc/ssh/late"] = errors.New("read-back")
	if err := j.Write("/etc/ssh/late", st("/etc/ssh/late"), []byte("x"), 0o644, setupx.Root, &setupx.Record{Object: "file"}); err == nil {
		t.Fatal("the injected read-back failure was not reported")
	}
	f.FailWrite["/etc/ssh/never"] = errors.New("refused")
	if err := j.Write("/etc/ssh/never", st("/etc/ssh/never"), []byte("x"), 0o644, setupx.Root, &setupx.Record{Object: "file"}); err == nil {
		t.Fatal("the injected write failure was not reported")
	}
	if want := []string{"/etc/ssh/authorized_keys.d", "/etc/ssh/authorized_keys.d/svc-shell", "/etc/ssh/old", "/etc/ssh/gone", "/etc/ssh/late"}; !reflect.DeepEqual(j.Paths(), want) {
		t.Fatalf("journal %v, want %v", j.Paths(), want)
	}
	undone, failed := j.Rollback()
	if len(failed) != 0 || len(undone) != 5 {
		t.Fatalf("rollback undid %v, failed %v", undone, failed)
	}
	if after := f.Snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("after the rollback the filesystem differs:\n%v\nwant\n%v", after, before)
	}
	if j.Changed() {
		t.Fatal("the journal still holds entries")
	}
}

// TestUnifiedDiff: a diff -u of two short files, and nothing for equal ones.
func TestUnifiedDiff(t *testing.T) {
	a := "Match User svc-shell\n    PermitTTY no\n    MaxSessions 8\n"
	b := "Match User svc-shell\n    PermitTTY yes\n    MaxSessions 8\n"
	want := "--- /etc/x (on the host)\n+++ /etc/x (install)\n@@ -1,3 +1,3 @@\n Match User svc-shell\n-    PermitTTY no\n+    PermitTTY yes\n     MaxSessions 8\n"
	if got := setupx.UnifiedDiff("/etc/x (on the host)", "/etc/x (install)", []byte(a), []byte(b)); got != want {
		t.Fatalf("diff\n%s\nwant\n%s", got, want)
	}
	if setupx.UnifiedDiff("a", "b", []byte(a), []byte(a)) != "" {
		t.Fatal("equal files differ")
	}
	if got := setupx.UnifiedDiff("a", "b", nil, []byte("x\n")); got != "--- a\n+++ b\n@@ -0,0 +1 @@\n+x\n" {
		t.Fatalf("from nothing: %q", got)
	}
	long := strings.Repeat("l\n", 3000)
	if got := setupx.UnifiedDiff("a", "b", []byte(long), nil); !strings.Contains(got, "too long to show") {
		t.Fatalf("long: %.80q", got)
	}
}
