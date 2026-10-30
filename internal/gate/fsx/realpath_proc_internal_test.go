//go:build linux

package fsx

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/procself"
)

// TestRealPathOfFileThroughProc: with Config.Proc set, an open file's real
// path is read from fd/N of that directory, opened before the sandbox, and
// not from what its path names afterwards (in the helper's core unit, after
// memory pressure, a new procfs inode its Landlock rule does not cover;
// procself). The directory here is invented: fd/N is a link to an invented
// path, then the directory is renamed away and replaced by one whose fd/N
// names another path. Without Proc, /proc/self/fd/N gives the file's own.
func TestRealPathOfFileThroughProc(t *testing.T) {
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	n := strconv.Itoa(int(f.Fd()))
	base := t.TempDir()
	dir := filepath.Join(base, "proc-1234")
	fakeFDLink(t, dir, n, "/srv/app/opened")
	proc, err := procself.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Close() })
	if err := os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	fakeFDLink(t, dir, n, "/srv/app/replacement")
	if p, err := realPathOfFile(proc, f); err != nil || p != "/srv/app/opened" {
		t.Fatalf("real path %q %v: read through the path, not the descriptor", p, err)
	}
	if p, err := realPathOfFile(nil, f); err != nil || p != f.Name() {
		t.Fatalf("without Proc: %q %v, want %q", p, err, f.Name())
	}
}

// fakeFDLink makes dir/fd/n a link to target.
func fakeFDLink(t *testing.T, dir, n, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "fd", n)); err != nil {
		t.Fatal(err)
	}
}
