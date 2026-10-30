//go:build linux

package procself_test

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/procself"
)

// fakeProc lays out a directory like /proc/<pid>: a status file, task/<tid>
// entries and an fd/<n> link (invented values).
func fakeProc(t *testing.T, dir, status, link string) {
	t.Helper()
	for _, d := range []string{"task/10", "task/11", "fd"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(link, filepath.Join(dir, "fd", "3")); err != nil {
		t.Fatal(err)
	}
}

// openFake opens dir as a Dir, closed when the test ends.
func openFake(t *testing.T, dir string) *procself.Dir {
	t.Helper()
	d, err := procself.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestReads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proc-1234")
	fakeProc(t, dir, "Name:\tprobe\n", "/srv/app/a")
	d := openFake(t, dir)
	if b, err := d.ReadFile("status", 64); err != nil || string(b) != "Name:\tprobe\n" {
		t.Fatalf("status %q %v", b, err)
	}
	if _, err := d.ReadFile("status", 4); err == nil || !strings.Contains(err.Error(), "longer than 4 bytes") {
		t.Fatalf("a file over the limit: %v", err)
	}
	names, err := d.ReadDirNames("task", 8)
	slices.Sort(names)
	if err != nil || !slices.Equal(names, []string{"10", "11"}) {
		t.Fatalf("task %v %v", names, err)
	}
	if _, err := d.ReadDirNames("task", 1); err == nil || !strings.Contains(err.Error(), "more than 1 entries") {
		t.Fatalf("a directory over the bound: %v", err)
	}
	if l, err := d.Readlink("fd/3"); err != nil || l != "/srv/app/a" {
		t.Fatalf("fd/3 %q %v", l, err)
	}
	if _, err := d.ReadFile("missing", 64); !os.IsNotExist(err) {
		t.Fatalf("a missing file: %v (the errno must be kept)", err)
	}
	for _, bad := range []string{"", "/status", "../status", "task/../status", "task//10", "./status", "fd/3\n"} {
		if _, err := d.ReadFile(bad, 64); err == nil || !strings.Contains(err.Error(), "is not a name under") {
			t.Fatalf("name %q: %v", bad, err)
		}
	}
}

// TestReadsThroughDescriptor: once opened, reads follow the directory that
// was opened, not its path. Here the path is renamed away and replaced with
// another directory; the core unit's case is the same directory reached
// through a new procfs inode after its dentry was reclaimed, which its
// Landlock rule does not cover. A read that resolved the path again would
// see the replacement.
func TestReadsThroughDescriptor(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "proc-1234")
	fakeProc(t, dir, "Name:\topened\n", "/srv/app/opened")
	d := openFake(t, dir)
	if err := os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	fakeProc(t, dir, "Name:\treplacement\n", "/srv/app/replacement")
	if err := os.RemoveAll(filepath.Join(dir, "task", "11")); err != nil {
		t.Fatal(err)
	}
	if b, err := d.ReadFile("status", 64); err != nil || string(b) != "Name:\topened\n" {
		t.Fatalf("status read through the path, not the descriptor: %q %v", b, err)
	}
	if names, err := d.ReadDirNames("task", 8); err != nil || len(names) != 2 {
		t.Fatalf("task listed through the path, not the descriptor: %v %v", names, err)
	}
	if l, err := d.Readlink("fd/3"); err != nil || l != "/srv/app/opened" {
		t.Fatalf("fd/3 read through the path, not the descriptor: %q %v", l, err)
	}
}

// TestOpenSelf: Open resolves /proc/self to this process's directory.
func TestOpenSelf(t *testing.T) {
	d, err := procself.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	b, err := d.ReadFile("status", 1<<16)
	if err != nil || !strings.Contains(string(b), "\nPid:\t"+strconv.Itoa(os.Getpid())+"\n") {
		t.Fatalf("status of another process, or none: %v", err)
	}
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if l, err := d.Readlink("fd/" + strconv.Itoa(int(f.Fd()))); err != nil || l != f.Name() {
		t.Fatalf("fd link %q %v, want %q", l, err, f.Name())
	}
}
