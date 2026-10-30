//go:build linux

package execx_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// Spec.Files (POLICY §4, {path:read:fd}; handoff N-22): the trampoline
// passes exactly these descriptors to the command, as 4, 5, …, each a
// regular file open read-only, and every other descriptor above stderr
// stays close-on-exec. Every file is an invented fixture.

func openFixture(t *testing.T, name, content string, flag int) (f *os.File, path string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, flag, 0) //nolint:gosec // G304: the test's own fixture
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, p
}

// TestFirstFileMatchesTemplate: the descriptor numbers the template
// engine writes into argv are the ones the trampoline passes.
func TestFirstFileMatchesTemplate(t *testing.T) {
	if execx.FirstFile != template.FirstFD || execx.MaxFiles != template.MaxFDTokens {
		t.Fatalf("execx passes %d.. (%d), the template engine names %d.. (%d)", execx.FirstFile, execx.MaxFiles, template.FirstFD, template.MaxFDTokens)
	}
}

// TestCommandGetsOnlyItsFiles: with two files passed, the command holds
// descriptors 4 and 5 on exactly those files (and nothing else above
// stderr but the Go runtime's own), while a descriptor the gate itself
// holds without close-on-exec still does not leak.
func TestCommandGetsOnlyItsFiles(t *testing.T) {
	p := probePath(t)
	a, pa := openFixture(t, "a", "A\n", os.O_RDONLY)
	b, pb := openFixture(t, "b", "B\n", os.O_RDONLY)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	if _, err = unix.FcntlInt(pw.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	out := procAttrs(run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"procattrs"}, Files: []*os.File{a, b}}).Stdout)
	want := []string{"4:100000:" + realPath(t, pa), "5:100000:" + realPath(t, pb)}
	if got := extraFDs(out["fds"]); !slices.Equal(got, want) {
		t.Fatalf("the command holds %v, want exactly %v", got, want)
	}
}

// TestCommandReadsThePassedFile: the command reopens /dev/fd/4 and reads
// the file it was given, also after its name was swapped for another file.
func TestCommandReadsThePassedFile(t *testing.T) {
	p := probePath(t)
	f, path := openFixture(t, "t", "ORIGINAL", os.O_RDONLY)
	if err := os.Rename(path, path+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("SWAPPED"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"cat", template.FDPath(4)}, Files: []*os.File{f}})
	if got := strings.TrimSpace(string(r.Stdout)); got != "READ:ORIGINAL" {
		t.Fatalf("read %q (stderr %q)", got, r.Stderr)
	}
	// Control: the same command without the descriptor has nothing there.
	r = run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"cat", template.FDPath(4)}})
	if strings.Contains(string(r.Stdout), "READ:") {
		t.Fatalf("read without a passed descriptor: %q", r.Stdout)
	}
}

// TestRunRefusesFiles: more than MaxFiles, a nil file, and (checked by the
// trampoline itself, before the command runs) a file open for writing, a
// directory or a pipe: nothing runs.
func TestRunRefusesFiles(t *testing.T) {
	p := probePath(t)
	ro, _ := openFixture(t, "ro", "x", os.O_RDONLY)
	rw, _ := openFixture(t, "rw", "x", os.O_RDWR)
	wo, _ := openFixture(t, "wo", "x", os.O_WRONLY)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	marker := filepath.Join(t.TempDir(), "ran")
	for name, files := range map[string][]*os.File{
		"nine files": slices.Repeat([]*os.File{ro}, execx.MaxFiles+1),
		"nil file":   {ro, nil},
		"read-write": {rw},
		"write-only": {ro, wo},
		"directory":  {dir},
		"pipe":       {pr},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := execx.Run(context.Background(), &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"write", marker},
				Env: execx.Environment("/nonexistent-home"), Trampoline: gatetest.Trampoline(t), Timeout: 10 * time.Second, MaxOutput: 1 << 20, Files: files})
			if !errors.Is(err, execx.ErrStart) {
				t.Fatalf("Run: %v, want ErrStart", err)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("the command ran")
			}
		})
	}
	// Eight read-only files run.
	r := run(t, &execx.Spec{MaxMemoryMB: testMemoryMB, Path: p, Args: []string{"procattrs"}, Files: slices.Repeat([]*os.File{ro}, execx.MaxFiles)})
	if got := extraFDs(procAttrs(r.Stdout)["fds"]); len(got) != execx.MaxFiles || !strings.HasPrefix(got[execx.MaxFiles-1], strconv.Itoa(execx.FirstFile+execx.MaxFiles-1)+":") {
		t.Fatalf("eight files: %v", got)
	}
}

func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
