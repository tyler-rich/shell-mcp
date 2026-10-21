//go:build linux && landlock_forcepsx

package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// TestThreadPathDecision (landlock_forcepsx test build): on a kernel at ABI
// 8 or above the sandbox plans as at ABI 7 and takes the psx path; below 8
// it plans for the kernel's own ABI, as a release build does.
func TestThreadPathDecision(t *testing.T) {
	for abi, c := range map[int]struct {
		planned int
		path    string
	}{
		0: {0, "none"}, 1: {1, "psx"}, 6: {6, "psx"}, 7: {7, "psx"},
		8: {7, "psx"}, 9: {7, "psx"}, 10: {7, "psx"},
	} {
		if got := capABI(abi); got != c.planned {
			t.Errorf("ABI %d planned as %d, want %d", abi, got, c.planned)
		}
		if got := threadPath(capABI(abi)); got != c.path {
			t.Errorf("ABI %d: path %s, want %s", abi, got, c.path)
		}
	}
}

// TestAddPathMissing (landlock_forcepsx test build): addPath skips a path
// that is gone, as go-landlock's IgnoreIfMissing does, and really adds an
// existing one: a directory right on a regular file is refused by the
// kernel. grants already drops missing paths, so this is the case where a
// path vanishes between grants and addPath.
func TestAddPathMissing(t *testing.T) {
	if rawKernelABI() < 1 {
		if req, _ := strconv.Atoi(os.Getenv("SHELL_MCP_REQUIRE_LANDLOCK_ABI")); req >= 1 {
			t.Fatal("Landlock is unavailable but SHELL_MCP_REQUIRE_LANDLOCK_ABI is set")
		}
		t.Skip("Landlock unavailable")
	}
	attr := llsys.RulesetAttr{HandledAccessFS: uint64(llsys.AccessFSReadFile | llsys.AccessFSReadDir)}
	fd, err := llsys.LandlockCreateRuleset(&attr, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	d := t.TempDir()
	file := filepath.Join(d, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := addPath(fd, pathGrant{access: llsys.AccessFSReadFile, path: filepath.Join(d, "gone")}); err != nil {
		t.Fatalf("missing path: %v", err)
	}
	if err := addPath(fd, pathGrant{access: llsys.AccessFSReadFile, path: file}); err != nil {
		t.Fatalf("existing file: %v", err)
	}
	if err := addPath(fd, pathGrant{access: llsys.AccessFSReadDir, path: file}); err == nil {
		t.Fatal("a directory right on a regular file was accepted: addPath added nothing")
	}
}
