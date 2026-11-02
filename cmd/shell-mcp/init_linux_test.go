//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestInitDispatch(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "srv")
	if err := os.Mkdir(parent, 0o755); err != nil { //nolint:gosec // G301: a parent only its owner can write to, as init requires
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil { //nolint:gosec // G302: as above
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "secrets")
	uid, gid := strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid())
	if os.Geteuid() == 0 {
		uid, gid = "65532", "65532"
	}
	var out, errb bytes.Buffer
	if code := run(context.Background(), nil, []string{"init", "--dir", dir, "--uid", uid, "--gid", gid}, emptyLookup, &out, &errb); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	if fi, err := os.Stat(filepath.Join(dir, "mcp_token")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mcp_token: %v %v", fi, err)
	}
	out.Reset()
	if code := run(context.Background(), nil, []string{"init", "--dir"}, emptyLookup, &out, &errb); code != 2 {
		t.Fatalf("usage: exit %d", code)
	}
	if code := run(context.Background(), nil, []string{"init", "--dir", dir, "--approver", "alice"}, emptyLookup, &out, &errb); code != 1 {
		t.Fatalf("--approver without a terminal: exit %d", code)
	}
}
