//go:build linux

package ops_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The helper's privileged writes get the gate's create-only commits:
// priv_write_file's expect_absent, and priv_copy and priv_move without
// overwrite, refuse a destination that appears at any point before the
// commit, and back up nothing. Fixtures are invented.

const helperWindowRuns = 100

func TestPrivWriteExpectAbsent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "fresh.conf")
	var w struct {
		Created   bool     `json:"created"`
		Verified  bool     `json:"verified"`
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("new\n"), "expect_absent": true, "owner": "tester", "group": "tester"}, &w)
	if !w.Created || !w.Verified || len(w.BackupIDs) != 0 || readFile(t, p) != "new\n" {
		t.Fatalf("create %+v", w)
	}
	if st := mustStat(t, p); st.Uid != f.uid || st.Gid != f.gid || st.Nlink != 1 {
		t.Fatalf("owner %d:%d links %d", st.Uid, st.Gid, st.Nlink)
	}
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("again\n"), "expect_absent": true}, "exists")
	h := sha256.Sum256([]byte("new\n"))
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("again\n"), "expect_absent": true, "expected_sha256": hex.EncodeToString(h[:])}, "bad_request")
	if readFile(t, p) != "new\n" {
		t.Fatalf("a refused write changed the file: %q", readFile(t, p))
	}
}

// TestPrivCreateOnlyCommitWindow: the destination appears after every check
// the helper makes, immediately before the commit.
func TestPrivCreateOnlyCommitWindow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := filepath.Join(f.write, "src.conf")
	cases := []struct {
		op   string
		args func(dst string, i int) m
		pre  func(i int)
	}{
		{"priv_write_file", func(dst string, _ int) m {
			return m{"path": dst, "content_b64": b64("approved\n"), "expect_absent": true}
		}, nil},
		{"priv_copy", func(dst string, _ int) m { return m{"source": src, "destination": dst} },
			func(int) { writeTestFile(t, src, "copied\n") }},
		{"priv_move", func(dst string, i int) m {
			return m{"source": fmt.Sprintf("%s.%d", src, i), "destination": dst}
		}, func(i int) { writeTestFile(t, fmt.Sprintf("%s.%d", src, i), "moved\n") }},
	}
	for _, c := range cases {
		for i := range helperWindowRuns {
			if c.pre != nil {
				c.pre(i)
			}
			dst := filepath.Join(f.write, fmt.Sprintf("%s-dst-%d", c.op, i))
			racer := fmt.Sprintf("racer %d\n", i)
			f.opts.InjectBeforeCommit = func() { writeTestFile(t, dst, racer) }
			f.fail(c.op, c.args(dst, i), "exists")
			f.opts.InjectBeforeCommit = nil
			if got := readFile(t, dst); got != racer {
				t.Fatalf("%s run %d: the racing file was replaced: %q", c.op, i, got)
			}
			if c.op == "priv_move" && readFile(t, fmt.Sprintf("%s.%d", src, i)) != "moved\n" {
				t.Fatalf("run %d: a refused move moved its source", i)
			}
		}
	}
}

// TestPrivNoReplaceUnsupported: without RENAME_NOREPLACE support a move
// without overwrite is refused, never done by check-then-rename.
func TestPrivNoReplaceUnsupported(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := filepath.Join(f.write, "src.conf")
	writeTestFile(t, src, "source\n")
	f.opts.InjectNoReplaceFault = func() error { return syscall.EINVAL }
	dst := filepath.Join(f.write, "dst.conf")
	r := f.serve("priv_move", m{"source": src, "destination": dst})
	if r.OK || r.Error == nil || r.Error.Code != "bad_request" || !strings.Contains(r.Error.Message, "RENAME_NOREPLACE") {
		t.Fatalf("move %+v", r)
	}
	if _, err := os.Lstat(dst); err == nil || readFile(t, src) != "source\n" {
		t.Fatal("the source moved")
	}
}

func writeTestFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
