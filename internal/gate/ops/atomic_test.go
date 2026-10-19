//go:build linux

package ops_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// Create-only writes through the gate (protocol: write_file's expect_absent;
// copy and move without overwrite). Fixtures are invented.

const gateWindowRuns = 100

func enc(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sumOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func contentOf(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteFileExpectAbsent(t *testing.T) {
	f := newFixture(t, "operator")
	p := filepath.Join(f.write, "fresh.txt")
	var w struct {
		Created  bool `json:"created"`
		Verified bool `json:"verified"`
	}
	f.ok("write_file", m{"path": p, "content_b64": enc("new\n"), "expect_absent": true}, &w)
	if !w.Created || !w.Verified || contentOf(t, p) != "new\n" {
		t.Fatalf("create %+v", w)
	}
	f.fail("write_file", m{"path": p, "content_b64": enc("again\n"), "expect_absent": true}, "exists")
	f.fail("write_file", m{"path": p, "content_b64": enc("again\n"), "expect_absent": true, "expected_sha256": sumOf("new\n")}, "bad_request")
	if contentOf(t, p) != "new\n" {
		t.Fatalf("a refused write changed the file: %q", contentOf(t, p))
	}
	// expect_absent false is the default: an ordinary replace.
	f.ok("write_file", m{"path": p, "content_b64": enc("replaced\n"), "expect_absent": false}, nil)
	if contentOf(t, p) != "replaced\n" {
		t.Fatal("plain write did not replace")
	}
}

// TestGateCreateOnlyCommitWindow: the destination appears after the gate's
// checks, immediately before the commit; the gate answers exists and the
// file is untouched, for every run.
func TestGateCreateOnlyCommitWindow(t *testing.T) {
	f := newFixture(t, "operator")
	src := filepath.Join(f.write, "src.txt")
	cases := []struct {
		op   string
		args func(dst string, i int) m
		pre  func(i int)
	}{
		{"write_file", func(dst string, _ int) m {
			return m{"path": dst, "content_b64": enc("approved\n"), "expect_absent": true}
		}, nil},
		{"copy", func(dst string, _ int) m { return m{"source": src, "destination": dst} },
			func(int) { gatetest.WriteFile(t, src, "copied\n", 0o644) }},
		{"move", func(dst string, i int) m {
			return m{"source": fmt.Sprintf("%s.%d", src, i), "destination": dst}
		}, func(i int) { gatetest.WriteFile(t, fmt.Sprintf("%s.%d", src, i), "moved\n", 0o644) }},
	}
	for _, c := range cases {
		for i := range gateWindowRuns {
			if c.pre != nil {
				c.pre(i)
			}
			dst := filepath.Join(f.write, fmt.Sprintf("%s-dst-%d", c.op, i))
			racer := fmt.Sprintf("racer %d\n", i)
			f.opts.InjectBeforeCommit = func() {
				if err := os.WriteFile(dst, []byte(racer), 0o600); err != nil {
					t.Errorf("plant: %v", err)
				}
			}
			f.fail(c.op, c.args(dst, i), "exists")
			f.opts.InjectBeforeCommit = nil
			if got := contentOf(t, dst); got != racer {
				t.Fatalf("%s run %d: the racing file was replaced: %q", c.op, i, got)
			}
		}
	}
}

// TestGateCopyMoveExpectedDestination: the gate's copy and move take
// expected_destination_sha256 (P-9, as for priv_copy and priv_move): only
// with overwrite, 64 lowercase hex digits; the destination must be a
// regular file with that content, otherwise exists (not_found when it is
// gone), and nothing changes.
func TestGateCopyMoveExpectedDestination(t *testing.T) {
	for _, op := range []string{"copy", "move"} {
		t.Run(op, func(t *testing.T) {
			f := newFixture(t, "operator")
			src, dst := filepath.Join(f.write, "src.txt"), filepath.Join(f.write, "dst.txt")
			gatetest.WriteFile(t, src, "new\n", 0o644)
			gatetest.WriteFile(t, dst, "approved old\n", 0o644)
			args := func(d string, overwrite bool, expected string) m {
				return m{"source": src, "destination": d, "overwrite": overwrite, "expected_destination_sha256": expected}
			}
			f.fail(op, args(dst, true, sumOf("something else")), "exists")
			f.fail(op, args(dst, true, "ABC"), "bad_request")
			f.fail(op, args(filepath.Join(f.write, "none.txt"), false, sumOf("x")), "bad_request")
			f.fail(op, args(filepath.Join(f.write, "gone.txt"), true, sumOf("x")), "not_found")
			gatetest.Mkdir(t, filepath.Join(f.write, "adir"), 0o755)
			f.fail(op, args(filepath.Join(f.write, "adir"), true, sumOf("x")), "exists")
			if contentOf(t, dst) != "approved old\n" || contentOf(t, src) != "new\n" {
				t.Fatalf("a refused %s changed something: dst %q", op, contentOf(t, dst))
			}
			f.ok(op, args(dst, true, sumOf("approved old\n")), nil)
			if contentOf(t, dst) != "new\n" {
				t.Fatalf("dst %q", contentOf(t, dst))
			}
		})
	}
}

// TestGateVerifiedReplaceCommitWindow: a write with expected_sha256, and a
// copy or move with overwrite and expected_destination_sha256, whose
// destination is replaced by another file after the gate's checks,
// immediately before the commit: the gate answers exists and the racing
// content survives, for every run; a refused move leaves its source.
func TestGateVerifiedReplaceCommitWindow(t *testing.T) {
	const old = "approved old\n"
	f := newFixture(t, "operator")
	src := filepath.Join(f.write, "src.txt")
	cases := []struct {
		op   string
		args func(dst string, i int) m
		pre  func(i int)
	}{
		{"write_file", func(dst string, _ int) m {
			return m{"path": dst, "content_b64": enc("approved new\n"), "expected_sha256": sumOf(old)}
		}, nil},
		{"copy", func(dst string, _ int) m {
			return m{"source": src, "destination": dst, "overwrite": true, "expected_destination_sha256": sumOf(old)}
		}, func(int) { gatetest.WriteFile(t, src, "approved new\n", 0o644) }},
		{"move", func(dst string, i int) m {
			return m{"source": fmt.Sprintf("%s.%d", src, i), "destination": dst, "overwrite": true, "expected_destination_sha256": sumOf(old)}
		}, func(i int) { gatetest.WriteFile(t, fmt.Sprintf("%s.%d", src, i), "approved new\n", 0o644) }},
	}
	for _, c := range cases {
		for i := range gateWindowRuns {
			if c.pre != nil {
				c.pre(i)
			}
			dst := filepath.Join(f.write, fmt.Sprintf("%s-repl-%d", c.op, i))
			gatetest.WriteFile(t, dst, old, 0o644)
			racer := fmt.Sprintf("racer %d\n", i)
			f.opts.InjectBeforeCommit = func() {
				tmp := dst + ".racer"
				if err := os.WriteFile(tmp, []byte(racer), 0o600); err != nil {
					t.Errorf("plant: %v", err)
				}
				if err := os.Rename(tmp, dst); err != nil {
					t.Errorf("plant: %v", err)
				}
			}
			r := f.call(c.op, c.args(dst, i))
			f.opts.InjectBeforeCommit = nil
			if got := contentOf(t, dst); got != racer {
				t.Fatalf("%s run %d: the racing content was lost (ok %v, error %+v): %q", c.op, i, r.OK, r.Error, got)
			}
			if r.OK || r.Error == nil || r.Error.Code != "exists" {
				t.Fatalf("%s run %d: %+v, want exists", c.op, i, r.Error)
			}
			if c.op == "move" && contentOf(t, fmt.Sprintf("%s.%d", src, i)) != "approved new\n" {
				t.Fatalf("move run %d: a refused move moved its source", i)
			}
		}
		t.Logf("gate %s with a bound destination, replaced before the commit: exists in %d of %d runs, the racing content kept", c.op, gateWindowRuns, gateWindowRuns)
	}
}
