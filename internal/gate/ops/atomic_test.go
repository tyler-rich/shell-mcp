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
