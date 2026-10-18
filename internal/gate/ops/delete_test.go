//go:build linux

package ops_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// delete and delete_preview through the gate's request handling: the
// preview binding (expected_preview_sha256) and a tree that changes after
// the gate's recompute. Fixtures are invented.

type deletePreview struct {
	Type          string   `json:"type"`
	Entries       int      `json:"entries"`
	Bytes         int64    `json:"bytes"`
	First         []string `json:"first"`
	PreviewSHA256 string   `json:"preview_sha256"`
	Deleted       bool     `json:"deleted"`
}

func gateTree(t *testing.T, dir string) {
	t.Helper()
	gatetest.WriteFile(t, filepath.Join(dir, "a.txt"), "aaa", 0o644)
	gatetest.WriteFile(t, filepath.Join(dir, "sub", "b.txt"), "bb", 0o644)
}

func TestDeleteBindsThePreview(t *testing.T) {
	f := newFixture(t, "destructive")
	dir := filepath.Join(f.write, "tree")
	gateTree(t, dir)
	var pv deletePreview
	f.ok("delete_preview", m{"path": dir, "recursive": true}, &pv)
	if pv.Type != "dir" || pv.Entries != 4 || pv.Bytes != 5 || len(pv.First) != 4 || len(pv.PreviewSHA256) != 64 || pv.Deleted {
		t.Fatalf("preview %+v", pv)
	}
	// delete_preview takes no expected hash; delete requires a well-formed one.
	f.fail("delete_preview", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "bad_request")
	f.fail("delete", m{"path": dir, "recursive": true}, "bad_request")
	f.fail("delete", m{"path": dir, "recursive": true, "expected_preview_sha256": strings.ToUpper(pv.PreviewSHA256)}, "bad_request")
	f.fail("delete", m{"path": dir, "recursive": true, "expected_preview_sha256": 42}, "bad_request")
	// A tree that changed since the preview is refused, and nothing is deleted.
	gatetest.WriteFile(t, filepath.Join(dir, "sub", "new.txt"), "n", 0o644)
	f.fail("delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	for _, p := range []string{"a.txt", "sub/b.txt", "sub/new.txt"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("%s was deleted: %v", p, err)
		}
	}
	// A fresh preview binds the tree as it is now.
	f.ok("delete_preview", m{"path": dir, "recursive": true}, &pv)
	var d deletePreview
	f.ok("delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, &d)
	if !d.Deleted || d.Entries != 5 || d.PreviewSHA256 != pv.PreviewSHA256 {
		t.Fatalf("delete %+v", d)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("tree still there: %v", err)
	}
}

// TestGateDeleteWindow: something new appears after the gate's recompute
// matched (a newcomer, or an entry replaced by another inode), at each
// point of the deletion pass; the gate answers exists and the newcomer
// survives, in every run.
func TestGateDeleteWindow(t *testing.T) {
	f := newFixture(t, "destructive")
	steps := []fsx.DeleteStep{fsx.DeleteStepAfterCompare, fsx.DeleteStepBeforeEntry, fsx.DeleteStepBeforeRename, fsx.DeleteStepAfterRename}
	for i := range gateWindowRuns {
		dir := filepath.Join(f.write, fmt.Sprintf("w%d", i))
		gateTree(t, dir)
		var pv deletePreview
		f.ok("delete_preview", m{"path": dir, "recursive": true}, &pv)
		step := steps[i%len(steps)]
		victim := dir + "/sub/b.txt"
		racer := fmt.Sprintf("racer %d\n", i)
		fired := false
		f.opts.InjectDeleteStep = func(s fsx.DeleteStep, p string) {
			if s != step || fired || (s != fsx.DeleteStepAfterCompare && p != victim) {
				return
			}
			fired = true
			tmp := filepath.Join(f.write, fmt.Sprintf("racer-%d", i))
			if err := os.WriteFile(tmp, []byte(racer), 0o600); err != nil {
				t.Error(err)
			}
			if err := os.Rename(tmp, victim); err != nil {
				t.Error(err)
			}
		}
		f.fail("delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
		f.opts.InjectDeleteStep = nil
		if !fired {
			t.Fatalf("run %d: the deletion pass never reached step %d", i, step)
		}
		if got := contentOf(t, victim); got != racer {
			t.Fatalf("run %d (step %d): the newcomer was changed: %q", i, step, got)
		}
	}
	t.Logf("gate delete window: %d runs, every newcomer survived", gateWindowRuns)
}
