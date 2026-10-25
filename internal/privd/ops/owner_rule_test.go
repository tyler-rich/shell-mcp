//go:build linux

package ops_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// Rule R through the helper (handoff docs/handoff/S4C-PRIVILEGED.md N-8,
// N-9, P-14; PRIVILEGED §6): root leaves a regular file only where the owner
// it will have is owner-matched on the chain from the privileged root;
// priv_backup_check reports that verdict for the previews; a delete's
// preview says when the tools could not restore its backup. The fixture's
// uid stands for root (gatetest.Trust); another account's write access is a
// world-writable directory. Every layout is invented.

// openDrop makes <write root>/drop, writable by everyone (another account
// could write it).
func openDrop(t *testing.T, f *fixture) string {
	t.Helper()
	drop := filepath.Join(f.write, "drop")
	gatetest.Mkdir(t, drop, 0o755)
	if err := os.Chmod(drop, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	return drop
}

// TestPrivOwnerRule: under a directory another account can write, a new file
// or copy without an owner (root's) and a write with an explicit owner and
// group are refused before anything is written, naming the directory; under
// the closed write root they are created with the helper's own ids.
func TestPrivOwnerRule(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := openDrop(t, f)
	src := filepath.Join(f.write, "src.conf")
	gatetest.WriteFile(t, src, "src\n", 0o640)
	fresh, copied := filepath.Join(drop, "fresh.conf"), filepath.Join(drop, "copied.conf")
	f.failMsg("priv_write_file", m{"path": fresh, "content_b64": b64("new\n")}, "path_denied", drop)
	f.failMsg("priv_write_file", m{"path": fresh, "content_b64": b64("new\n"), "owner": "tester", "group": "tester"}, "path_denied", drop)
	f.failMsg("priv_write_file", m{"path": fresh, "content_b64": b64("new\n"), "owner": "root", "group": "root"}, "path_denied", drop)
	f.failMsg("priv_copy", m{"source": src, "destination": copied}, "path_denied", drop)
	f.failMsg("priv_copy", m{"source": src, "destination": copied, "overwrite": true}, "path_denied", drop)
	if present(fresh) || present(copied) {
		t.Fatal("a refused create made a file")
	}
	// A closed chain: created, with the helper's own ids.
	var w writeOut
	f.ok("priv_write_file", m{"path": filepath.Join(f.write, "fresh.conf"), "content_b64": b64("new\n")}, &w)
	if w.UID == nil || w.GID == nil || *w.UID != f.uid || *w.GID != f.gid {
		t.Fatalf("a new file's owner %v:%v, want %d:%d", w.UID, w.GID, f.uid, f.gid)
	}
	f.ok("priv_copy", m{"source": src, "destination": filepath.Join(f.write, "copied.conf")}, nil)
}

type ownerRuleOut struct {
	OwnerRule *struct {
		Verdict string  `json:"verdict"`
		UID     *uint32 `json:"uid"`
		Name    string  `json:"name"`
		Dir     string  `json:"dir"`
		Why     string  `json:"why"`
	} `json:"owner_rule"`
}

// TestPrivBackupCheckOwnerRule (P-14): priv_backup_check reports which owners
// a file at the path may have: any under a closed chain, none under a
// directory another account can write, naming it; for a new path and an
// existing file alike.
func TestPrivBackupCheckOwnerRule(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := openDrop(t, f)
	gatetest.WriteFile(t, filepath.Join(drop, "there.conf"), "there\n", 0o644)
	for _, c := range []struct {
		path, verdict, dir string
	}{
		{filepath.Join(f.write, "new.conf"), "any", ""},
		{filepath.Join(f.write, "app.conf"), "any", ""},
		{filepath.Join(drop, "new.conf"), "none", drop},
		{filepath.Join(drop, "there.conf"), "none", drop},
	} {
		var out ownerRuleOut
		f.ok("priv_backup_check", m{"path": c.path}, &out)
		r := out.OwnerRule
		if r == nil || r.Verdict != c.verdict || r.Dir != c.dir || r.UID != nil {
			t.Fatalf("%s: owner_rule %+v, want %s under %q", c.path, r, c.verdict, c.dir)
		}
		if c.dir != "" && !strings.Contains(r.Why, "world-writable") {
			t.Fatalf("%s: why %q", c.path, r.Why)
		}
	}
}

// TestPrivDeletePreviewRestoreWarning: when a restore would refuse any entry
// of the backup a delete writes (rule R: its recorded owner under a
// directory another account can write), the delete's preview says so in a
// warning, with the count and the first reason; the restore of that backup
// is then indeed refused. A delete whose backup restores has no warning,
// and neither has one that writes no backup.
func TestPrivDeletePreviewRestoreWarning(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := openDrop(t, f)
	file := filepath.Join(drop, "root.conf")
	gatetest.WriteFile(t, file, "root's\n", 0o640)
	tree := filepath.Join(drop, "tree")
	delTree(t, tree) // 7 entries
	for _, c := range []struct {
		path      string
		recursive bool
		n         string
	}{
		{file, false, "1 entry"},
		{tree, true, "7 entries"},
	} {
		r := f.ok("priv_delete_preview", m{"path": c.path, "recursive": c.recursive}, nil)
		want := "the tools won't be able to restore " + c.n + " of this backup: "
		if len(r.Warnings) != 1 || !strings.HasPrefix(r.Warnings[0], want) || !strings.Contains(r.Warnings[0], drop) {
			t.Fatalf("%s: warnings %q, want one starting %q naming %s", c.path, r.Warnings, want, drop)
		}
		// The warning is what a restore would then do.
		_, out := f.deleteBound(c.path, c.recursive)
		f.failMsg("priv_restore_preview", m{"id": out.BackupIDs[0]}, "path_denied", drop)
	}
	// Restorable: no warning.
	closed := filepath.Join(f.write, "closed")
	delTree(t, closed)
	if r := f.ok("priv_delete_preview", m{"path": closed, "recursive": true}, nil); len(r.Warnings) != 0 {
		t.Fatalf("a restorable backup warns %q", r.Warnings)
	}
	// No backup, no warning.
	g := newFixture(t, keep(0))
	gdrop := openDrop(t, g)
	gatetest.WriteFile(t, filepath.Join(gdrop, "x"), "x\n", 0o640)
	if r := g.ok("priv_delete_preview", m{"path": filepath.Join(gdrop, "x")}, nil); len(r.Warnings) != 0 {
		t.Fatalf("a delete without a backup warns %q", r.Warnings)
	}
}

// TestPrivOwnerRuleRace (core unit): another account that can write a
// directory under the write root swaps what is on the path (a closed
// sibling directory, a symlink to a closed directory elsewhere in the root)
// again and again while the helper is asked to create files beneath it.
// Every request is refused and nothing is created anywhere.
func TestPrivOwnerRuleRace(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := openDrop(t, f)
	a, b := filepath.Join(drop, "a"), filepath.Join(drop, "b")
	gatetest.Mkdir(t, a, 0o755)
	gatetest.Mkdir(t, b, 0o755)
	vault := filepath.Join(f.write, "vault")
	gatetest.Mkdir(t, vault, 0o755)
	link := filepath.Join(drop, "link")
	if err := os.Symlink(vault, link); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(f.write, "src.conf")
	gatetest.WriteFile(t, src, "src\n", 0o640)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	swaps := 0
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			alt := b
			if i%2 == 1 {
				alt = link
			}
			if unix.Renameat2(unix.AT_FDCWD, alt, unix.AT_FDCWD, a, unix.RENAME_EXCHANGE) == nil {
				swaps++
			}
		}
	})
	refused := map[string]int{}
	for i := range 100 {
		for _, q := range []struct {
			op   string
			args m
		}{
			{"priv_write_file", m{"path": filepath.Join(a, fmt.Sprintf("w%d", i)), "content_b64": b64("x\n")}},
			{"priv_write_file", m{"path": filepath.Join(a, fmt.Sprintf("o%d", i)), "content_b64": b64("x\n"), "owner": "root", "group": "root"}},
			{"priv_copy", m{"source": src, "destination": filepath.Join(a, fmt.Sprintf("c%d", i))}},
		} {
			r := f.serve(q.op, q.args)
			// path_denied by rule R, or not_a_directory when the symlink
			// was in place at the lookup: refused either way.
			if r.OK || r.Error == nil || r.Error.Code != "path_denied" && r.Error.Code != "not_a_directory" {
				close(stop)
				wg.Wait()
				t.Fatalf("run %d: %s %v: ok=%v %+v, want path_denied or not_a_directory", i, q.op, q.args, r.OK, r.Error)
			}
			refused[r.Error.Code]++
		}
	}
	close(stop)
	wg.Wait()
	if swaps == 0 {
		t.Fatal("the racer never swapped")
	}
	for _, d := range []string{a, b, vault} {
		if names, _ := os.ReadDir(d); len(names) != 0 {
			t.Fatalf("%s holds %d entries after the race", d, len(names))
		}
	}
	t.Logf("requests refused %v while the racer made %d swaps", refused, swaps)
}
