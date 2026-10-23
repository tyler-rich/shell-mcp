//go:build linux

package ops_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The move rule through the helper (handoff docs/handoff/S4C-PRIVILEGED.md
// N-17; PRIVILEGED §6, "Moves"): priv_move moves a non-directory only when
// its owner is owner-matched at the source and passes rule R at the
// destination, every directory of a moved tree has a mode priv_mkdir could
// create, and the source is staged in the destination's directory and
// checked before the commit. The fixture's uid stands for root
// (gatetest.Trust); another account's write access is a world-writable
// directory. Every layout is invented.

const movePrefix = ".shell-mcp-move-"

// TestPrivMoveRule: (a) into a directory another account can write and (b)
// out of one (a world-readable file included, and a planted tree) are
// refused naming the directory, changing nothing; a directory whose mode
// priv_mkdir could not create is refused naming it and its mode; a move
// between closed directories works.
func TestPrivMoveRule(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := openDrop(t, f)
	own := filepath.Join(f.write, "root.conf")
	gatetest.WriteFile(t, own, "root's\n", 0o600)
	gatetest.WriteFile(t, filepath.Join(drop, "over.conf"), "old\n", 0o600)
	planted := filepath.Join(drop, "planted.conf")
	gatetest.WriteFile(t, planted, "planted\n", 0o644)
	plantedTree := filepath.Join(drop, "tree")
	delTree(t, plantedTree)
	closedTree := filepath.Join(f.write, "closed")
	delTree(t, closedTree)
	for _, c := range []struct {
		name string
		args m
		msg  string
	}{
		{"(a) a new file", m{"source": own, "destination": filepath.Join(drop, "root.conf")}, "the directory " + drop + " is "},
		{"(a) over a file", m{"source": own, "destination": filepath.Join(drop, "over.conf"), "overwrite": true}, "the directory " + drop + " is "},
		{"(a) a tree", m{"source": closedTree, "destination": filepath.Join(drop, "closed")}, "the directory " + drop + " is "},
		{"(b) a world-readable file", m{"source": planted, "destination": filepath.Join(f.write, "planted.conf")}, "the directory " + drop + " is "},
		{"(b) a planted tree", m{"source": plantedTree, "destination": filepath.Join(f.write, "tree")}, "the directory " + drop + " is "},
	} {
		f.failMsg("priv_move", c.args, "path_denied", c.msg)
	}
	if readFile(t, own) != "root's\n" || readFile(t, planted) != "planted\n" || readFile(t, filepath.Join(drop, "over.conf")) != "old\n" ||
		present(filepath.Join(drop, "root.conf")) || present(filepath.Join(f.write, "planted.conf")) || present(filepath.Join(f.write, "tree")) ||
		!present(filepath.Join(closedTree, "b", "c.txt")) || !present(filepath.Join(plantedTree, "b", "c.txt")) {
		t.Fatal("a refused move changed something")
	}
	if f.storeUse() != 0 {
		t.Fatal("a refused move left a backup")
	}
	// Directory modes priv_mkdir could not create.
	for _, c := range []struct {
		mode os.FileMode
		want string
	}{{0o777, "0777"}, {0o775, "0775"}, {0o755 | os.ModeSetgid, "2755"}} {
		d := filepath.Join(f.write, "wide")
		gatetest.Mkdir(t, filepath.Join(d, "in"), 0o755)
		if err := os.Chmod(d, c.mode); err != nil {
			t.Fatal(err)
		}
		f.failMsg("priv_move", m{"source": d, "destination": filepath.Join(f.write, "wide2")}, "path_denied", c.want)
		if present(filepath.Join(f.write, "wide2")) {
			t.Fatal("a refused directory was moved")
		}
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	// An inner directory too.
	outer := filepath.Join(f.write, "outer")
	gatetest.Mkdir(t, filepath.Join(outer, "in"), 0o755)
	if err := os.Chmod(filepath.Join(outer, "in"), 0o777); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	f.failMsg("priv_move", m{"source": outer, "destination": filepath.Join(f.write, "outer2")}, "path_denied", filepath.Join(outer, "in"))
	// Closed to closed: moved.
	f.ok("priv_move", m{"source": own, "destination": filepath.Join(f.write, "moved.conf")}, nil)
	f.ok("priv_move", m{"source": closedTree, "destination": filepath.Join(f.write, "closed2")}, nil)
}

// TestPrivMoveSwapWindows: the source swapped after the helper's check
// (before the stage) is put back, and the move refused with exists,
// nothing at the destination; when the source's name is taken again before
// the put-back, what was staged goes back into the source's directory under
// a staging name, which the refusal and the journal line (set_aside) name.
func TestPrivMoveSwapWindows(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src, other := filepath.Join(f.write, "f.conf"), filepath.Join(f.write, "other.conf")
	dst := filepath.Join(f.write, "d", "f.conf")
	gatetest.Mkdir(t, filepath.Dir(dst), 0o755)
	gatetest.WriteFile(t, src, "checked\n", 0o640)
	gatetest.WriteFile(t, other, "other\n", 0o640)
	f.opts.InjectBeforeCommit = func() {
		if err := unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, other, unix.RENAME_EXCHANGE); err != nil {
			t.Error(err)
		}
	}
	f.fail("priv_move", m{"source": src, "destination": dst}, "exists")
	f.opts.InjectBeforeCommit = nil
	if present(dst) || readFile(t, src) != "other\n" || readFile(t, other) != "checked\n" {
		t.Fatal("the swapped-in file reached the destination, or was not put back")
	}
	f.opts.InjectAfterStage = func(tmp string) error {
		if err := unix.Renameat2(unix.AT_FDCWD, filepath.Join(filepath.Dir(dst), tmp), unix.AT_FDCWD, other, unix.RENAME_EXCHANGE); err != nil {
			return err
		}
		return os.WriteFile(src, []byte("taken\n"), 0o600)
	}
	r := f.serve("priv_move", m{"source": src, "destination": dst})
	f.opts.InjectAfterStage = nil
	if r.OK || r.Error == nil || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, movePrefix) {
		t.Fatalf("%+v, want exists naming where it was put back", r.Error)
	}
	lines := f.auditLines()
	if !strings.Contains(lines[len(lines)-1], `"set_aside":"`+f.write+"/"+movePrefix) {
		t.Fatalf("the journal line does not name the staging entry: %s", lines[len(lines)-1])
	}
	if present(dst) {
		t.Fatal("the swapped-in file reached the destination")
	}
}

// TestPrivMoveStoppedAfterStage: a helper killed between the stage and the
// commit leaves the source staged in the destination's directory, intact.
// The next move into or out of that directory is refused naming it; every
// operation given a path through such a name refuses it; a delete of the
// tree holding it is refused; moved back by hand, it moves again.
func TestPrivMoveStoppedAfterStage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := filepath.Join(f.write, "f.conf")
	dd := filepath.Join(f.write, "d")
	gatetest.Mkdir(t, dd, 0o755)
	gatetest.WriteFile(t, src, "precious\n", 0o640)
	f.opts.InjectAfterStage = func(string) error { return errors.New("killed") }
	r := f.serve("priv_move", m{"source": src, "destination": filepath.Join(dd, "f.conf")})
	f.opts.InjectAfterStage = nil
	if r.OK {
		t.Fatal("the stopped move succeeded")
	}
	ents, err := os.ReadDir(dd)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), movePrefix) {
		t.Fatalf("the destination's directory holds %v, want one staged entry", ents)
	}
	staged := filepath.Join(dd, ents[0].Name())
	if readFile(t, staged) != "precious\n" || present(src) {
		t.Fatal("the staged entry is not the source")
	}
	gatetest.WriteFile(t, filepath.Join(f.write, "g.conf"), "g\n", 0o640)
	gatetest.WriteFile(t, filepath.Join(dd, "h.conf"), "h\n", 0o640)
	f.failMsg("priv_move", m{"source": filepath.Join(f.write, "g.conf"), "destination": filepath.Join(dd, "g.conf")}, "path_denied", movePrefix)
	f.failMsg("priv_move", m{"source": filepath.Join(dd, "h.conf"), "destination": filepath.Join(f.write, "h.conf")}, "path_denied", movePrefix)
	for _, q := range []struct {
		op   string
		args m
	}{
		{"priv_read_file", m{"path": staged}},
		{"priv_stat", m{"path": staged}},
		{"priv_backup_check", m{"path": staged}},
		{"priv_write_file", m{"path": staged, "content_b64": b64("x\n")}},
		{"priv_move", m{"source": staged, "destination": src}},
		{"priv_delete_preview", m{"path": staged}},
		{"priv_delete_preview", m{"path": dd, "recursive": true}},
		{"priv_chmod_preview", m{"path": dd, "mode": "0750", "recursive": true}},
	} {
		f.failMsg(q.op, q.args, "path_denied", movePrefix)
	}
	if readFile(t, staged) != "precious\n" {
		t.Fatal("the staged entry changed")
	}
	if err := os.Rename(staged, src); err != nil {
		t.Fatal(err)
	}
	f.ok("priv_move", m{"source": src, "destination": filepath.Join(dd, "f.conf")}, nil)
	if readFile(t, filepath.Join(dd, "f.conf")) != "precious\n" {
		t.Fatal("not moved after recovery")
	}
}
