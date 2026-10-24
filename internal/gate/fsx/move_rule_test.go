//go:build linux

package fsx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The move rule (handoff docs/handoff/S4C-PRIVILEGED.md N-17; PRIVILEGED
// §6, "Moves"), applied with Config.GuardMovedIn (the helper). A move keeps
// its inode, owner and mode, so root moves a non-directory only when its
// owner is owner-matched on the chain from the root to the source's parent
// (another account could not have put it there; no world-readable
// exception) and passes rule R on the chain to the destination's parent
// (another account could not move it on); in a moved tree, both chains are
// extended by the tree's own directories, and every directory of the tree
// must have a mode priv_mkdir could create. The source is staged under
// .shell-mcp-move-<32 hex> in the destination's directory, checked to be
// the inode that was checked, and only then committed; anything else is put
// back. Every layout is invented.
//
// As in moved_in_test.go, the test's own uid stands for root (trustTest)
// or for another account (trustTest false); another account's write access
// is a group- or world-writable directory.

// stagePrefix is the staging name's prefix, spelled out here.
const stagePrefix = ".shell-mcp-move-"

// stagedIn lists the staging names in dir.
func stagedIn(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	must(t, err)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), stagePrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func gone(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); err == nil {
		t.Fatalf("%s exists", p)
	}
}

// wantUnchanged fails unless err is marked unchanged.
func wantUnchanged(t *testing.T, err error) {
	t.Helper()
	var fe *Error
	if !asError(err, &fe) || !fe.Unchanged {
		t.Fatalf("the refusal is not marked unchanged: %v", err)
	}
}

// TestMoveRuleFile: a file moves only when its owner is owner-matched at
// the source and passes rule R at the destination. (a) into a directory
// another account can write, and (b) out of one into a closed directory,
// are refused before anything is backed up or moved, naming the directory;
// a world-readable file gets no exception. The gate is unchanged.
func TestMoveRuleFile(t *testing.T) {
	for _, c := range []struct {
		name             string
		trustTest        bool
		srcMode, dstMode os.FileMode
		fileMode         os.FileMode
		overwrite        bool
		ok               bool
		deniedAt         string // "src" or "dst"
	}{
		{"closed to closed", true, 0o755, 0o755, 0o600, false, true, ""},
		{"(a) into a world-writable directory", true, 0o755, 0o777, 0o600, false, false, "dst"},
		{"(a) into a group-writable directory", true, 0o755, 0o770, 0o600, false, false, "dst"},
		{"(a) into a sticky world-writable directory", true, 0o755, os.ModeSticky | 0o777, 0o600, false, false, "dst"},
		{"(a) over a file in a world-writable directory", true, 0o755, 0o777, 0o600, true, false, "dst"},
		{"(b) out of a world-writable directory", true, 0o777, 0o755, 0o600, false, false, "src"},
		{"(b) out of a group-writable directory", true, 0o770, 0o755, 0o600, false, false, "src"},
		{"(b) a world-readable file gets no exception", true, 0o777, 0o755, 0o644, false, false, "src"},
		{"(b) over a file, out of a world-writable directory", true, 0o777, 0o755, 0o600, true, false, "src"},
		{"the account's own file in its own directories", false, 0o750, 0o750, 0o600, false, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newMovedEnv(t, c.trustTest)
			sd, dd := filepath.Join(e.root, "s"), filepath.Join(e.root, "d")
			mkdirMode(t, sd, c.srcMode)
			mkdirMode(t, dd, c.dstMode)
			src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
			putMode(t, src, "moved\n", c.fileMode)
			if c.overwrite {
				putMode(t, dst, "old\n", 0o600)
			}
			_, err := e.fs.Move(src, dst, c.overwrite)
			if c.ok {
				must(t, err)
				if read(t, dst) != "moved\n" {
					t.Fatal("not moved")
				}
				gone(t, src)
				return
			}
			dir := dd
			if c.deniedAt == "src" {
				dir = sd
			}
			wantDenied(t, err, dir)
			wantUnchanged(t, err)
			if read(t, src) != "moved\n" || len(e.backups) != 0 {
				t.Fatalf("a refused move changed something (%d backups)", len(e.backups))
			}
			if c.overwrite {
				if read(t, dst) != "old\n" {
					t.Fatal("a refused move replaced the destination")
				}
			} else {
				gone(t, dst)
			}
			if s := append(stagedIn(t, sd), stagedIn(t, dd)...); len(s) != 0 {
				t.Fatalf("a refused move left %v", s)
			}
			// The gate is unchanged.
			gate := e.newFS(t, e.root, c.trustTest, false)
			if _, err := gate.Move(src, dst, c.overwrite); err != nil {
				t.Fatalf("the gate's move changed: %v", err)
			}
		})
	}
}

// TestMoveRuleTree: in a moved tree, every non-directory is checked on the
// source and destination chains extended by the tree's own directories; the
// directories themselves are exempt (as priv_mkdir is). A tree planted in a
// directory another account can write, a tree moved into one, and a symlink
// in a tree moved into one, are refused, naming the directory; a tree of
// directories only moves anywhere.
func TestMoveRuleTree(t *testing.T) {
	mk := func(t *testing.T, top string, withLink bool) {
		t.Helper()
		mkdirMode(t, top, 0o755)
		mkdirMode(t, filepath.Join(top, "sub"), 0o755)
		if withLink {
			must(t, os.Symlink("elsewhere", filepath.Join(top, "sub", "l")))
			return
		}
		putMode(t, filepath.Join(top, "a.conf"), "a\n", 0o640)
		putMode(t, filepath.Join(top, "sub", "b.conf"), "b\n", 0o600)
	}
	for _, c := range []struct {
		name             string
		srcMode, dstMode os.FileMode
		dirsOnly, link   bool
		ok               bool
		deniedAt         string
	}{
		{"closed to closed", 0o755, 0o755, false, false, true, ""},
		{"a planted tree, out of a world-writable directory", 0o777, 0o755, false, false, false, "src"},
		{"into a world-writable directory", 0o755, 0o777, false, false, false, "dst"},
		{"into a group-writable directory", 0o755, 0o770, false, false, false, "dst"},
		{"a symlink in the tree, into a world-writable directory", 0o755, 0o777, false, true, false, "dst"},
		{"directories only, into a world-writable directory", 0o755, 0o777, true, false, true, ""},
		{"directories only, out of a world-writable directory", 0o777, 0o755, true, false, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newMovedEnv(t, true)
			sd, dd := filepath.Join(e.root, "s"), filepath.Join(e.root, "d")
			mkdirMode(t, sd, c.srcMode)
			mkdirMode(t, dd, c.dstMode)
			src, dst := filepath.Join(sd, "tree"), filepath.Join(dd, "tree")
			if c.dirsOnly {
				mkdirMode(t, filepath.Join(src, "sub", "deeper"), 0o755)
				mkdirMode(t, filepath.Join(src, "sub"), 0o755)
				mkdirMode(t, src, 0o755)
			} else {
				mk(t, src, c.link)
			}
			_, err := e.fs.Move(src, dst, false)
			if c.ok {
				must(t, err)
				gone(t, src)
				return
			}
			dir := dd
			if c.deniedAt == "src" {
				dir = sd
			}
			wantDenied(t, err, dir)
			wantUnchanged(t, err)
			gone(t, dst)
			if _, err := os.Stat(filepath.Join(src, "sub")); err != nil {
				t.Fatal("a refused move changed the source tree")
			}
			gate := e.newFS(t, e.root, true, false)
			if _, err := gate.Move(src, dst, false); err != nil {
				t.Fatalf("the gate's move changed: %v", err)
			}
		})
	}
}

// TestMoveDirectoryModes: a move whose moved directory, or a directory
// inside the moved tree, has a mode priv_mkdir could not create (bits
// beyond modes.max, group- or world-writable, setuid, setgid or sticky) is
// refused before anything is moved, naming the directory and its mode.
func TestMoveDirectoryModes(t *testing.T) {
	for _, c := range []struct {
		name         string
		top, inner   os.FileMode
		max          os.FileMode // 0: no modes.max (the default bits only)
		ok           bool
		bad, badMode string // the directory named ("top" or "inner") and its mode
	}{
		{"closed", 0o755, 0o750, 0, true, "", ""},
		{"within modes.max", 0o750, 0o700, 0o750, true, "", ""},
		{"world-writable", 0o777, 0o755, 0, false, "top", "0777"},
		{"world-writable, not readable by others", 0o753, 0o755, 0, false, "top", "0753"},
		{"group-writable", 0o775, 0o755, 0, false, "top", "0775"},
		{"sticky", os.ModeSticky | 0o755, 0o755, 0, false, "top", "1755"},
		{"setgid", os.ModeSetgid | 0o755, 0o755, 0, false, "top", "2755"},
		{"beyond modes.max", 0o755, 0o750, 0o750, false, "top", "0755"},
		{"an inner directory world-writable", 0o755, 0o777, 0, false, "inner", "0777"},
		{"an inner directory beyond modes.max", 0o750, 0o755, 0o750, false, "inner", "0755"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newMovedEnv(t, true)
			if c.max != 0 {
				m := c.max
				e.fs.cfg.ModesMax = &m
			}
			src, dst := filepath.Join(e.root, "tree"), filepath.Join(e.root, "moved")
			inner := filepath.Join(src, "inner")
			mkdirMode(t, inner, 0o700)
			must(t, os.Chmod(inner, c.inner))
			must(t, os.Chmod(src, c.top))
			exactMode(t, inner, c.inner)
			exactMode(t, src, c.top)
			_, err := e.fs.Move(src, dst, false)
			if c.ok {
				must(t, err)
				return
			}
			wantCode(t, err, protocol.CodePathDenied)
			wantUnchanged(t, err)
			name := src
			if c.bad == "inner" {
				name = inner
			}
			var fe *Error
			if !asError(err, &fe) || !strings.Contains(fe.Msg, name) || !strings.Contains(fe.Msg, c.badMode) {
				t.Fatalf("the refusal does not name %s and its mode %s: %v", name, c.badMode, err)
			}
			gone(t, dst)
			// The gate is unchanged.
			gate := e.newFS(t, e.root, true, false)
			if _, err := gate.Move(src, dst, false); err != nil {
				t.Fatalf("the gate's move changed: %v", err)
			}
		})
	}
}

// TestMoveStagesInTheDestination: the source is staged under
// .shell-mcp-move-<32 hex> in the destination's directory before the
// commit, so a replaced destination is set aside there and never in the
// source's directory; nothing is left staged afterwards.
func TestMoveStagesInTheDestination(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("overwrite=%v", overwrite), func(t *testing.T) {
			e := newMovedEnv(t, true)
			sd, dd := filepath.Join(e.root, "s"), filepath.Join(e.root, "d")
			mkdirMode(t, sd, 0o755)
			mkdirMode(t, dd, 0o755)
			src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
			putMode(t, src, "new\n", 0o640)
			if overwrite {
				putMode(t, dst, "old\n", 0o640)
			}
			called := 0
			e.fs.cfg.InjectAfterStage = func(tmp string) error {
				called++
				if !strings.HasPrefix(tmp, stagePrefix) || len(tmp) != len(stagePrefix)+32 {
					t.Errorf("staging name %q", tmp)
				}
				if read(t, filepath.Join(dd, tmp)) != "new\n" {
					t.Error("the staged entry is not the source")
				}
				if _, err := os.Lstat(src); err == nil {
					t.Error("the source is still under its name while staged")
				}
				if overwrite && read(t, dst) != "old\n" {
					t.Error("the destination was replaced before the commit")
				}
				return nil
			}
			_, err := e.fs.Move(src, dst, overwrite)
			must(t, err)
			if called != 1 {
				t.Fatalf("staged %d times, want 1", called)
			}
			if read(t, dst) != "new\n" {
				t.Fatal("not moved")
			}
			ents, err := os.ReadDir(sd)
			must(t, err)
			if len(ents) != 0 {
				t.Fatalf("the source's directory holds %d entries after the move", len(ents))
			}
			if s := stagedIn(t, dd); len(s) != 0 {
				t.Fatalf("left staged: %v", s)
			}
		})
	}
}

// TestMoveSwapAfterCheck: the source's name is taken by another object
// after the helper checked it (before the stage), or the staged name is
// (before the commit). Whatever was staged is put back under the source's
// name, nothing reaches the destination, and the move is refused with
// exists, unchanged.
func TestMoveSwapAfterCheck(t *testing.T) {
	for _, when := range []string{"before the stage", "after the stage"} {
		t.Run(when, func(t *testing.T) {
			e := newMovedEnv(t, true)
			sd, dd := filepath.Join(e.root, "s"), filepath.Join(e.root, "d")
			mkdirMode(t, sd, 0o755)
			mkdirMode(t, dd, 0o755)
			src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
			other := filepath.Join(sd, "other.conf")
			putMode(t, src, "checked\n", 0o640)
			putMode(t, other, "other\n", 0o640)
			if when == "before the stage" {
				e.fs.cfg.InjectBeforeCommit = func() {
					must(t, unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, other, unix.RENAME_EXCHANGE))
				}
			} else {
				e.fs.cfg.InjectAfterStage = func(tmp string) error {
					// The staged entry is exchanged for another file.
					return unix.Renameat2(unix.AT_FDCWD, filepath.Join(dd, tmp), unix.AT_FDCWD, other, unix.RENAME_EXCHANGE)
				}
			}
			_, err := e.fs.Move(src, dst, false)
			wantCode(t, err, protocol.CodeExists)
			wantUnchanged(t, err)
			gone(t, dst)
			if s := stagedIn(t, dd); len(s) != 0 {
				t.Fatalf("left staged: %v", s)
			}
			// What was staged went back under the source's name.
			if got := read(t, src); got != "other\n" {
				t.Fatalf("the source's name holds %q, want the swapped-in file put back", got)
			}
			if got := read(t, other); got != "checked\n" {
				t.Fatalf("the swapped-out name holds %q", got)
			}
		})
	}
}

// TestMovePutBackTaken: when the source's name was taken again before what
// was staged could be put back, it goes back into the source's directory
// under a staging name, which the refusal names (Error.SetAside); it is
// not marked unchanged.
func TestMovePutBackTaken(t *testing.T) {
	e := newMovedEnv(t, true)
	sd, dd := filepath.Join(e.root, "s"), filepath.Join(e.root, "d")
	mkdirMode(t, sd, 0o755)
	mkdirMode(t, dd, 0o755)
	src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
	other := filepath.Join(sd, "other.conf")
	putMode(t, src, "checked\n", 0o640)
	putMode(t, other, "other\n", 0o640)
	e.fs.cfg.InjectAfterStage = func(tmp string) error {
		must(t, unix.Renameat2(unix.AT_FDCWD, filepath.Join(dd, tmp), unix.AT_FDCWD, other, unix.RENAME_EXCHANGE))
		putMode(t, src, "taken\n", 0o640)
		return nil
	}
	_, err := e.fs.Move(src, dst, false)
	wantCode(t, err, protocol.CodeExists)
	var fe *Error
	if !asError(err, &fe) || fe.Unchanged || !strings.HasPrefix(filepath.Base(fe.SetAside), stagePrefix) || filepath.Dir(fe.SetAside) != sd ||
		!strings.Contains(fe.Msg, fe.SetAside) {
		t.Fatalf("the refusal does not name where it was put back: %+v", fe)
	}
	if read(t, fe.SetAside) != "other\n" || read(t, src) != "taken\n" {
		t.Fatal("the put-back entry or the source's new file is wrong")
	}
	gone(t, dst)
}

// TestMoveStoppedAfterStage: a helper that stops between the stage and the
// commit (killed) leaves the source under its staging name in the
// destination's directory; nothing is lost. The next move into or out of
// that directory is refused naming the entry, every path through such a
// name is refused (read, stat, write, delete, move), and a delete of a
// tree holding it is refused; once the entry is moved back by hand, moves
// work again. The gate refuses such a name as well.
func TestMoveStoppedAfterStage(t *testing.T) {
	e := newMovedEnv(t, true)
	sd, dd := filepath.Join(e.root, "s"), filepath.Join(e.root, "d")
	mkdirMode(t, sd, 0o755)
	mkdirMode(t, dd, 0o755)
	src, dst := filepath.Join(sd, "f.conf"), filepath.Join(dd, "f.conf")
	putMode(t, src, "precious\n", 0o640)
	stop := errors.New("the helper was killed here")
	e.fs.cfg.InjectAfterStage = func(string) error { return stop }
	_, err := e.fs.Move(src, dst, false)
	if !errors.Is(err, stop) {
		t.Fatalf("%v, want the stop", err)
	}
	e.fs.cfg.InjectAfterStage = nil
	s := stagedIn(t, dd)
	if len(s) != 1 {
		t.Fatalf("staged entries %v, want one", s)
	}
	staged := filepath.Join(dd, s[0])
	if read(t, staged) != "precious\n" {
		t.Fatal("the staged entry lost the source")
	}
	gone(t, src)
	gone(t, dst)
	stranded := func(t *testing.T, err error) {
		t.Helper()
		wantCode(t, err, protocol.CodePathDenied)
		var fe *Error
		if !asError(err, &fe) || !strings.Contains(fe.Msg, stagePrefix) {
			t.Fatalf("the refusal does not name the staged entry: %v", err)
		}
	}
	other := filepath.Join(sd, "g.conf")
	putMode(t, other, "g\n", 0o640)
	_, err = e.fs.Move(other, filepath.Join(dd, "g.conf"), false)
	stranded(t, err)
	out := filepath.Join(dd, "h.conf")
	putMode(t, out, "h\n", 0o640)
	_, err = e.fs.Move(out, filepath.Join(sd, "h.conf"), false)
	stranded(t, err)
	_, err = e.fs.ReadFile(staged, ReadOptions{MaxBytes: 1024})
	stranded(t, err)
	_, err = e.fs.Stat(staged)
	stranded(t, err)
	_, err = e.fs.WriteFile(staged, []byte("x\n"), WriteOptions{Create: true})
	stranded(t, err)
	_, err = e.fs.Move(staged, filepath.Join(sd, "back.conf"), false)
	stranded(t, err)
	_, err = e.fs.PreviewDelete(staged, false)
	stranded(t, err)
	_, err = e.fs.PreviewDelete(dd, true)
	stranded(t, err)
	if read(t, staged) != "precious\n" {
		t.Fatal("the staged entry changed")
	}
	// The gate refuses it too (handoff N-18; TestGateMoveStoppedAfterStage).
	gate := e.newFS(t, e.root, true, false)
	_, err = gate.ReadFile(staged, ReadOptions{MaxBytes: 1024})
	stranded(t, err)
	// Recovered by hand: moves work again.
	must(t, os.Rename(staged, src))
	if _, err := e.fs.Move(src, dst, false); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if read(t, dst) != "precious\n" {
		t.Fatal("not moved after recovery")
	}
}

// FuzzMoveDirMode: a moved directory's mode is refused exactly when it has
// a bit priv_mkdir could not create (beyond modes.max, group- or
// world-writable, setuid, setgid or sticky), and the refusal names it.
func FuzzMoveDirMode(f *testing.F) {
	f.Add(uint16(0o755), uint16(0o755))
	f.Add(uint16(0o2755), uint16(0o755))
	f.Add(uint16(0o750), uint16(0o700))
	f.Add(uint16(0o777), uint16(0))
	f.Fuzz(func(t *testing.T, perm, maxBits uint16) {
		p := uint32(perm) & 0o7777
		fs := New(&Config{})
		allowed := uint32(0o755)
		if maxBits != 0 {
			m := os.FileMode(maxBits & 0o777)
			fs.cfg.ModesMax = &m
			allowed &= uint32(m)
		}
		err := fs.moveDirMode("/srv/r/d", p)
		want := p&^allowed != 0
		if (err != nil) != want {
			t.Fatalf("mode %04o, allowed %04o: refused %v", p, allowed, err)
		}
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("%04o", p)) {
			t.Fatalf("the refusal does not name the mode %04o: %v", p, err)
		}
	})
}

// FuzzStagedComponent: a path is refused, in the helper and in the gate
// (handoff N-18), exactly when one of its components starts with the
// staging prefix.
func FuzzStagedComponent(f *testing.F) {
	f.Add("/srv/r/.shell-mcp-move-0123", "x")
	f.Add("/srv/r/a/b", ".shell-mcp-move-")
	f.Add("/srv/r", "a/.shell-mcp-movex")
	f.Fuzz(func(t *testing.T, base, rel string) {
		p := base + "/" + rel
		want := false
		for _, c := range strings.Split(p, "/") {
			if strings.HasPrefix(c, stagePrefix) {
				want = true
			}
		}
		if hasStagedComponent(p) != want {
			t.Fatalf("%q: staged %v", p, !want)
		}
		helper := New(&Config{GuardMovedIn: true})
		if (helper.stagedRefused(p) != nil) != want {
			t.Fatalf("%q: the helper's refusal disagrees", p)
		}
		if (New(&Config{}).stagedRefused(p) != nil) != want {
			t.Fatalf("%q: the gate's refusal disagrees", p)
		}
	})
}
