//go:build linux

package fsx

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The gate's delete and delete_preview (PreviewDelete, DeleteExact):
// refusals, the preview binding, and what may change between the preview,
// the gate's recompute and the last unlink. Every layout is invented.

// newDelEnv is newEnv with .git protected (as the policy's built-in set
// has it), a second write root nested inside the first, and limit as
// max_delete_entries.
func newDelEnv(t *testing.T, limit int) *env {
	t.Helper()
	e := newEnv(t)
	deny, err := pathx.NewMatcher([]string{e.secrets + "/**", "**/*.key"})
	must(t, err)
	prot, err := pathx.NewMatcher([]string{"**/.ssh", "**/.git", e.write + "/locked"})
	must(t, err)
	nested := filepath.Join(e.write, "holder", "inner")
	must(t, os.MkdirAll(nested, 0o750))
	e.fs = New(&Config{
		ReadRoots:  []string{e.read},
		WriteRoots: []string{e.write, nested},
		Deny:       deny,
		Protected:  prot,
		Limits:     Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: limit},
	})
	return e
}

// mkTree makes dir with 7 entries (itself included) and 6 bytes:
// a.txt, b/, b/c.txt, b/d/, b/d/e.txt, f/.
func mkTree(t *testing.T, dir string) []string {
	t.Helper()
	put(t, filepath.Join(dir, "a.txt"), "aaa")
	put(t, filepath.Join(dir, "b", "c.txt"), "cc")
	put(t, filepath.Join(dir, "b", "d", "e.txt"), "e")
	must(t, os.MkdirAll(filepath.Join(dir, "f"), 0o750))
	return []string{dir, dir + "/a.txt", dir + "/b", dir + "/b/c.txt", dir + "/b/d", dir + "/b/d/e.txt", dir + "/f"}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func allExist(t *testing.T, paths []string) {
	t.Helper()
	for _, p := range paths {
		if !exists(p) {
			t.Fatalf("%s was removed", p)
		}
	}
}

// noTempNames: no entry set aside by a deletion is left anywhere under dir.
func noTempNames(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(filepath.Base(p), ".shell-mcp-delete-") {
			t.Fatalf("a temporary name was left behind: %s", p)
		}
		return nil
	})
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func TestValidPreviewSHA256(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if !ValidPreviewSHA256(good) {
		t.Fatal("refused a valid hash")
	}
	for _, s := range []string{"", good[:63], good + "0", strings.ToUpper(good), good[:63] + "g", good[:63] + " ", "sha256:" + good[7:]} {
		if ValidPreviewSHA256(s) {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestPreviewDeleteReportsTheTree(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	paths := mkTree(t, dir)
	pv, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	if pv.Type != "dir" || pv.Entries != 7 || pv.Bytes != 6 || pv.Deleted || !slices.Equal(pv.First, paths) || !ValidPreviewSHA256(pv.PreviewSHA256) {
		t.Fatalf("preview %+v", pv)
	}
	again, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	if again.PreviewSHA256 != pv.PreviewSHA256 {
		t.Fatal("an unchanged tree previewed with another hash")
	}
	allExist(t, paths)

	f, err := e.fs.PreviewDelete(dir+"/a.txt", false)
	must(t, err)
	if f.Type != "file" || f.Entries != 1 || f.Bytes != 3 || !slices.Equal(f.First, []string{dir + "/a.txt"}) || f.PreviewSHA256 == pv.PreviewSHA256 {
		t.Fatalf("file preview %+v", f)
	}

	// first holds at most 50 entries; the hash covers them all.
	big := filepath.Join(e.write, "big")
	for i := range 60 {
		put(t, filepath.Join(big, fmt.Sprintf("f%02d", i)), "x")
	}
	b, err := e.fs.PreviewDelete(big, true)
	must(t, err)
	if b.Entries != 61 || len(b.First) != 50 || b.Bytes != 60 {
		t.Fatalf("big preview: %d entries, %d listed", b.Entries, len(b.First))
	}
	must(t, os.Remove(filepath.Join(big, "f59")))
	b2, err := e.fs.PreviewDelete(big, true)
	must(t, err)
	if b2.PreviewSHA256 == b.PreviewSHA256 {
		t.Fatal("removing an entry beyond the first 50 left the hash unchanged")
	}
}

func TestDeleteExactRemovesThePreview(t *testing.T) {
	e := newDelEnv(t, 100)
	file := filepath.Join(e.write, "one.txt")
	put(t, file, "12345")
	pv, err := e.fs.PreviewDelete(file, false)
	must(t, err)
	d, err := e.fs.DeleteExact(file, false, pv.PreviewSHA256)
	must(t, err)
	if !d.Deleted || d.Entries != 1 || d.Bytes != 5 || d.PreviewSHA256 != pv.PreviewSHA256 || exists(file) {
		t.Fatalf("file delete %+v", d)
	}

	empty := filepath.Join(e.write, "empty")
	must(t, os.Mkdir(empty, 0o750))
	pv, err = e.fs.PreviewDelete(empty, false)
	must(t, err)
	if _, err = e.fs.DeleteExact(empty, false, pv.PreviewSHA256); err != nil || exists(empty) {
		t.Fatalf("empty dir: %v", err)
	}

	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	pv, err = e.fs.PreviewDelete(dir, true)
	must(t, err)
	d, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	must(t, err)
	if !d.Deleted || d.Entries != 7 || exists(dir) {
		t.Fatalf("tree delete %+v", d)
	}
	if !exists(filepath.Join(e.write, "app.yaml")) {
		t.Fatal("a sibling was removed")
	}
	noTempNames(t, e.write)
}

// refusal checks one refused path for the preview and for delete, and that
// nothing under keep changed.
func refusal(t *testing.T, e *env, p string, recursive bool, code string, keep []string) {
	t.Helper()
	_, err := e.fs.PreviewDelete(p, recursive)
	wantCode(t, err, code)
	_, err = e.fs.DeleteExact(p, recursive, zeroHash)
	wantCode(t, err, code)
	allExist(t, keep)
}

func TestDeleteExactRefusals(t *testing.T) {
	e := newDelEnv(t, 20)
	w := e.write
	t.Run("the root of a write root", func(t *testing.T) {
		refusal(t, e, w, true, protocol.CodePathDenied, []string{w + "/app.yaml"})
		refusal(t, e, w+"/holder/inner", true, protocol.CodePathDenied, []string{w + "/holder/inner"})
	})
	t.Run("a tree holding a configured root", func(t *testing.T) {
		put(t, w+"/holder/inner/x", "x")
		refusal(t, e, w+"/holder", true, protocol.CodePathDenied, []string{w + "/holder/inner/x"})
	})
	t.Run("outside the write roots", func(t *testing.T) {
		refusal(t, e, e.read+"/hello.txt", false, protocol.CodePathDenied, []string{e.read + "/hello.txt"})
		refusal(t, e, e.outside+"/passwd", false, protocol.CodePathDenied, []string{e.outside + "/passwd"})
	})
	t.Run("protected", func(t *testing.T) {
		put(t, w+"/home/.ssh/authorized_keys", "k")
		refusal(t, e, w+"/home", true, protocol.CodePathDenied, []string{w + "/home/.ssh/authorized_keys"})
		refusal(t, e, w+"/home/.ssh", true, protocol.CodePathDenied, []string{w + "/home/.ssh/authorized_keys"})
		put(t, w+"/locked", "l")
		refusal(t, e, w+"/locked", false, protocol.CodePathDenied, []string{w + "/locked"})
	})
	t.Run(".git", func(t *testing.T) {
		put(t, w+"/repo/.git/config", "[core]\n")
		put(t, w+"/repo/README", "r")
		keep := []string{w + "/repo/.git/config", w + "/repo/README"}
		refusal(t, e, w+"/repo/.git/config", false, protocol.CodePathDenied, keep)
		refusal(t, e, w+"/repo/.git", true, protocol.CodePathDenied, keep)
		refusal(t, e, w+"/repo", true, protocol.CodePathDenied, keep)
	})
	t.Run("deny list", func(t *testing.T) {
		put(t, w+"/server.key", "k")
		refusal(t, e, w+"/server.key", false, protocol.CodePathDenied, []string{w + "/server.key"})
		put(t, w+"/keys/a.key", "k")
		put(t, w+"/keys/readme", "r")
		refusal(t, e, w+"/keys", true, protocol.CodePathDenied, []string{w + "/keys/a.key", w + "/keys/readme"})
	})
	t.Run("final symlink", func(t *testing.T) {
		must(t, os.Symlink(e.outside, w+"/link"))
		refusal(t, e, w+"/link", true, protocol.CodePathDenied, []string{w + "/link", e.outside + "/passwd"})
	})
	t.Run("non-recursive non-empty directory", func(t *testing.T) {
		paths := mkTree(t, w+"/nr")
		refusal(t, e, w+"/nr", false, protocol.CodeBadRequest, paths)
	})
	t.Run("above max_delete_entries", func(t *testing.T) {
		var keep []string
		for i := range 25 {
			p := fmt.Sprintf("%s/big/f%02d", w, i)
			put(t, p, "x")
			keep = append(keep, p)
		}
		refusal(t, e, w+"/big", true, protocol.CodeTooLarge, keep)
	})
	t.Run("missing and unclean", func(t *testing.T) {
		refusal(t, e, w+"/nope", false, protocol.CodeNotFound, nil)
		refusal(t, e, w+"/./app.yaml", false, protocol.CodeBadRequest, []string{w + "/app.yaml"})
	})
	t.Run("expected_preview_sha256", func(t *testing.T) {
		paths := mkTree(t, w+"/h")
		pv, err := e.fs.PreviewDelete(w+"/h", true)
		must(t, err)
		if !ValidPreviewSHA256(pv.PreviewSHA256) || len(pv.PreviewSHA256) != 64 {
			t.Fatalf("preview has no preview_sha256: %q", pv.PreviewSHA256)
		}
		for _, bad := range []string{"", pv.PreviewSHA256[:63], strings.ToUpper(pv.PreviewSHA256), pv.PreviewSHA256 + "0"} {
			_, err = e.fs.DeleteExact(w+"/h", true, bad)
			wantCode(t, err, protocol.CodeBadRequest)
		}
		// A well-formed hash of another tree.
		_, err = e.fs.DeleteExact(w+"/h", true, zeroHash)
		wantCode(t, err, protocol.CodeExists)
		allExist(t, paths)
	})
}

func TestDeleteSymlinksAreRemovedNotFollowed(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "withlinks")
	put(t, dir+"/x", "xy")
	must(t, os.Symlink(e.outside, dir+"/out-dir"))            // a directory outside every root
	must(t, os.Symlink(e.outside+"/passwd", dir+"/out-file")) // a file outside
	must(t, os.Symlink("../app.yaml", dir+"/in-file"))        // a file inside the root
	put(t, e.write+"/linked/keep.txt", "keep")
	must(t, os.Symlink(e.write+"/linked", dir+"/in-dir")) // a directory inside the root
	pv, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	if pv.Entries != 6 || pv.Bytes != 2 {
		t.Fatalf("preview followed a link: %+v", pv)
	}
	_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	must(t, err)
	if exists(dir) {
		t.Fatal("tree still exists")
	}
	if contentAt(t, e.outside+"/passwd") != "OUTSIDE" || contentAt(t, e.write+"/app.yaml") != "key: value\n" || contentAt(t, e.write+"/linked/keep.txt") != "keep" {
		t.Fatal("a link's target was changed")
	}
}

func contentAt(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return string(b)
}

// TestPreviewHashCoversEveryEntry: the hash changes when an entry is added,
// removed, renamed, resized, modified in place, or replaced by another
// inode (also with the same name, size and content, and a directory
// recreated under its name, which may reuse the inode number).
func TestPreviewHashCoversEveryEntry(t *testing.T) {
	e := newDelEnv(t, 100)
	mutations := []struct {
		name string
		do   func(t *testing.T, dir string)
	}{
		{"added", func(t *testing.T, dir string) { put(t, dir+"/b/d/new.txt", "n") }},
		{"added empty dir", func(t *testing.T, dir string) { must(t, os.Mkdir(dir+"/f/g", 0o750)) }},
		{"removed", func(t *testing.T, dir string) { must(t, os.Remove(dir+"/b/c.txt")) }},
		{"renamed", func(t *testing.T, dir string) { must(t, os.Rename(dir+"/b/c.txt", dir+"/b/c2.txt")) }},
		{"moved to another directory", func(t *testing.T, dir string) { must(t, os.Rename(dir+"/b/c.txt", dir+"/f/c.txt")) }},
		{"resized", func(t *testing.T, dir string) {
			f, err := os.OpenFile(dir+"/a.txt", os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: test fixture
			must(t, err)
			_, err = f.WriteString("a")
			must(t, errors.Join(err, f.Close()))
		}},
		{"modified in place, same size", func(t *testing.T, dir string) {
			f, err := os.OpenFile(dir+"/a.txt", os.O_WRONLY, 0) //nolint:gosec // G304: test fixture
			must(t, err)
			_, err = f.WriteString("bbb")
			must(t, errors.Join(err, f.Close()))
		}},
		{"replaced by another inode, same content", func(t *testing.T, dir string) {
			put(t, dir+"/b/tmp", "aaa")
			must(t, os.Rename(dir+"/b/tmp", dir+"/a.txt"))
		}},
		{"directory recreated", func(t *testing.T, dir string) {
			must(t, os.Remove(dir+"/f"))
			must(t, os.Mkdir(dir+"/f", 0o750))
		}},
	}
	for i, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			dir := filepath.Join(e.write, fmt.Sprintf("h%d", i))
			mkTree(t, dir)
			pv, err := e.fs.PreviewDelete(dir, true)
			must(t, err)
			time.Sleep(10 * time.Millisecond) // timestamps move on
			m.do(t, dir)
			after, err := e.fs.PreviewDelete(dir, true)
			must(t, err)
			if after.PreviewSHA256 == pv.PreviewSHA256 {
				t.Fatalf("%s: the preview hash did not change", m.name)
			}
			_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
			wantCode(t, err, protocol.CodeExists)
		})
	}
}

// mountPoint returns a file or directory this test can see that is a mount
// point and whose parent is not /, or "".
func mountPoint(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	mounts := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fl := strings.Fields(sc.Text()); len(fl) > 4 {
			mounts[fl[4]] = true
		}
	}
	for _, c := range []string{"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"} {
		if mounts[c] {
			return c
		}
	}
	return ""
}

// TestDeleteRefusesAMountPoint: a mount point is never deleted or entered.
// Containers bind-mount files under /etc; where none is visible the case
// is skipped here and covered by e2e-host (a tmpfs inside a write root,
// and a tree holding one).
func TestDeleteRefusesAMountPoint(t *testing.T) {
	mp := mountPoint(t)
	if mp == "" {
		t.Skip("no mount point under /etc is visible here; e2e-host covers mount points")
	}
	none, err := pathx.NewMatcher(nil)
	must(t, err)
	f := New(&Config{WriteRoots: []string{filepath.Dir(mp)}, Deny: none, Protected: none, Limits: Limits{MaxDeleteEntries: 10}})
	for _, err := range []error{
		func() error { _, err := f.PreviewDelete(mp, false); return err }(),
		func() error { _, err := f.DeleteExact(mp, false, zeroHash); return err }(),
	} {
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), "mount") {
			t.Fatalf("refusal does not name the mount point: %v", err)
		}
	}
	if !exists(mp) {
		t.Fatal("the mount point is gone")
	}
}

func TestDeleteNoReplaceUnsupported(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EINVAL, syscall.ENOSYS} {
		e := newDelEnv(t, 100)
		dir := filepath.Join(e.write, "tree")
		paths := mkTree(t, dir)
		pv, err := e.fs.PreviewDelete(dir, true)
		must(t, err)
		e.fs.cfg.InjectNoReplaceFault = func() error { return errno }
		_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
		wantCode(t, err, protocol.CodeBadRequest)
		if !strings.Contains(err.Error(), "RENAME_NOREPLACE") || !strings.Contains(err.Error(), "nothing was deleted") {
			t.Fatalf("message: %v", err)
		}
		allExist(t, paths)
	}
}

// --- windows -------------------------------------------------------------------

const deleteWindowRuns = 200

// replaceFile puts content at p as a new inode (rename over it, or create
// it when p is free), staging the file in staging first.
func replaceFile(t *testing.T, staging, p, content string) {
	t.Helper()
	tmp := filepath.Join(staging, "racer-"+randHex(8))
	must(t, os.WriteFile(tmp, []byte(content), 0o600))
	must(t, os.Rename(tmp, p))
}

// TestDeleteWindowBeforeTheRecompute: the tree changes between the preview
// and the delete request (a newcomer, or an entry replaced by another
// inode). The gate's recompute differs: exists, and nothing is deleted.
func TestDeleteWindowBeforeTheRecompute(t *testing.T) {
	e := newDelEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	for i := range deleteWindowRuns {
		dir := filepath.Join(e.write, fmt.Sprintf("w%d", i))
		paths := mkTree(t, dir)
		pv, err := e.fs.PreviewDelete(dir, true)
		must(t, err)
		racer := fmt.Sprintf("racer %d", i)
		planted := dir + "/b/d/newcomer"
		if i%2 == 1 {
			planted = dir + "/b/c.txt"
		}
		replaceFile(t, staging, planted, racer)
		_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
		wantCode(t, err, protocol.CodeExists)
		allExist(t, paths)
		if contentAt(t, planted) != racer {
			t.Fatalf("run %d: the newcomer was changed", i)
		}
	}
	t.Logf("before the recompute: %d runs, every newcomer survived and nothing was deleted", deleteWindowRuns)
}

// TestDeleteWindowAfterTheRecompute: the tree changes after the gate's
// recompute matched, before anything is removed. The newcomer survives;
// the deletion stops with exists and reports what it deleted.
func TestDeleteWindowAfterTheRecompute(t *testing.T) {
	e := newDelEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	for i := range deleteWindowRuns {
		dir := filepath.Join(e.write, fmt.Sprintf("w%d", i))
		mkTree(t, dir)
		pv, err := e.fs.PreviewDelete(dir, true)
		must(t, err)
		racer := fmt.Sprintf("racer %d", i)
		planted := []string{dir + "/b/d/newcomer", dir + "/b/c.txt", dir + "/f/newcomer", dir + "/a.txt"}[i%4]
		fired := false
		e.fs.cfg.InjectDeleteStep = func(s DeleteStep, _ string) {
			if s == DeleteStepAfterCompare {
				fired = true
				replaceFile(t, staging, planted, racer)
			}
		}
		_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
		e.fs.cfg.InjectDeleteStep = nil
		if !fired {
			t.Fatalf("run %d: the deletion pass never reached the point after the recompute", i)
		}
		wantCode(t, err, protocol.CodeExists)
		if !strings.Contains(err.Error(), "of 7 entries") {
			t.Fatalf("run %d: the refusal does not report what was deleted: %v", i, err)
		}
		if contentAt(t, planted) != racer {
			t.Fatalf("run %d: the newcomer was changed", i)
		}
		noTempNames(t, dir)
	}
	t.Logf("after the recompute: %d runs, every newcomer survived", deleteWindowRuns)
}

// TestDeleteWindowDuringDeletion: at every point of the deletion pass, for
// every entry in turn, something new appears: the entry is replaced by
// another inode under its name (or, once it was set aside, a newcomer takes
// the free name); for a directory, a newcomer appears inside it, also
// inside its temporary name once it was set aside (a racer that reads the
// directory can find that name). The newcomer always survives, at the path
// where it appeared, and no temporary name is left.
func TestDeleteWindowDuringDeletion(t *testing.T) {
	t.Parallel()
	e := newDelEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	steps := []DeleteStep{DeleteStepBeforeEntry, DeleteStepBeforeRename, DeleteStepAfterRename, DeleteStepBeforeUnlink}
	perStep := map[DeleteStep]int{}
	succeeded := 0
	for i := range deleteWindowRuns {
		dir := filepath.Join(e.write, fmt.Sprintf("w%d", i))
		paths := mkTree(t, dir)
		pv, err := e.fs.PreviewDelete(dir, true)
		must(t, err)
		victim := paths[i%len(paths)]
		step := steps[(i/len(paths))%len(steps)]
		racer := fmt.Sprintf("racer %d", i)
		var planted string
		e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
			if s != step || p != victim || planted != "" {
				return
			}
			fi, lerr := os.Lstat(victim)
			switch {
			case lerr == nil && fi.IsDir():
				planted = victim + "/newcomer"
				replaceFile(t, staging, planted, racer)
			case lerr == nil:
				planted = victim
				replaceFile(t, staging, planted, racer)
			default: // set aside: the name is free
				if tmp := tempNameIn(t, filepath.Dir(victim)); tmp != "" && fiIsDir(t, tmp) {
					// A newcomer inside the set-aside directory; if it is
					// restored, it is back under the directory's name.
					must(t, os.WriteFile(tmp+"/newcomer", []byte(racer), 0o600))
					planted = victim + "/newcomer"
					return
				}
				planted = victim
				replaceFile(t, staging, planted, racer)
			}
		}
		_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
		e.fs.cfg.InjectDeleteStep = nil
		if planted == "" {
			t.Fatalf("run %d: the deletion pass never reached step %d of %s", i, step, victim)
		}
		perStep[step]++
		if err == nil {
			// Only possible when the newcomer took the target's own name
			// after the target was set aside.
			if victim != dir {
				t.Fatalf("run %d: delete succeeded although %s changed at step %d", i, victim, step)
			}
			succeeded++
		} else {
			wantCode(t, err, protocol.CodeExists)
		}
		if got := contentAt(t, planted); got != racer {
			t.Fatalf("run %d (step %d, %s): the newcomer was changed: %q", i, step, victim, got)
		}
		noTempNames(t, e.write)
	}
	t.Logf("during deletion: %d runs (per step: %v), every newcomer survived; %d runs completed (newcomer under the target's freed name)",
		deleteWindowRuns, perStep, succeeded)
}

func tempNameIn(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	must(t, err)
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), ".shell-mcp-delete-") {
			return filepath.Join(dir, en.Name())
		}
	}
	return ""
}

func fiIsDir(t *testing.T, p string) bool {
	t.Helper()
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// TestDeleteConcurrentRacer: no hook. A goroutine starts after a random
// delay of up to the deletion's measured duration and then, until the
// delete returns, keeps creating new files in random directories of the
// tree and replacing random files of the tree by other inodes. Every file
// it managed to create survives, in every run, at its path or, in the one
// documented case (racerRunProblem), reported under a temporary name.
func TestDeleteConcurrentRacer(t *testing.T) {
	t.Parallel()
	const runs = 400
	e := newDelEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	// The deletion's duration: the median of a few.
	var durs []time.Duration
	for i := range 9 {
		cal := filepath.Join(e.write, fmt.Sprintf("calibrate%d", i))
		mkRacerTree(t, cal)
		pv, err := e.fs.PreviewDelete(cal, true)
		must(t, err)
		start := time.Now()
		_, err = e.fs.DeleteExact(cal, true, pv.PreviewSHA256)
		must(t, err)
		durs = append(durs, time.Since(start))
	}
	slices.Sort(durs)
	dur := max(durs[len(durs)/2], 20*time.Microsecond)

	var atRecompute, during, stranded, completed, planted int
	for i := range runs {
		dir := filepath.Join(e.write, fmt.Sprintf("r%d", i))
		files := mkRacerTree(t, dir)
		pv, err := e.fs.PreviewDelete(dir, true)
		must(t, err)
		w := racerWrites{}
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			spin(time.Duration(jitter(int64(dur))))
			for k := 0; ; k++ {
				select {
				case <-done:
					return
				default:
				}
				var p string
				if k%2 == 0 {
					p = fmt.Sprintf("%s/s%d/new-%d", dir, 1+pick(3), k)
				} else {
					p = files[pick(len(files))]
				}
				if racerPut(staging, p, fmt.Sprintf("racer %d.%d", i, k), w) != nil {
					return
				}
				spin(time.Duration(jitter(int64(dur/8) + 1)))
			}
		})
		_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
		close(done)
		wg.Wait()
		switch {
		case err == nil:
			completed++
		case strings.Contains(err.Error(), "changed since the preview"):
			wantCode(t, err, protocol.CodeExists)
			atRecompute++
		default:
			wantCode(t, err, protocol.CodeExists)
			during++
		}
		planted += len(w)
		aside, problem := racerRunProblem(e.write, files, w, err)
		if problem != nil {
			t.Fatalf("run %d: %v", i, problem)
		}
		if aside != "" {
			stranded++
			// Recovered as an operator would (POLICY §3), so that every
			// later run is checked for temporary names of its own.
			must(t, os.Remove(aside))
		}
	}
	t.Logf("concurrent racer: %d runs (a deletion takes ~%v): %d refused at the recompute, %d stopped during deletion (%d of them leaving the racer's "+
		"earlier file set aside, reported), %d completed before the racer changed anything; %d racer files, every one survived",
		runs, dur, atRecompute, during, stranded, completed, planted)
}

// mkRacerTree makes the racer's tree under dir (s1, s2 and s3, each with
// the files f0 to f3) and returns its files.
func mkRacerTree(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	for _, s := range []string{"s1", "s2", "s3"} {
		for j := range 4 {
			p := fmt.Sprintf("%s/%s/f%d", dir, s, j)
			put(t, p, "data")
			files = append(files, p)
		}
	}
	return files
}

// racerWrites records every file a racer put into a tree, by path, in the
// order it put them: each later one at a path replaced the one before.
type racerWrites map[string][]string

// racerPut puts content at p as a new inode, staged in staging, as the
// racer does: it creates p or replaces what is there, and is recorded in w
// only when its rename succeeded. An error means it could not stage it.
func racerPut(staging, p, content string, w racerWrites) error {
	tmp := filepath.Join(staging, "racer-"+randHex(8))
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if os.Rename(tmp, p) != nil {
		_ = os.Remove(tmp)
		return nil
	}
	w[p] = append(w[p], content)
	return nil
}

// tempNames lists every entry under dir whose name has the set-aside
// prefix.
func tempNames(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(filepath.Base(p), ".shell-mcp-delete-") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// racerRunProblem checks one racer run, after DeleteExact returned err:
// every file the racer put into the tree is still there with the content
// it put last (each earlier one was replaced by the racer itself), and no
// entry is left set aside anywhere under root, with one exception, the
// documented one (POLICY §3, "Entries set aside and not removed"). The
// racer replaced a listed file after its check under its name and before
// it was set aside, so what was set aside failed its check; and it took
// the name again before the put-back. The racer's earlier file then stays
// under its temporary name. That is accepted only when it is the one
// entry left set aside under root; the refusal is exists, not unchanged,
// and names it (Error.SetAside, and the message with the listed file it
// was set aside from); that file is one of the tree's, in the same
// directory; and the entry is a regular file holding one of the racer's
// earlier writes at that file, not its last (which holds the name). It
// returns the path of the entry it accepted ("" when there is none).
func racerRunProblem(root string, files []string, w racerWrites, err error) (string, error) {
	for p, cs := range w {
		if got, rerr := os.ReadFile(p); rerr != nil || string(got) != cs[len(cs)-1] { //nolint:gosec // G304: test fixture
			return "", fmt.Errorf("the racer's file %s was deleted or changed (%v): the deletion removed something it never saw", p, rerr)
		}
	}
	left := tempNames(root)
	var fe *Error
	reported := errors.As(err, &fe) && fe.SetAside != ""
	switch {
	case len(left) == 0 && !reported:
		return "", nil
	case len(left) == 0:
		return "", fmt.Errorf("the refusal names %s as set aside, but no temporary name was left", fe.SetAside)
	case len(left) > 1:
		return "", fmt.Errorf("%d temporary names were left behind: %v", len(left), left)
	case !reported:
		return "", fmt.Errorf("a temporary name was left behind without being reported: %s (%v)", left[0], err)
	}
	aside := left[0]
	if fe.SetAside != aside || fe.Code != protocol.CodeExists || fe.Unchanged || !strings.Contains(fe.Msg, "it was left, not deleted, as "+aside) {
		return "", fmt.Errorf("the entry left as %s is not the one the refusal reports: %+v", aside, fe)
	}
	from := ""
	for _, p := range files {
		if strings.Contains(fe.Msg, "the entry set aside from "+p+" could not be put back") {
			from = p
		}
	}
	if from == "" || filepath.Dir(from) != filepath.Dir(aside) {
		return "", fmt.Errorf("the entry left as %s was not set aside from a file of the tree in its directory: %s", aside, fe.Msg)
	}
	fi, lerr := os.Lstat(aside)
	got, rerr := os.ReadFile(aside) //nolint:gosec // G304: test fixture
	if cs := w[from]; lerr != nil || rerr != nil || !fi.Mode().IsRegular() || len(cs) < 2 || !slices.Contains(cs[:len(cs)-1], string(got)) {
		return "", fmt.Errorf("the entry left as %s is not one of the racer's earlier files at %s (%q, %v)", aside, from, got, errors.Join(lerr, rerr))
	}
	return aside, nil
}

// putBackTaken deletes the racer's tree under dir while its victim
// s2/f1 is replaced, after its check under its name and before it is set
// aside, by first, and then, once it was set aside and before it can be
// put back, by the racer ("racer 0.3", recorded in w). It returns the
// tree's files, the victim and the delete's error.
func putBackTaken(t *testing.T, e *env, dir string, w racerWrites, first func(staging, victim string)) (files []string, victim string, err error) {
	t.Helper()
	staging := filepath.Join(e.write, "staging")
	must(t, os.MkdirAll(staging, 0o750))
	files = mkRacerTree(t, dir)
	pv, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	victim = dir + "/s2/f1"
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
		if p != victim {
			return
		}
		switch s {
		case DeleteStepBeforeRename: // the object set aside is not the listed one
			first(staging, victim)
		case DeleteStepAfterRename: // and its name is taken again before the put-back
			must(t, racerPut(staging, victim, "racer 0.3", w))
		default:
		}
	}
	_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	e.fs.cfg.InjectDeleteStep = nil
	return files, victim, err
}

// TestDeleteRacerPutBackTaken: the sequence TestDeleteConcurrentRacer
// reaches under load, driven through the deletion's steps. The racer
// replaces a listed file after its check under its name and before it is
// set aside, so what is set aside (the racer's file) fails its check; and
// it replaces the file again before the put-back, so the put-back finds
// the name taken. That is POLICY §3's "Entries set aside and not removed":
// the racer's first file stays under its temporary name, reported as such,
// and nothing else is lost or deleted. The racer's checks accept exactly
// that.
func TestDeleteRacerPutBackTaken(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	w := racerWrites{}
	files, victim, err := putBackTaken(t, e, dir, w, func(staging, victim string) {
		must(t, racerPut(staging, victim, "racer 0.1", w))
	})
	wantCode(t, err, protocol.CodeExists)
	aside, problem := racerRunProblem(e.write, files, w, err)
	if problem != nil {
		t.Fatal(problem)
	}
	if aside == "" || contentAt(t, aside) != "racer 0.1" || contentAt(t, victim) != "racer 0.3" {
		t.Fatalf("set aside %q: not the racer's first file, or the name does not hold its second", aside)
	}
	// Bottom-up: s1's four files, s1 and s2/f0 were removed before the
	// victim; nothing after it was.
	var fe *Error
	if !errors.As(err, &fe) || !strings.Contains(fe.Msg, "6 of 16 entries were deleted") {
		t.Fatalf("the refusal does not say what was deleted: %v", err)
	}
	var left []string
	must(t, filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		left = append(left, p)
		return err
	}))
	want := []string{dir, dir + "/s2", aside, dir + "/s2/f1", dir + "/s2/f2", dir + "/s2/f3", dir + "/s3", dir + "/s3/f0", dir + "/s3/f1", dir + "/s3/f2", dir + "/s3/f3"}
	if !slices.Equal(left, want) {
		t.Fatalf("left %v, want %v", left, want)
	}
}

// TestRacerRunProblemRejects: the racer's checks accept nothing but the
// documented case. Each case starts from it, or from the closest sequence
// a deletion can be driven through, and changes one thing.
func TestRacerRunProblemRejects(t *testing.T) {
	cases := []struct {
		name string
		// run deletes the racer's tree under dir and changes the tree
		// after it, and returns the tree's files, the racer's writes and
		// the delete's error.
		run func(t *testing.T, e *env, dir string) ([]string, racerWrites, error)
	}{
		{"left set aside without being reported", func(t *testing.T, e *env, dir string) ([]string, racerWrites, error) {
			files := mkRacerTree(t, dir)
			pv, err := e.fs.PreviewDelete(dir, true)
			must(t, err)
			e.fs.cfg.InjectStopAfterSetAside = func(p string) error {
				if p == dir+"/s2/f1" {
					return errors.New("stopped after the set-aside")
				}
				return nil
			}
			_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
			e.fs.cfg.InjectStopAfterSetAside = nil
			return files, racerWrites{}, err
		}},
		{"a directory left set aside", func(t *testing.T, e *env, dir string) ([]string, racerWrites, error) {
			files := mkRacerTree(t, dir)
			pv, err := e.fs.PreviewDelete(dir, true)
			must(t, err)
			w := racerWrites{}
			e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
				if p != dir+"/s1" || s != DeleteStepAfterRename {
					return
				}
				must(t, os.WriteFile(tempNameIn(t, dir)+"/inside", []byte("newcomer inside"), 0o600))
				must(t, racerPut(filepath.Join(e.write, "staging"), dir+"/s1", "racer 0.1", w))
			}
			must(t, os.MkdirAll(filepath.Join(e.write, "staging"), 0o750))
			_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
			e.fs.cfg.InjectDeleteStep = nil
			return files, w, err
		}},
		{"set aside, but not one of the racer's files", func(t *testing.T, e *env, dir string) ([]string, racerWrites, error) {
			w := racerWrites{}
			files, _, err := putBackTaken(t, e, dir, w, func(staging, victim string) { replaceFile(t, staging, victim, "not the racer's") })
			return files, w, err
		}},
		{"a second temporary name", func(t *testing.T, e *env, dir string) ([]string, racerWrites, error) {
			w := racerWrites{}
			files, _, err := putBackTaken(t, e, dir, w, func(staging, victim string) { must(t, racerPut(staging, victim, "racer 0.1", w)) })
			put(t, dir+"/s3/.shell-mcp-delete-0123456789abcdef0123456789abcdef", "stray")
			return files, w, err
		}},
		{"a racer file lost", func(t *testing.T, e *env, dir string) ([]string, racerWrites, error) {
			w := racerWrites{}
			files, victim, err := putBackTaken(t, e, dir, w, func(staging, victim string) { must(t, racerPut(staging, victim, "racer 0.1", w)) })
			must(t, os.Remove(victim))
			return files, w, err
		}},
		{"reported, but nothing left set aside", func(t *testing.T, e *env, dir string) ([]string, racerWrites, error) {
			w := racerWrites{}
			files, _, err := putBackTaken(t, e, dir, w, func(staging, victim string) { must(t, racerPut(staging, victim, "racer 0.1", w)) })
			must(t, os.Remove(tempNameIn(t, dir+"/s2")))
			return files, w, err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDelEnv(t, 100)
			files, w, err := c.run(t, e, filepath.Join(e.write, "tree"))
			if aside, problem := racerRunProblem(e.write, files, w, err); problem == nil {
				t.Fatalf("accepted (set aside %q; %v)", aside, err)
			} else {
				t.Logf("refused: %v", problem)
			}
		})
	}
}

// spin waits d without sleeping (time.Sleep oversleeps at this scale).
func spin(d time.Duration) {
	until := time.Now().Add(d)
	for time.Now().Before(until) {
		runtime.Gosched()
	}
}

// jitter and pick are test timing and choices, not secrets.
func jitter(n int64) int64 { return rand.Int64N(n) } //nolint:gosec // G404: test jitter

func pick(n int) int { return rand.IntN(n) } //nolint:gosec // G404: test choice
