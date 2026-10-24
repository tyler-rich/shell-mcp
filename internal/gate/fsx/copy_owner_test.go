//go:build linux

package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A copy's owner and group (handoff docs/handoff/S4C-PRIVILEGED.md N-19,
// P-15; PRIVILEGED §6): the helper's copy takes an optional owner and group
// exactly as its write does. Under rule R the owner the copy will have is
// the one given, else the destination's current one, else root's; an
// explicit owner must itself pass (N-6 tightened), and both ids are set on
// the new inode. As in owner_rule_test.go, the test's own uid stands for
// root (trustTest) or for another account (trustTest false). Every layout
// is invented.

// TestCopyOwnerUnderAccountDirectory: under another account's directory
// (closed to everyone else) a copy given that account as its owner lands
// with that owner and group, new or over the account's own file; an
// explicit owner root is refused, naming the one owner that would pass,
// and changes nothing.
func TestCopyOwnerUnderAccountDirectory(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	root := uint32(0)
	e := newMovedEnv(t, false) // the test's uid is another account
	dir := filepath.Join(e.root, "app")
	mkdirMode(t, dir, 0o750)
	src := filepath.Join(e.root, "src.bin")
	putMode(t, src, "binary\n", 0o644)
	fresh, existing := filepath.Join(dir, "fresh.bin"), filepath.Join(dir, "app.bin")
	putMode(t, existing, "old\n", 0o640)
	for _, p := range []string{fresh, existing} {
		_, err := e.fs.CopyAs(src, p, p == existing, "", &Owner{UID: &root, GID: &gid})
		wantDenied(t, err, e.root)
		var fe *Error
		if !asError(err, &fe) || !fe.Unchanged || !strings.Contains(fe.Msg, "uid "+strconv.FormatUint(uint64(uid), 10)) {
			t.Fatalf("%s: the refusal does not name the one owner that would pass (uid %d): %v", p, uid, err)
		}
	}
	if _, err := os.Lstat(fresh); err == nil || read(t, existing) != "old\n" || len(e.backups) != 0 {
		t.Fatalf("a refused owner: root changed something (%d backups)", len(e.backups))
	}
	for _, p := range []string{fresh, existing} {
		r, err := e.fs.CopyAs(src, p, p == existing, "", &Owner{UID: &uid, GID: &gid})
		must(t, err)
		fi, err := os.Lstat(p)
		must(t, err)
		st := fi.Sys().(*syscall.Stat_t)
		if r.UID != uid || r.GID != gid || st.Uid != uid || st.Gid != gid || read(t, p) != "binary\n" {
			t.Fatalf("%s: %+v, on disk %d:%d", p, r, st.Uid, st.Gid)
		}
	}
}

// TestCopyOwnerUnderOpenDirectory: under a directory another account can
// write, no owner passes, given or not, and nothing is created; under a
// closed chain the owner and group given are set.
func TestCopyOwnerUnderOpenDirectory(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	e := newMovedEnv(t, true)
	open := filepath.Join(e.root, "drop")
	mkdirMode(t, open, 0o777)
	src := filepath.Join(e.root, "src.bin")
	putMode(t, src, "binary\n", 0o644)
	p := filepath.Join(open, "copy.bin")
	_, err := e.fs.CopyAs(src, p, false, "", &Owner{UID: &uid, GID: &gid})
	wantDenied(t, err, open)
	if names, _ := os.ReadDir(open); len(names) != 0 {
		t.Fatalf("a refused copy left %v", names)
	}
	r, err := e.fs.CopyAs(src, filepath.Join(e.root, "closed.bin"), false, "", &Owner{UID: &uid, GID: &gid})
	must(t, err)
	if r.UID != uid || r.GID != gid {
		t.Fatalf("a copy under a closed chain: %+v", r)
	}
}

// TestCopyOwnerSetgidGroup: in a closed setgid directory, a copy given a
// group gets that group, never the helper's own; without one it gets the
// helper's (TestNewInodeGroupExplicit). Needs a supplementary group other
// than the test's own; CI's runner user has one, a container user may not.
func TestCopyOwnerSetgidGroup(t *testing.T) {
	egid := uint32(os.Getegid()) //nolint:gosec // G115: test ids fit
	groups, err := os.Getgroups()
	must(t, err)
	other := -1
	for _, g := range groups {
		if uint32(g) != egid { //nolint:gosec // G115: test ids fit
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("the test user has no supplementary group to give a setgid directory")
	}
	og := uint32(other) //nolint:gosec // G115: test ids fit
	e := newMovedEnv(t, true)
	dir := filepath.Join(e.root, "sg")
	mkdirMode(t, dir, 0o755)
	must(t, os.Chown(dir, -1, other))
	must(t, os.Chmod(dir, 0o755|os.ModeSetgid))
	src := filepath.Join(e.root, "src.bin")
	putMode(t, src, "binary\n", 0o644)
	p := filepath.Join(dir, "copy.bin")
	r, err := e.fs.CopyAs(src, p, false, "", &Owner{GID: &og})
	must(t, err)
	fi, err := os.Lstat(p)
	must(t, err)
	if st := fi.Sys().(*syscall.Stat_t); st.Gid != og || r.GID != og {
		t.Fatalf("a copy given group %d: on disk %d, reported %d", og, st.Gid, r.GID)
	}
	if fi.Mode()&(os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != 0 {
		t.Fatalf("the copy has special bits: %v", fi.Mode())
	}
}

// TestCopyOwnerSwapRace: the account that owns a directory swaps what is on
// a path in it (a sibling directory, and a symlink to a directory outside
// the root) again and again while root copies beneath it, given the
// account's owner, or root as the owner. Root's copies are always refused;
// the account's land only in the account's own directories, as its, or are
// refused; nothing ever lands outside the root.
func TestCopyOwnerSwapRace(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	root := uint32(0)
	e := newMovedEnv(t, false)
	app := filepath.Join(e.root, "app")
	mkdirMode(t, app, 0o755)
	a, b := filepath.Join(app, "a"), filepath.Join(app, "b")
	mkdirMode(t, a, 0o755)
	mkdirMode(t, b, 0o755)
	outside := filepath.Join(e.d, "outside")
	mkdirMode(t, outside, 0o755)
	link := filepath.Join(app, "link")
	must(t, os.Symlink(outside, link))
	src := filepath.Join(e.root, "src.bin")
	putMode(t, src, "binary\n", 0o644)
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
	const runs = 300
	landed, refused := 0, map[string]int{}
	fail := func(format string, args ...any) {
		t.Helper()
		close(stop)
		wg.Wait()
		t.Fatalf(format, args...)
	}
	for i := range runs {
		_, rerr := e.fs.CopyAs(src, filepath.Join(a, fmt.Sprintf("r%d", i)), false, "", &Owner{UID: &root, GID: &gid})
		_, oerr := e.fs.CopyAs(src, filepath.Join(a, fmt.Sprintf("o%d", i)), false, "", &Owner{UID: &uid, GID: &gid})
		if rerr == nil {
			fail("run %d: root's copy was left under the account's directory", i)
		}
		var fe *Error
		if !asError(rerr, &fe) || fe.Code != "path_denied" && fe.Code != "not_a_directory" {
			fail("run %d: %v, want path_denied or not_a_directory", i, rerr)
		}
		refused[fe.Code]++
		switch {
		case oerr == nil:
			landed++
		case asError(oerr, &fe) && (fe.Code == "path_denied" || fe.Code == "not_a_directory" || fe.Code == "verify_failed"):
			// The symlink in place at the lookup, or the directory moved
			// before the read-back re-opened the copy: never a success.
			refused[fe.Code]++
		default:
			fail("run %d: the account's copy: %v", i, oerr)
		}
	}
	close(stop)
	wg.Wait()
	if swaps == 0 {
		t.Fatal("the racer never swapped")
	}
	if names, _ := os.ReadDir(outside); len(names) != 0 {
		t.Fatalf("%s holds %d entries after the race", outside, len(names))
	}
	for _, d := range []string{a, b} {
		names, _ := os.ReadDir(d)
		for _, n := range names {
			if strings.HasPrefix(n.Name(), "r") {
				t.Fatalf("root's copy %s/%s is there", d, n.Name())
			}
			fi, err := os.Lstat(filepath.Join(d, n.Name()))
			must(t, err)
			if st := fi.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
				t.Fatalf("%s/%s is %d:%d", d, n.Name(), st.Uid, st.Gid)
			}
		}
	}
	t.Logf("%d copies landed as the account, refused %v, while the racer made %d swaps", landed, refused, swaps)
}
