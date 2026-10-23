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

// Rule R (handoff docs/handoff/S4C-PRIVILEGED.md N-8, N-9; PRIVILEGED §6,
// "Files another account could have moved in"): with Config.GuardMovedIn
// (the helper), root leaves a regular file at a path only when the owner
// the file will have is owner-matched on the chain from the root to its
// parent: the existing owner (an overwrite keeping it), the owner given, or
// root's (a new file or copy without one). An explicit owner must pass too,
// so owner: root under another account's directory is refused. A refusal
// names the one owner that would pass, when exactly one would. With
// Config.ExplicitOwner every new inode gets both ids set explicitly, so a
// setgid parent never chooses the group. Every layout is invented.
//
// As in moved_in_test.go, the test's own uid stands for root (trustTest)
// or for another account (trustTest false); another account's write access
// is a group- or world-writable directory.

// TestOwnerRuleNewFiles: a new file or copy without an owner (root's) is
// refused under a directory another account can write, before anything is
// written; under a closed chain it is created.
func TestOwnerRuleNewFiles(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	for _, c := range []struct {
		name    string
		dirMode os.FileMode
		ok      bool
	}{
		{"a closed chain", 0o755, true},
		{"a world-writable directory", 0o777, false},
		{"a group-writable directory", 0o770, false},
		{"a sticky world-writable directory", 0o1777, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newMovedEnv(t, true)
			dir := filepath.Join(e.root, "d")
			mkdirMode(t, dir, c.dirMode)
			src := filepath.Join(e.root, "src.conf")
			putMode(t, src, "copied\n", 0o644)
			p, cp := filepath.Join(dir, "new.conf"), filepath.Join(dir, "copy.conf")
			_, werr := e.fs.WriteFile(p, []byte("new\n"), WriteOptions{Create: true})
			_, cerr := e.fs.CopyExpecting(src, cp, false, "")
			if c.ok {
				must(t, werr)
				must(t, cerr)
				return
			}
			for _, err := range []error{werr, cerr} {
				wantDenied(t, err, dir)
				var fe *Error
				if asError(err, &fe) && (!fe.Unchanged || !strings.Contains(fe.Msg, "no owner")) {
					t.Fatalf("the refusal is not unchanged or does not say no owner passes: %+v", fe)
				}
			}
			// An explicit owner and group do not pass either: no owner does.
			_, err := e.fs.WriteFile(p, []byte("new\n"), WriteOptions{Create: true, Owner: &Owner{UID: &uid, GID: &gid}})
			wantDenied(t, err, dir)
			for _, q := range []string{p, cp} {
				if _, serr := os.Lstat(q); serr == nil {
					t.Fatalf("a refused create made %s", q)
				}
			}
			if names, _ := os.ReadDir(dir); len(names) != 0 {
				t.Fatalf("a refused create left %v", names)
			}
			// The gate is unchanged.
			gate := e.newFS(t, e.root, true, false)
			if _, err := gate.WriteFile(p, []byte("gate\n"), WriteOptions{Create: true}); err != nil {
				t.Fatalf("the gate's write changed: %v", err)
			}
		})
	}
}

// TestOwnerRuleExplicitOwner: under another account's directory (closed to
// everyone else), the only owner that passes is that account: an explicit
// owner: root is refused, for a new file and over an existing one (the
// owner: root escape of N-6 is closed), naming the owner that would pass;
// the account's own uid is accepted.
func TestOwnerRuleExplicitOwner(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	root := uint32(0)
	e := newMovedEnv(t, false) // the test's uid is another account
	dir := filepath.Join(e.root, "app")
	mkdirMode(t, dir, 0o750)
	fresh, existing := filepath.Join(dir, "fresh.conf"), filepath.Join(dir, "app.conf")
	putMode(t, existing, "old\n", 0o640)
	// The root itself is the account's here, so it is the directory named.
	for _, p := range []string{fresh, existing} {
		_, err := e.fs.WriteFile(p, []byte("root's\n"), WriteOptions{Create: true, Owner: &Owner{UID: &root, GID: &gid}})
		wantDenied(t, err, e.root)
		var fe *Error
		if !asError(err, &fe) || !fe.Unchanged || !strings.Contains(fe.Msg, "uid "+strconv.FormatUint(uint64(uid), 10)) {
			t.Fatalf("%s: the refusal does not name the one owner that would pass (uid %d): %v", p, uid, err)
		}
	}
	if _, err := os.Lstat(fresh); err == nil || read(t, existing) != "old\n" || len(e.backups) != 0 {
		t.Fatalf("a refused owner: root changed something (%d backups)", len(e.backups))
	}
	// The account's own uid passes: a new file and an overwrite.
	for _, p := range []string{fresh, existing} {
		r, err := e.fs.WriteFile(p, []byte("own\n"), WriteOptions{Create: true, Owner: &Owner{UID: &uid, GID: &gid}})
		must(t, err)
		if r.UID != uid || r.GID != gid || read(t, p) != "own\n" {
			t.Fatalf("%s: %+v", p, r)
		}
	}
	// Kept, it passes too (the file is the account's).
	if _, err := e.fs.WriteFile(existing, []byte("kept\n"), WriteOptions{Create: true}); err != nil {
		t.Fatalf("an owner-matched overwrite keeping its owner: %v", err)
	}
}

// TestOwnerVerdict: the owners a chain allows. Every directory closed: any;
// otherwise the one uid that owns every directory that is not root's, when
// none of them is group- or world-writable; else none. Dir is the first
// directory that is not closed.
func TestOwnerVerdict(t *testing.T) {
	f := New(&Config{TrustedDirOwner: func(u uint32) bool { return u == 0 }})
	root := ChainDir{Path: "/srv/r", UID: 0, Mode: 0o755}
	app := ChainDir{Path: "/srv/r/app", UID: 1001, Mode: 0o750}
	appSub := ChainDir{Path: "/srv/r/app/conf", UID: 1001, Mode: 0o700}
	other := ChainDir{Path: "/srv/r/app/x", UID: 1002, Mode: 0o750}
	shared := ChainDir{Path: "/srv/r/shared", UID: 0, Mode: 0o775}
	sticky := ChainDir{Path: "/srv/r/tmp", UID: 0, Mode: 0o1777}
	appShared := ChainDir{Path: "/srv/r/app/shared", UID: 1001, Mode: 0o770}
	for _, c := range []struct {
		chain []ChainDir
		want  string // "any", "only <uid>" or "none"
		dir   string
	}{
		{nil, "any", ""},
		{[]ChainDir{root}, "any", ""},
		{[]ChainDir{root, {Path: "/srv/r/sg", UID: 0, Mode: 0o2755}}, "any", ""},
		{[]ChainDir{root, app}, "only 1001", app.Path},
		{[]ChainDir{root, app, appSub}, "only 1001", app.Path},
		{[]ChainDir{root, app, other}, "none", app.Path},
		{[]ChainDir{root, shared}, "none", shared.Path},
		{[]ChainDir{root, sticky}, "none", sticky.Path},
		{[]ChainDir{root, app, appShared}, "none", app.Path},
		{[]ChainDir{shared, app}, "none", shared.Path},
	} {
		v := f.OwnerVerdictOf(c.chain)
		got := "none"
		switch {
		case v.Any:
			got = "any"
		case v.UID != nil:
			got = fmt.Sprintf("only %d", *v.UID)
		}
		gotDir := ""
		if v.Dir != nil {
			gotDir = v.Dir.Path
		}
		if got != c.want || gotDir != c.dir {
			t.Fatalf("%v: %s (dir %q), want %s (dir %q)", c.chain, got, gotDir, c.want, c.dir)
		}
	}
}

// FuzzOwnerVerdict: the verdict allows exactly the owners MovedInBy
// accepts, for every uid the chain names and for root.
func FuzzOwnerVerdict(f *testing.F) {
	f.Add([]byte{0, 0, 0o7, 0o55})
	f.Add([]byte{1, 0, 0o7, 0o50, 0, 0, 0o7, 0o75})
	f.Add([]byte{0, 0, 0o7, 0o55, 1, 0, 0o7, 0o50, 1, 0, 0o7, 0o00})
	f.Add([]byte{0, 0, 0o7, 0o55, 1, 0, 0o7, 0o50, 2, 0, 0o7, 0o50})
	f.Fuzz(func(t *testing.T, raw []byte) {
		fs := New(&Config{TrustedDirOwner: func(u uint32) bool { return u == 0 }})
		var chain []ChainDir
		for i := 0; i+3 < len(raw) && len(chain) < 64; i += 4 {
			chain = append(chain, ChainDir{Path: "/d" + strconv.Itoa(i), UID: uint32(raw[i]) % 3, Mode: (uint32(raw[i+2])<<8 | uint32(raw[i+3])) & 0o7777})
		}
		v := fs.OwnerVerdictOf(chain)
		for owner := range uint32(3) {
			passes := fs.MovedInBy(chain, owner) == nil
			allowed := v.Any || v.UID != nil && *v.UID == owner
			if passes != allowed {
				t.Fatalf("%v owner %d: MovedInBy passes %v, verdict %+v", chain, owner, passes, v)
			}
		}
		first := -1
		for i, d := range chain {
			if d.Mode&0o022 != 0 || d.UID != 0 {
				first = i
				break
			}
		}
		switch {
		case first < 0 && (!v.Any || v.Dir != nil):
			t.Fatalf("%v: closed chain, verdict %+v", chain, v)
		case first >= 0 && (v.Any || v.Dir == nil || *v.Dir != chain[first]):
			t.Fatalf("%v: verdict %+v, want the first open directory %d", chain, v, first)
		}
	})
}

// TestOwnerRuleSwapRace: another account that can write a directory swaps
// what is on the path (a closed sibling directory, and a symlink to a closed
// directory outside the root) again and again while root creates files
// beneath it. Every create is refused, and nothing is ever created, in the
// directories swapped in or outside.
func TestOwnerRuleSwapRace(t *testing.T) {
	e := newMovedEnv(t, true)
	app := filepath.Join(e.root, "app")
	mkdirMode(t, app, 0o777) // another account's write access
	a, b := filepath.Join(app, "a"), filepath.Join(app, "b")
	mkdirMode(t, a, 0o755)
	mkdirMode(t, b, 0o755)
	outside := filepath.Join(e.d, "outside")
	mkdirMode(t, outside, 0o755)
	link := filepath.Join(app, "link")
	must(t, os.Symlink(outside, link))
	src := filepath.Join(e.root, "src.conf")
	putMode(t, src, "copied\n", 0o644)
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
	refused := 0
	for i := range runs {
		_, werr := e.fs.WriteFile(filepath.Join(a, fmt.Sprintf("w%d", i)), []byte("x\n"), WriteOptions{Create: true})
		_, cerr := e.fs.CopyExpecting(src, filepath.Join(a, fmt.Sprintf("c%d", i)), false, "")
		for _, err := range []error{werr, cerr} {
			if err == nil {
				close(stop)
				wg.Wait()
				t.Fatalf("run %d: root created a file under a directory another account can write", i)
			}
			wantCode(t, err, "path_denied")
			refused++
		}
	}
	close(stop)
	wg.Wait()
	if swaps == 0 {
		t.Fatal("the racer never swapped")
	}
	for _, d := range []string{a, b, outside} {
		if names, _ := os.ReadDir(d); len(names) != 0 {
			t.Fatalf("%s holds %d entries after the race", d, len(names))
		}
	}
	t.Logf("%d creates refused while the racer made %d swaps", refused, swaps)
}

// TestNewInodeGroupExplicit: in a setgid directory (closed, so rule R lets
// root create there), a new file, copy or directory without a group gets
// the helper's own group, never the directory's, so the approval page's
// "root" is true; with a group given it gets that one. The gate keeps the
// kernel's inheritance. Needs a supplementary group other than the test's
// own; CI's runner user has one, a container user may not.
func TestNewInodeGroupExplicit(t *testing.T) {
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
	for _, guard := range []bool{true, false} {
		t.Run(fmt.Sprintf("helper=%v", guard), func(t *testing.T) {
			e := newMovedEnv(t, true)
			fs := e.newFS(t, e.root, true, guard)
			dir := filepath.Join(e.root, "sg")
			mkdirMode(t, dir, 0o755)
			must(t, os.Chown(dir, -1, other))
			must(t, os.Chmod(dir, 0o755|os.ModeSetgid))
			src := filepath.Join(e.root, "src.conf")
			putMode(t, src, "copied\n", 0o644)
			want := egid
			if !guard {
				want = uint32(other) //nolint:gosec // G115: test ids fit
			}
			w, err := fs.WriteFile(filepath.Join(dir, "new.conf"), []byte("new\n"), WriteOptions{Create: true})
			must(t, err)
			c, err := fs.CopyExpecting(src, filepath.Join(dir, "copy.conf"), false, "")
			must(t, err)
			_, err = fs.MkdirAs(filepath.Join(dir, "sub"), nil, false, nil)
			must(t, err)
			for _, p := range []string{"new.conf", "copy.conf", "sub"} {
				fi, err := os.Lstat(filepath.Join(dir, p))
				must(t, err)
				st := fi.Sys().(*syscall.Stat_t)
				if st.Gid != want {
					t.Fatalf("%s: group %d, want %d", p, st.Gid, want)
				}
				if p == "sub" && guard && fi.Mode()&os.ModeSetgid != 0 {
					t.Fatalf("%s kept the parent's setgid bit", p)
				}
			}
			if guard && (w.GID != egid || c.GID != egid) {
				t.Fatalf("reported groups %d %d, want %d", w.GID, c.GID, egid)
			}
		})
	}
}
