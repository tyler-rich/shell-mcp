//go:build linux

package fsx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The moved-in rule (handoff docs/handoff/S4C-PRIVILEGED.md N-6, N-7;
// PRIVILEGED §6, "Files another account could have moved in"): with
// Config.GuardMovedIn (the helper), a file under a directory another
// account could write is read only when that account could read it itself
// (owner-matched or world-readable), and a write or copy over it keeps its
// owner and group only when it is owner-matched. The chain runs from the
// root (inclusive) to the file's parent. Every layout is invented.
//
// An unprivileged test cannot make a file owned by another uid. Another
// account's write access is a group- or world-writable directory, and
// "another account's directory" is the test's own uid left out of the trust
// (trustTest false), as in the chain rule's tests.

type movedEnv struct {
	d, root string
	fs      *FS
	backups []*BackupSource
}

// newMovedEnv makes <d>/r, a read and write root (0755), with the helper's
// configuration. With trustTest the test's uid counts as root's.
func newMovedEnv(t *testing.T, trustTest bool) *movedEnv {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	e := &movedEnv{d: d, root: filepath.Join(d, "r")}
	mkdirMode(t, e.root, 0o755)
	e.fs = e.newFS(t, e.root, trustTest, true)
	return e
}

func (e *movedEnv) newFS(t *testing.T, root string, trustTest, guard bool) *FS {
	t.Helper()
	empty, err := pathx.NewMatcher(nil)
	must(t, err)
	uid := uint32(os.Getuid()) //nolint:gosec // G115: test ids fit
	return New(&Config{
		WriteRoots:      []string{root},
		Deny:            empty,
		Protected:       empty,
		Limits:          Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: 20},
		GuardMovedIn:    guard,
		VerifyReplaced:  true,
		TrustedDirOwner: func(u uint32) bool { return u == 0 || trustTest && u == uid },
		Backup: func(src *BackupSource) error {
			e.backups = append(e.backups, src)
			return nil
		},
	})
}

// mkdirMode makes p with exactly mode (the umask cleared by a chmod).
func mkdirMode(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	must(t, os.MkdirAll(p, 0o700))
	must(t, os.Chmod(p, mode))
}

// putMode writes p with exactly mode.
func putMode(t *testing.T, p, s string, mode os.FileMode) {
	t.Helper()
	must(t, os.WriteFile(p, []byte(s), 0o600))
	must(t, os.Chmod(p, mode))
}

func wantDenied(t *testing.T, err error, dir string) {
	t.Helper()
	wantCode(t, err, protocol.CodePathDenied)
	var fe *Error
	if !asError(err, &fe) || !strings.Contains(fe.Msg, "the directory "+dir+" is ") {
		t.Fatalf("the refusal does not name the directory %s: %v", dir, err)
	}
}

func asError(err error, fe **Error) bool {
	e, ok := err.(*Error) //nolint:errorlint // fsx returns *Error unwrapped
	if ok {
		*fe = e
	}
	return ok
}

// TestMovedInReads: priv_read_file's ReadFile (text and a binary file's
// hash) and a copy's read of its source return a file under an open
// directory only when it is owner-matched or world-readable.
func TestMovedInReads(t *testing.T) {
	for _, c := range []struct {
		name      string
		trustTest bool
		dirMode   os.FileMode
		fileMode  os.FileMode
		ok        bool
	}{
		{"a closed chain", true, 0o755, 0o600, true},
		{"the owner's own directory and file", false, 0o750, 0o600, true},
		{"a world-writable directory", true, 0o777, 0o600, false},
		{"a group-writable directory, the owner's own file", true, 0o770, 0o600, false},
		{"a group-writable directory of another account", false, 0o770, 0o640, false},
		{"a world-readable file in a world-writable directory", true, 0o777, 0o644, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newMovedEnv(t, c.trustTest)
			dir := filepath.Join(e.root, "d")
			mkdirMode(t, dir, c.dirMode)
			text, bin := filepath.Join(dir, "text.conf"), filepath.Join(dir, "blob")
			putMode(t, text, "secret\n", c.fileMode)
			putMode(t, bin, "bin\x00ary", c.fileMode)
			for i, p := range []string{text, bin} {
				r, err := e.fs.ReadFile(p, ReadOptions{})
				dst := filepath.Join(e.root, "copy"+string(rune('a'+i)))
				_, cerr := e.fs.CopyExpecting(p, dst, false, "")
				if c.ok {
					must(t, err)
					must(t, cerr)
					if r.SHA256 == "" {
						t.Fatalf("%s: no hash", p)
					}
					continue
				}
				wantDenied(t, err, dir)
				if r.SHA256 != "" || r.Content != "" {
					t.Fatalf("%s: a refused read returned %+v", p, r)
				}
				wantDenied(t, cerr, dir)
				if _, err := os.Lstat(dst); err == nil {
					t.Fatalf("a refused copy created %s", dst)
				}
			}
			// The gate (no GuardMovedIn) reads as before.
			gate := e.newFS(t, e.root, c.trustTest, false)
			if _, err := gate.ReadFile(text, ReadOptions{}); err != nil {
				t.Fatalf("the gate's read changed: %v", err)
			}
		})
	}
}

// TestMovedInSameParentSwap: a rename within one parent needs write access
// to that parent only, so another account that can write a directory in
// the root can swap a closed sibling directory into the path. The file's
// parent is then closed, but the chain from the root to it is not: the read
// is refused, naming the open directory. A directory above the root is not
// checked per request (check-policy's WARN covers it).
func TestMovedInSameParentSwap(t *testing.T) {
	e := newMovedEnv(t, true)
	app := filepath.Join(e.root, "app")
	mkdirMode(t, app, 0o777) // another account can write it
	secrets := filepath.Join(app, "secrets")
	mkdirMode(t, secrets, 0o755)
	putMode(t, filepath.Join(secrets, "token"), "TOKEN\n", 0o600)
	config := filepath.Join(app, "config")
	must(t, os.Rename(secrets, config))
	_, err := e.fs.ReadFile(filepath.Join(config, "token"), ReadOptions{})
	wantDenied(t, err, app)

	// Above the root: <d>/top is world-writable, the root <d>/top/r2 closed.
	top := filepath.Join(e.d, "top")
	mkdirMode(t, top, 0o777)
	r2 := filepath.Join(top, "r2")
	mkdirMode(t, r2, 0o755)
	putMode(t, filepath.Join(r2, "own"), "own\n", 0o600)
	if _, err := e.newFS(t, r2, true, true).ReadFile(filepath.Join(r2, "own"), ReadOptions{}); err != nil {
		t.Fatalf("a directory above the root was checked per request: %v", err)
	}
}

// TestMovedInOverwrites: a write or copy over an existing file keeps its
// owner and group only when it is owner-matched; otherwise a write needs both
// an owner and a group, and a copy is refused, before anything is backed up
// or written. A new file is not concerned (handoff N-8).
func TestMovedInOverwrites(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	for _, c := range []struct {
		name      string
		trustTest bool
		dirMode   os.FileMode
		inherit   bool
	}{
		{"a closed chain", true, 0o755, true},
		{"the owner's own directory", false, 0o750, true},
		{"a group-writable directory, owners matching", true, 0o770, false},
		{"a world-writable directory", true, 0o777, false},
		{"a group-writable directory of another account", false, 0o770, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newMovedEnv(t, c.trustTest)
			dir := filepath.Join(e.root, "d")
			mkdirMode(t, dir, c.dirMode)
			p := filepath.Join(dir, "app.conf")
			src := filepath.Join(e.root, "src.conf")
			putMode(t, src, "copied\n", 0o644)
			reset := func() { putMode(t, p, "old\n", 0o644) }
			reset()
			_, werr := e.fs.WriteFile(p, []byte("new\n"), WriteOptions{Create: true})
			reset()
			_, cerr := e.fs.CopyExpecting(src, p, true, hexSHA("old\n"))
			if c.inherit {
				must(t, werr)
				must(t, cerr)
				return
			}
			for _, err := range []error{werr, cerr} {
				wantDenied(t, err, dir)
				var fe *Error
				if asError(err, &fe) && !fe.Unchanged {
					t.Fatalf("a refusal before any change is not marked unchanged: %v", err)
				}
			}
			if read(t, p) != "old\n" || len(e.backups) != 0 {
				t.Fatalf("a refused overwrite changed %q or backed up %d", read(t, p), len(e.backups))
			}
			// Only an owner, or only a group, is not enough.
			_, err := e.fs.WriteFile(p, []byte("new\n"), WriteOptions{Create: true, Owner: &Owner{UID: &uid}})
			wantDenied(t, err, dir)
			_, err = e.fs.WriteFile(p, []byte("new\n"), WriteOptions{Create: true, Owner: &Owner{GID: &gid}})
			wantDenied(t, err, dir)
			// Both, given explicitly: written.
			r, err := e.fs.WriteFile(p, []byte("new\n"), WriteOptions{Create: true, Owner: &Owner{UID: &uid, GID: &gid}})
			must(t, err)
			if r.UID != uid || r.GID != gid || read(t, p) != "new\n" || len(e.backups) != 1 {
				t.Fatalf("an explicit owner: %+v, %q, %d backups", r, read(t, p), len(e.backups))
			}
			// A new file there is not concerned (N-8, a follow-up).
			if _, err := e.fs.WriteFile(filepath.Join(dir, "fresh"), []byte("x"), WriteOptions{Create: true}); err != nil {
				t.Fatalf("a new file in an open directory: %v", err)
			}
		})
	}
}

// TestMovedInBy: the predicate on a chain. A directory passes when it is
// neither group- nor world-writable and is root's or the file owner's; the
// first that fails is returned.
func TestMovedInBy(t *testing.T) {
	f := New(&Config{TrustedDirOwner: func(u uint32) bool { return u == 0 }})
	root := ChainDir{Path: "/srv/r", UID: 0, Mode: 0o755}
	app := ChainDir{Path: "/srv/r/app", UID: 1001, Mode: 0o750}
	other := ChainDir{Path: "/srv/r/app/x", UID: 1002, Mode: 0o750}
	shared := ChainDir{Path: "/srv/r/shared", UID: 0, Mode: 0o775}
	sticky := ChainDir{Path: "/srv/r/tmp", UID: 0, Mode: 0o1777}
	for _, c := range []struct {
		chain []ChainDir
		owner uint32
		want  string
	}{
		{nil, 0, ""},
		{[]ChainDir{root}, 1001, ""},
		{[]ChainDir{root, app}, 1001, ""},
		{[]ChainDir{root, app}, 0, app.Path},
		{[]ChainDir{root, app, other}, 1001, other.Path},
		{[]ChainDir{root, shared}, 0, shared.Path},
		{[]ChainDir{root, sticky}, 0, sticky.Path},
		{[]ChainDir{shared, app}, 1001, shared.Path},
		{[]ChainDir{{Path: "/srv/r", UID: 0, Mode: 0o2755}}, 1001, ""},
	} {
		got := f.MovedInBy(c.chain, c.owner)
		switch {
		case c.want == "" && got != nil:
			t.Fatalf("%v owner %d: %+v, want none", c.chain, c.owner, got)
		case c.want != "" && (got == nil || got.Path != c.want):
			t.Fatalf("%v owner %d: %+v, want %s", c.chain, c.owner, got, c.want)
		}
	}
}

// TestWriteChain: the chain from the root (inclusive) to the parent, by
// descriptor, with each directory's owner and mode.
func TestWriteChain(t *testing.T) {
	e := newMovedEnv(t, true)
	mkdirMode(t, filepath.Join(e.root, "a", "b"), 0o750)
	must(t, os.Chmod(filepath.Join(e.root, "a"), 0o770)) //nolint:gosec // G302: a group-writable directory on the chain
	chain, err := e.fs.WriteChain(filepath.Join(e.root, "a", "b", "f"))
	must(t, err)
	uid := uint32(os.Getuid()) //nolint:gosec // G115: test ids fit
	want := []ChainDir{{e.root, uid, 0o755}, {filepath.Join(e.root, "a"), uid, 0o770}, {filepath.Join(e.root, "a", "b"), uid, 0o750}}
	if len(chain) != len(want) {
		t.Fatalf("chain %+v", chain)
	}
	for i := range want {
		if chain[i] != want[i] {
			t.Fatalf("chain[%d] = %+v, want %+v", i, chain[i], want[i])
		}
	}
	if one, oerr := e.fs.WriteChain(filepath.Join(e.root, "f")); oerr != nil || len(one) != 1 || one[0].Path != e.root {
		t.Fatalf("a file in the root: %+v %v", one, oerr)
	}
	_, err = e.fs.WriteChain(filepath.Join(e.root, "missing", "f"))
	wantCode(t, err, protocol.CodeNotFound)
	_, err = e.fs.WriteChain(filepath.Join(e.d, "elsewhere", "f"))
	wantCode(t, err, protocol.CodePathDenied)
}

// FuzzMovedInBy: the predicate returns the first directory that is group- or
// world-writable, or owned by neither a trusted uid nor the owner; nil when
// there is none.
func FuzzMovedInBy(f *testing.F) {
	f.Add([]byte{0, 0, 0o7, 0o55}, uint32(0))
	f.Add([]byte{1, 0, 0o7, 0o50, 0, 0, 0o7, 0o75}, uint32(1))
	f.Fuzz(func(t *testing.T, raw []byte, owner uint32) {
		fs := New(&Config{TrustedDirOwner: func(u uint32) bool { return u == 0 }})
		var chain []ChainDir
		for i := 0; i+3 < len(raw) && len(chain) < 64; i += 4 {
			chain = append(chain, ChainDir{Path: "/d", UID: uint32(raw[i]) % 3, Mode: (uint32(raw[i+2])<<8 | uint32(raw[i+3])) & 0o7777})
		}
		owner %= 3
		want := -1
		for i, d := range chain {
			if d.Mode&0o022 != 0 || d.UID != 0 && d.UID != owner {
				want = i
				break
			}
		}
		got := fs.MovedInBy(chain, owner)
		switch {
		case want < 0 && got != nil:
			t.Fatalf("%v owner %d: %+v, want none", chain, owner, got)
		case want >= 0 && got != &chain[want]:
			t.Fatalf("%v owner %d: %+v, want index %d", chain, owner, got, want)
		}
	})
}
