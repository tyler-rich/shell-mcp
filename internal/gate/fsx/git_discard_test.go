//go:build linux

package fsx

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// git_discard's filesystem side: git's index lock as the gate holds it,
// the temporary index, work-tree observation and set-aside. Every layout
// is invented; ".git" is a plain directory here (git itself is exercised
// by the gate's tests).

func newRepoEnv(t *testing.T) (*env, string) {
	t.Helper()
	e := newDelEnv(t, 100)
	repo := filepath.Join(e.write, "repo")
	must(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o750))
	put(t, filepath.Join(repo, ".git", "index"), "old index")
	return e, repo
}

func TestGitIndexLock(t *testing.T) {
	e, repo := newRepoEnv(t)
	lockPath := filepath.Join(repo, ".git", "index.lock")
	k, err := e.fs.LockGitIndex(repo)
	must(t, err)
	if !exists(lockPath) || !strings.HasPrefix(contentAt(t, lockPath), "shell-mcp-gate") {
		t.Fatalf("lock %v %q", exists(lockPath), contentAt(t, lockPath))
	}
	locked, byGate, err := e.fs.GitIndexLockState(repo)
	if err != nil || !locked || !byGate {
		t.Fatalf("state %v %v %v", locked, byGate, err)
	}
	// A second lock is refused while the first is held.
	_, err = e.fs.LockGitIndex(repo)
	wantCode(t, err, protocol.CodeExists)
	// The temporary index is created exclusively inside .git and committed
	// by rename onto .git/index.
	tmp, err := k.NewTempIndex()
	must(t, err)
	if filepath.Dir(tmp) != filepath.Join(repo, ".git") || !strings.HasPrefix(filepath.Base(tmp), ".shell-mcp-index-") || !exists(tmp) {
		t.Fatalf("temp index %q", tmp)
	}
	must(t, os.WriteFile(tmp, []byte("new index"), 0o600))
	must(t, k.CommitTempIndex())
	if contentAt(t, filepath.Join(repo, ".git", "index")) != "new index" || exists(tmp) {
		t.Fatal("the temporary index was not committed")
	}
	k.Release()
	if exists(lockPath) {
		t.Fatal("Release left the lock")
	}
	if locked, _, err = e.fs.GitIndexLockState(repo); err != nil || locked {
		t.Fatalf("state after release %v %v", locked, err)
	}
	k.Release() // twice is harmless
}

func TestGitIndexLockRefusesAndLeavesForeignLocks(t *testing.T) {
	e, repo := newRepoEnv(t)
	lockPath := filepath.Join(repo, ".git", "index.lock")
	// git's own lock (or one it left): refused, never removed.
	put(t, lockPath, "")
	_, err := e.fs.LockGitIndex(repo)
	wantCode(t, err, protocol.CodeExists)
	if locked, byGate, _ := e.fs.GitIndexLockState(repo); !locked || byGate || !exists(lockPath) {
		t.Fatalf("git lock: locked %v byGate %v", locked, byGate)
	}
	must(t, os.Remove(lockPath))
	// A symlink at the lock's name is refused, not followed.
	target := filepath.Join(e.write, "elsewhere")
	must(t, os.Symlink(target, lockPath))
	_, err = e.fs.LockGitIndex(repo)
	wantCode(t, err, protocol.CodeExists)
	if exists(target) {
		t.Fatal("the lock followed a symlink")
	}
	must(t, os.Remove(lockPath))
	// Release removes only its own lock: one replaced meanwhile stays.
	k, err := e.fs.LockGitIndex(repo)
	must(t, err)
	tmp, err := k.NewTempIndex()
	must(t, err)
	must(t, os.Remove(lockPath))
	put(t, lockPath, "someone else's")
	put(t, tmp+".lock", "git's lock for the temporary index")
	k.Release()
	if contentAt(t, lockPath) != "someone else's" {
		t.Fatal("Release removed a lock it did not create")
	}
	if exists(tmp) || exists(tmp+".lock") {
		t.Fatal("Release left the temporary index or its lock")
	}
	must(t, os.Remove(lockPath))
	// .git must be a real directory inside the root.
	other := filepath.Join(e.write, "other")
	must(t, os.MkdirAll(filepath.Join(other, "real-git"), 0o750))
	must(t, os.Symlink("real-git", filepath.Join(other, ".git")))
	_, err = e.fs.LockGitIndex(other)
	wantCode(t, err, protocol.CodePathDenied)
	if exists(filepath.Join(other, "real-git", "index.lock")) {
		t.Fatal("a lock was created through a symlinked .git")
	}
	// Outside the write roots.
	_, err = e.fs.LockGitIndex(e.read)
	wantCode(t, err, protocol.CodePathDenied)
}

func TestObserveWorktree(t *testing.T) {
	e, repo := newRepoEnv(t)
	budget := int64(1 << 20)
	put(t, filepath.Join(repo, "f.txt"), "content")
	must(t, os.Symlink("f.txt", filepath.Join(repo, "lnk")))
	must(t, os.MkdirAll(filepath.Join(repo, "dir"), 0o750))
	put(t, filepath.Join(repo, "file-not-dir"), "x")
	for _, c := range []struct {
		rel, state, blocked string
	}{
		{"f.txt", "file", ""}, {"lnk", "symlink", ""}, {"dir", "dir", ""}, {"missing", "absent", ""},
		{"missing-dir/x", "absent", ""}, {"file-not-dir/x", "absent", "file-not-dir"}, {"lnk/x", "absent", "lnk"},
	} {
		w, err := e.fs.ObserveWorktree(filepath.Join(repo, c.rel), &budget)
		must(t, err)
		if w.State != c.state || (c.blocked == "") != (w.BlockedBy == "") || c.blocked != "" && w.BlockedBy != filepath.Join(repo, c.blocked) {
			t.Fatalf("%s: %+v", c.rel, w)
		}
	}
	w, err := e.fs.ObserveWorktree(filepath.Join(repo, "f.txt"), &budget)
	must(t, err)
	if w.SHA256 != sha256Hex("content") || w.Size != 7 {
		t.Fatalf("file %+v", w)
	}
	l, err := e.fs.ObserveWorktree(filepath.Join(repo, "lnk"), &budget)
	must(t, err)
	if l.SHA256 != sha256Hex("f.txt") {
		t.Fatalf("symlink %+v", l)
	}
	// The hash budget is shared and bounded.
	small := int64(3)
	_, err = e.fs.ObserveWorktree(filepath.Join(repo, "f.txt"), &small)
	wantCode(t, err, protocol.CodeTooLarge)
	// The usual refusals: .git, the protected set, outside the write roots,
	// a set-aside name, a FIFO.
	for _, p := range []string{filepath.Join(repo, ".git", "config"), filepath.Join(e.write, "locked", "x"), filepath.Join(e.read, "x"),
		filepath.Join(repo, ".shell-mcp-delete-0123")} {
		_, err := e.fs.ObserveWorktree(p, &budget)
		wantCode(t, err, protocol.CodePathDenied)
	}
	must(t, unix.Mkfifo(filepath.Join(repo, "fifo"), 0o600))
	_, err = e.fs.ObserveWorktree(filepath.Join(repo, "fifo"), &budget)
	wantCode(t, err, protocol.CodePathDenied)
}

func TestSetAside(t *testing.T) {
	e, repo := newRepoEnv(t)
	budget := int64(1 << 20)
	p := filepath.Join(repo, "f.txt")
	put(t, p, "approved")
	w, err := e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	a, err := e.fs.SetAside(&w)
	must(t, err)
	if exists(p) || contentAt(t, a.Temp()) != "approved" || !strings.HasPrefix(filepath.Base(a.Temp()), ".shell-mcp-delete-") || filepath.Dir(a.Temp()) != repo {
		t.Fatalf("set aside %q", a.Temp())
	}
	must(t, a.PutBack())
	if contentAt(t, p) != "approved" {
		t.Fatal("not put back")
	}
	// The renames may have moved its change time: observe it again.
	w, err = e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	a, err = e.fs.SetAside(&w)
	must(t, err)
	must(t, a.Remove())
	if exists(p) || exists(a.Temp()) {
		t.Fatal("not removed")
	}

	// Changed since it was observed: refused, nothing moved.
	put(t, p, "approved")
	w, err = e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	put(t, p, "changed!") // same size, new content and change time
	_, err = e.fs.SetAside(&w)
	wantCode(t, err, protocol.CodeExists)
	if contentAt(t, p) != "changed!" || tempNameIn(t, repo) != "" {
		t.Fatal("a changed file was moved")
	}
	// Edited in place between the first check and the rename: the content
	// check after the rename catches it, and it is put back.
	w, err = e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, at string) {
		if s == DeleteStepBeforeRename && at == p {
			f, ferr := os.OpenFile(p, os.O_WRONLY, 0) //nolint:gosec // G304: the test's own file
			must(t, ferr)
			_, ferr = f.WriteAt([]byte("CHANGED!"), 0)
			must(t, ferr)
			must(t, f.Close())
		}
	}
	_, err = e.fs.SetAside(&w)
	e.fs.cfg.InjectDeleteStep = nil
	wantCode(t, err, protocol.CodeExists)
	if contentAt(t, p) != "CHANGED!" || tempNameIn(t, repo) != "" {
		t.Fatal("an in-place edit was not put back")
	}
	// Put back over a newcomer: refused, the entry stays set aside and the
	// error names it.
	w, err = e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	a, err = e.fs.SetAside(&w)
	must(t, err)
	put(t, p, "newcomer")
	err = a.PutBack()
	var fe *Error
	if !errors.As(err, &fe) || fe.Code != protocol.CodeExists || fe.SetAside != a.Temp() || !strings.Contains(fe.Msg, a.Temp()) {
		t.Fatalf("put back over a newcomer: %v", err)
	}
	if contentAt(t, p) != "newcomer" || contentAt(t, a.Temp()) != "CHANGED!" {
		t.Fatal("put back replaced the newcomer")
	}
	// Remove refuses an entry written after it was checked, through a
	// descriptor opened before it was set aside: it stays, named.
	must(t, os.Remove(p))
	put(t, p, "open")
	w, err = e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	held, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own file
	must(t, err)
	a, err = e.fs.SetAside(&w)
	must(t, err)
	_, err = held.WriteString(" and written later")
	must(t, err)
	must(t, held.Close())
	err = a.Remove()
	if !errors.As(err, &fe) || fe.Code != protocol.CodeExists || fe.SetAside != a.Temp() {
		t.Fatalf("Remove after a write: %v", err)
	}
	if contentAt(t, a.Temp()) != "open and written later" {
		t.Fatal("the late write was removed")
	}
	// Remove refuses an object replaced under the temporary name.
	_ = os.Remove(p)
	put(t, p, "again")
	w, err = e.fs.ObserveWorktree(p, &budget)
	must(t, err)
	a, err = e.fs.SetAside(&w)
	must(t, err)
	replaceFile(t, repo, a.Temp(), "swapped")
	wantCode(t, a.Remove(), protocol.CodeExists)
	if contentAt(t, a.Temp()) != "swapped" {
		t.Fatal("Remove removed a replaced object")
	}
}

// decodeWorktreeEntry is AppendHash's inverse, for the fuzz target.
func decodeWorktreeEntry(b []byte) (w WorktreeEntry, rest []byte, ok bool) {
	str := func() (string, bool) {
		n, k := binary.Uvarint(b)
		if k <= 0 || uint64(len(b)-k) < n { //nolint:gosec // G115: not negative here
			return "", false
		}
		s := string(b[k : k+int(n)]) //nolint:gosec // G115: n is at most len(b)
		b = b[k+int(n):]
		return s, true
	}
	var p string
	if p, w.id, b, ok = decodePreviewEntry(b); !ok {
		return w, nil, false
	}
	w.Path = p
	if w.State, ok = str(); !ok || len(b) < 4 {
		return w, nil, false
	}
	w.Mode, b = binary.BigEndian.Uint32(b), b[4:]
	w.Size = w.id.size
	if w.SHA256, ok = str(); !ok {
		return w, nil, false
	}
	if w.BlockedBy, ok = str(); !ok {
		return w, nil, false
	}
	return w, b, true
}

// FuzzWorktreeEntryEncoding: an entry's hash input decodes back to exactly
// that entry, two in a row, so different entries never hash alike.
func FuzzWorktreeEntryEncoding(f *testing.F) {
	f.Add("/srv/app/repo/a", "file", uint32(0o644), int64(3), uint64(7), uint64(9), int64(1760000000), uint32(1), true, "ab", "")
	f.Add("", "", uint32(0), int64(0), uint64(0), uint64(0), int64(0), uint32(0), false, "", "/x")
	f.Fuzz(func(t *testing.T, path, state string, mode uint32, size int64, dev, ino uint64, cs int64, cn uint32, hasB bool, sha, blocked string) {
		w := WorktreeEntry{Path: path, State: state, Mode: mode, Size: size, SHA256: sha, BlockedBy: blocked,
			id: ident{typ: unix.S_IFREG, size: size, dev: dev, ino: ino, ctime: unix.StatxTimestamp{Sec: cs, Nsec: cn}, hasBtime: hasB}}
		b := w.AppendHash(nil)
		b = w.AppendHash(b)
		for i := range 2 {
			got, rest, ok := decodeWorktreeEntry(b)
			if !ok || got.Path != w.Path || got.State != w.State || got.Mode != w.Mode || got.Size != w.Size || got.SHA256 != w.SHA256 ||
				got.BlockedBy != w.BlockedBy || got.id != w.id {
				t.Fatalf("entry %d: %+v ok %v; want %+v", i, got, ok, w)
			}
			b = rest
		}
		if len(b) != 0 {
			t.Fatalf("%d bytes left", len(b))
		}
	})
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
