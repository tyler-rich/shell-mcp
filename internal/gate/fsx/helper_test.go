//go:build linux

package fsx

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// These tests cover what the privileged helper adds to fsx: an explicit
// owner on writes and mkdir, Chown, and the backup hook that runs before
// every overwrite, move-over and delete. The gate never sets any of them
// (its tests run with a nil hook and no owner).

func ids(t *testing.T) (uint32, uint32) {
	t.Helper()
	return uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: test process ids fit
}

func ownerOf(t *testing.T, p string) (uint32, uint32) {
	t.Helper()
	fi, err := os.Lstat(p)
	must(t, err)
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
	must(t, err)
	return string(b)
}

// noTemp fails if a temp file was left in dir.
func noTemp(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	must(t, err)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Fatalf("temp file %s left behind", e.Name())
		}
	}
}

func TestWriteWithOwner(t *testing.T) {
	e := newEnv(t)
	uid, gid := ids(t)
	p := filepath.Join(e.write, "owned.txt")
	r, err := e.fs.WriteFile(p, []byte("x"), WriteOptions{Create: true, Owner: &Owner{UID: &uid, GID: &gid}})
	must(t, err)
	if u, g := ownerOf(t, p); u != uid || g != gid || !r.Verified {
		t.Fatalf("owner %d:%d result %+v", u, g, r)
	}
	if os.Getuid() == 0 {
		t.Skip("the refusal case needs a non-root test user")
	}
	// A chown the process may not make fails the write and changes nothing.
	root := uint32(0)
	_, err = e.fs.WriteFile(filepath.Join(e.write, "app.yaml"), []byte("changed\n"), WriteOptions{Create: true, Owner: &Owner{UID: &root}})
	wantCode(t, err, protocol.CodePathDenied)
	if got := read(t, filepath.Join(e.write, "app.yaml")); got != "key: value\n" {
		t.Fatalf("content changed: %q", got)
	}
	noTemp(t, e.write)
}

func TestMkdirAsOwner(t *testing.T) {
	e := newEnv(t)
	uid, gid := ids(t)
	p := filepath.Join(e.write, "a", "b")
	m := os.FileMode(0o750)
	r, err := e.fs.MkdirAs(p, &m, true, &Owner{UID: &uid, GID: &gid})
	must(t, err)
	if u, g := ownerOf(t, p); !r.Created || u != uid || g != gid {
		t.Fatalf("created %v owner %d:%d", r.Created, u, g)
	}
	if os.Getuid() == 0 {
		t.Skip("the refusal case needs a non-root test user")
	}
	root := uint32(0)
	_, err = e.fs.MkdirAs(filepath.Join(e.write, "c"), &m, false, &Owner{UID: &root})
	wantCode(t, err, protocol.CodePathDenied)
	if _, err := os.Lstat(filepath.Join(e.write, "c")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("directory left behind after a failed chown: %v", err)
	}
}

func TestChown(t *testing.T) {
	e := newEnv(t)
	uid, gid := ids(t)
	p := filepath.Join(e.write, "app.yaml")
	r, err := e.fs.Chown(p, Owner{GID: &gid})
	must(t, err)
	if r.Path != p || r.GID != gid || r.UID != uid || r.OldUID != uid {
		t.Fatalf("result %+v", r)
	}
	_, err = e.fs.Chown(p, Owner{})
	wantCode(t, err, protocol.CodeBadRequest)
	_, err = e.fs.Chown(filepath.Join(e.read, "hello.txt"), Owner{GID: &gid})
	wantCode(t, err, protocol.CodePathDenied)
	must(t, os.Symlink(p, filepath.Join(e.write, "link")))
	_, err = e.fs.Chown(filepath.Join(e.write, "link"), Owner{GID: &gid})
	wantCode(t, err, protocol.CodePathDenied)
	put(t, filepath.Join(e.write, "locked"), "x")
	_, err = e.fs.Chown(filepath.Join(e.write, "locked"), Owner{GID: &gid})
	wantCode(t, err, protocol.CodePathDenied)
	sgid := filepath.Join(e.write, "sgid")
	put(t, sgid, "x")
	must(t, os.Chmod(sgid, 0o2750))
	if fi, _ := os.Stat(sgid); fi.Mode()&fs.ModeSetgid != 0 {
		_, err = e.fs.Chown(sgid, Owner{GID: &gid})
		wantCode(t, err, protocol.CodePolicyDenied)
	}
	if os.Getuid() != 0 {
		root := uint32(0)
		_, err = e.fs.Chown(p, Owner{UID: &root})
		wantCode(t, err, protocol.CodePathDenied)
	}
}

// recorder is a backup hook that copies what it is given.
type recorder struct {
	calls []string            // "file:<path>" or "tree:<path>"
	files map[string]string   // path (or path/rel) -> content
	infos map[string]fs.FileMode
	fail  error
	after func() // runs after the copy, before returning (to race the op)
}

func newRecorder() *recorder {
	return &recorder{files: map[string]string{}, infos: map[string]fs.FileMode{}}
}

func (r *recorder) hook(src *BackupSource) error {
	r.calls = append(r.calls, src.Kind+":"+src.Path)
	switch src.Kind {
	case "file":
		b, err := io.ReadAll(src.File)
		if err != nil {
			return err
		}
		r.files[src.Path] = string(b)
	case "tree":
		err := src.Walk(func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error {
			r.infos[rel] = fi.Mode()
			if !fi.Mode().IsRegular() {
				return nil
			}
			f, err := open()
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			b, err := io.ReadAll(f)
			r.files[src.Path+"/"+rel] = string(b)
			return err
		})
		if err != nil {
			return err
		}
	}
	if r.after != nil {
		r.after()
	}
	return r.fail
}

func backupEnv(t *testing.T) (*env, *recorder) {
	t.Helper()
	e := newEnv(t)
	rec := newRecorder()
	e.fs.cfg.Backup = rec.hook
	return e, rec
}

var errHook = &Error{Code: protocol.CodeBackupFailed, Msg: "backup store unavailable"}

func TestBackupBeforeOverwrite(t *testing.T) {
	e, rec := backupEnv(t)
	p := filepath.Join(e.write, "app.yaml")
	// A new file replaces nothing: no backup.
	_, err := e.fs.WriteFile(filepath.Join(e.write, "new.txt"), []byte("n"), WriteOptions{Create: true})
	must(t, err)
	if len(rec.calls) != 0 {
		t.Fatalf("backup of a new file: %v", rec.calls)
	}
	_, err = e.fs.WriteFile(p, []byte("v2\n"), WriteOptions{Create: true})
	must(t, err)
	if !slices.Equal(rec.calls, []string{"file:" + p}) || rec.files[p] != "key: value\n" {
		t.Fatalf("calls %v files %v", rec.calls, rec.files)
	}
	// A failed backup changes nothing.
	rec.fail = errHook
	_, err = e.fs.WriteFile(p, []byte("v3\n"), WriteOptions{Create: true})
	wantCode(t, err, protocol.CodeBackupFailed)
	if got := read(t, p); got != "v2\n" {
		t.Fatalf("content %q after a failed backup", got)
	}
	noTemp(t, e.write)
	// Copy over an existing file backs up the destination.
	rec.fail = nil
	_, err = e.fs.Copy(filepath.Join(e.read, "hello.txt"), p, true)
	must(t, err)
	if rec.calls[len(rec.calls)-1] != "file:"+p || rec.files[p] != "v2\n" {
		t.Fatalf("copy backup %v %v", rec.calls, rec.files)
	}
}

// A file replaced after it was backed up is not overwritten: the backup
// would not hold what the write destroys.
func TestBackupRaceOnOverwrite(t *testing.T) {
	e, rec := backupEnv(t)
	p := filepath.Join(e.write, "app.yaml")
	rec.after = func() {
		put(t, p+".swap", "swapped in\n")
		must(t, os.Rename(p+".swap", p))
	}
	_, err := e.fs.WriteFile(p, []byte("v2\n"), WriteOptions{Create: true})
	wantCode(t, err, protocol.CodeBackupFailed)
	if got := read(t, p); got != "swapped in\n" {
		t.Fatalf("content %q", got)
	}
	noTemp(t, e.write)
}

func TestBackupBeforeMoveOver(t *testing.T) {
	e, rec := backupEnv(t)
	src, dst := filepath.Join(e.write, "src.txt"), filepath.Join(e.write, "app.yaml")
	put(t, src, "moved\n")
	rec.fail = errHook
	_, err := e.fs.Move(src, dst, true)
	wantCode(t, err, protocol.CodeBackupFailed)
	if read(t, dst) != "key: value\n" || read(t, src) != "moved\n" {
		t.Fatal("a failed backup moved something")
	}
	rec.fail = nil
	r, err := e.fs.Move(src, dst, true)
	must(t, err)
	if !r.Replaced || rec.files[dst] != "key: value\n" || read(t, dst) != "moved\n" {
		t.Fatalf("move %+v backups %v", r, rec.files)
	}
	// A move to a new name replaces nothing.
	n := len(rec.calls)
	_, err = e.fs.Move(dst, filepath.Join(e.write, "fresh.txt"), false)
	must(t, err)
	if len(rec.calls) != n {
		t.Fatalf("backup of a move to a new name: %v", rec.calls)
	}
}

func TestBackupBeforeDelete(t *testing.T) {
	e, rec := backupEnv(t)
	p := filepath.Join(e.write, "app.yaml")
	rec.fail = errHook
	_, err := e.fs.Delete(p, false)
	wantCode(t, err, protocol.CodeBackupFailed)
	if read(t, p) != "key: value\n" {
		t.Fatal("deleted after a failed backup")
	}
	rec.fail = nil
	r, err := e.fs.Delete(p, false)
	must(t, err)
	if !r.Deleted || rec.files[p] != "key: value\n" {
		t.Fatalf("delete %+v backups %v", r, rec.files)
	}
	// A tree: every entry is visited, regular files can be read.
	tree := filepath.Join(e.write, "tree")
	put(t, filepath.Join(tree, "a.txt"), "A")
	put(t, filepath.Join(tree, "sub", "b.txt"), "B")
	must(t, os.MkdirAll(filepath.Join(tree, "empty"), 0o750))
	rec.fail = errHook
	_, err = e.fs.Delete(tree, true)
	wantCode(t, err, protocol.CodeBackupFailed)
	if read(t, filepath.Join(tree, "sub", "b.txt")) != "B" {
		t.Fatal("tree deleted after a failed backup")
	}
	rec.fail = nil
	_, err = e.fs.Delete(tree, true)
	must(t, err)
	if rec.files[tree+"/a.txt"] != "A" || rec.files[tree+"/sub/b.txt"] != "B" || !rec.infos["empty"].IsDir() || !rec.infos["sub"].IsDir() {
		t.Fatalf("tree backup files %v infos %v", rec.files, rec.infos)
	}
	if _, err := os.Lstat(tree); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("tree not deleted")
	}
}

// An entry that appears after the tree was backed up stops the delete: it
// is never removed without a backup.
func TestBackupTreeChangedAfterBackup(t *testing.T) {
	e, rec := backupEnv(t)
	tree := filepath.Join(e.write, "tree")
	put(t, filepath.Join(tree, "a.txt"), "A")
	rec.after = func() { put(t, filepath.Join(tree, "late.txt"), "LATE") }
	_, err := e.fs.Delete(tree, true)
	wantCode(t, err, protocol.CodeBackupFailed)
	if read(t, filepath.Join(tree, "late.txt")) != "LATE" {
		t.Fatal("an entry that was never backed up was deleted")
	}
}

// Too many entries are refused before anything is backed up or removed.
func TestBackupTreeTooLarge(t *testing.T) {
	e, rec := backupEnv(t)
	tree := filepath.Join(e.write, "big")
	for i := range 25 { // MaxDeleteEntries is 20
		put(t, filepath.Join(tree, "f"+strings.Repeat("x", i)), "x")
	}
	_, err := e.fs.Delete(tree, true)
	wantCode(t, err, protocol.CodeTooLarge)
	if len(rec.calls) != 0 {
		t.Fatalf("backup attempted: %v", rec.calls)
	}
}
