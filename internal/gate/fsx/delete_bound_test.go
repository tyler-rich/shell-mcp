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
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The helper's delete (PreviewDeleteBound, DeleteExactBound; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-4, D10): the gate's walk and
// set-aside deletion, with the helper's policy hash in the preview hash,
// the backup written from the plan before anything is removed, the entries
// removed reported, and the commit and "unchanged" signals the helper's
// fail-safe backup rule relies on. Every layout is invented.

// planBackup records what a delete handed to the backup hook.
type planBackup struct {
	calls int
	kind  string
	count int
	// walked are the entries Walk visited (rel, with "/" for a directory)
	// and listed those List visited; files their content.
	walked, listed []string
	files          map[string]string
	fail           error
}

func (b *planBackup) hook(src *BackupSource) error {
	b.calls++
	b.kind, b.count = src.Kind, src.Count
	if b.fail != nil {
		return b.fail
	}
	if b.files == nil {
		b.files = map[string]string{}
	}
	if src.Kind == BackupFile {
		c, err := io.ReadAll(src.File)
		if err != nil {
			return err
		}
		b.files[""] = string(c)
		return nil
	}
	if src.List != nil {
		if err := src.List(func(rel string, fi fs.FileInfo) error {
			if fi.IsDir() {
				rel += "/"
			}
			b.listed = append(b.listed, rel)
			return nil
		}); err != nil {
			return err
		}
	}
	return src.Walk(func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error {
		if fi.IsDir() {
			b.walked = append(b.walked, rel+"/")
			return nil
		}
		b.walked = append(b.walked, rel)
		f, err := open()
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		c, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		b.files[rel] = string(c)
		return nil
	})
}

// newBoundEnv is newDelEnv with the helper's backup hook and commit report.
func newBoundEnv(t *testing.T, limit int) (*env, *planBackup, *int) {
	t.Helper()
	e := newDelEnv(t, limit)
	b := &planBackup{}
	commits := 0
	e.fs.cfg.Backup = b.hook
	e.fs.cfg.OnCommit = func() { commits++ }
	return e, b, &commits
}

const binding = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"

// TestPreviewDeleteBoundHash: the helper's preview hash binds its policy
// (its binding) and differs from the gate's for the same tree; the gate's
// hash and DeleteExact are unchanged.
func TestPreviewDeleteBoundHash(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	gate, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	a, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	a2, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	other, err := e.fs.PreviewDeleteBound(dir, true, strings.Repeat("c", 64))
	must(t, err)
	if a.PreviewSHA256 != a2.PreviewSHA256 || !ValidPreviewSHA256(a.PreviewSHA256) {
		t.Fatalf("an unchanged tree hashed differently: %s %s", a.PreviewSHA256, a2.PreviewSHA256)
	}
	if a.PreviewSHA256 == gate.PreviewSHA256 || a.PreviewSHA256 == other.PreviewSHA256 {
		t.Fatalf("the binding is not in the hash: gate %s bound %s other %s", gate.PreviewSHA256, a.PreviewSHA256, other.PreviewSHA256)
	}
	if a.Entries != gate.Entries || a.Bytes != gate.Bytes || !slices.Equal(a.First, gate.First) || a.Type != "dir" {
		t.Fatalf("bound %+v gate %+v", a, gate)
	}
	// Neither hash is accepted by the other function, and nothing is deleted.
	_, err = e.fs.DeleteExactBound(dir, true, binding, gate.PreviewSHA256)
	wantCode(t, err, protocol.CodeExists)
	_, err = e.fs.DeleteExactBound(dir, true, strings.Repeat("c", 64), a.PreviewSHA256)
	wantCode(t, err, protocol.CodeExists)
	_, err = e.fs.DeleteExact(dir, true, a.PreviewSHA256)
	wantCode(t, err, protocol.CodeExists)
	allExist(t, []string{dir + "/a.txt", dir + "/b/d/e.txt"})
	_, err = e.fs.DeleteExactBound(dir, true, binding, "")
	wantCode(t, err, protocol.CodeBadRequest)
	r, err := e.fs.DeleteExactBound(dir, true, binding, a.PreviewSHA256)
	must(t, err)
	if !r.Deleted || exists(dir) {
		t.Fatalf("bound delete %+v", r)
	}
}

// TestDeleteBackupFromPlan: the backup holds exactly the plan's entries, in
// walk order, written before anything is removed; List visits the same
// entries without opening anything, and the preview hands it over; the
// result lists every entry removed.
func TestDeleteBackupFromPlan(t *testing.T) {
	e, b, commits := newBoundEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	paths := mkTree(t, dir)
	want := []string{"a.txt", "b/", "b/c.txt", "b/d/", "b/d/e.txt", "f/"}
	pv, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	if pv.Backup == nil || pv.Backup.Kind != BackupTree || pv.Backup.Count != 6 || pv.Backup.Walk != nil || pv.Backup.File != nil ||
		pv.Backup.Info == nil || !pv.Backup.Info.IsDir() || pv.Backup.List == nil {
		t.Fatalf("the preview's backup source %+v", pv.Backup)
	}
	var listed []string
	must(t, pv.Backup.List(func(rel string, fi fs.FileInfo) error {
		if fi.IsDir() {
			rel += "/"
		}
		listed = append(listed, rel)
		return nil
	}))
	if !slices.Equal(listed, want) || b.calls != 0 || *commits != 0 {
		t.Fatalf("the preview listed %v (backups %d, commits %d)", listed, b.calls, *commits)
	}
	early := false
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, _ string) {
		if s == DeleteStepBeforeEntry && b.calls != 1 {
			early = true
		}
	}
	r, err := e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
	e.fs.cfg.InjectDeleteStep = nil
	must(t, err)
	if early {
		t.Fatal("an entry was removed before the backup was written")
	}
	if b.calls != 1 || b.kind != BackupTree || b.count != 6 || !slices.Equal(b.walked, want) || !slices.Equal(b.listed, want) {
		t.Fatalf("backup: calls %d kind %s count %d walked %v listed %v", b.calls, b.kind, b.count, b.walked, b.listed)
	}
	if b.files["a.txt"] != "aaa" || b.files["b/c.txt"] != "cc" || b.files["b/d/e.txt"] != "e" {
		t.Fatalf("backed-up content %v", b.files)
	}
	got := slices.Clone(r.Removed)
	slices.Sort(got)
	exp := slices.Clone(paths)
	slices.Sort(exp)
	if !slices.Equal(got, exp) || r.Removed[len(r.Removed)-1] != dir || *commits == 0 {
		t.Fatalf("removed %v (want every entry, the target last), commits %d", r.Removed, *commits)
	}
	// A single file is backed up as a file.
	p := filepath.Join(e.write, "one.txt")
	put(t, p, "one")
	*b = planBackup{}
	pv, err = e.fs.PreviewDeleteBound(p, false, binding)
	must(t, err)
	if pv.Backup == nil || pv.Backup.Kind != BackupFile || pv.Backup.Info.Size() != 3 {
		t.Fatalf("file backup source %+v", pv.Backup)
	}
	r, err = e.fs.DeleteExactBound(p, false, binding, pv.PreviewSHA256)
	must(t, err)
	if b.calls != 1 || b.kind != BackupFile || b.files[""] != "one" || !slices.Equal(r.Removed, []string{p}) || exists(p) {
		t.Fatalf("file: %+v backup %+v", r, b)
	}
}

// TestDeleteBackupRefusals: what cannot be backed up is not deleted: a tree
// holding a symlink (backup_failed), a failing hook (its error), and an
// entry replaced or rewritten just before the backup reads it (exists).
// Each is provably unchanged and reports no commit.
func TestDeleteBackupRefusals(t *testing.T) {
	e, b, commits := newBoundEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	check := func(what string, err error, code string, keep []string) {
		t.Helper()
		wantCode(t, err, code)
		var fe *Error
		if !errors.As(err, &fe) || !fe.Unchanged {
			t.Fatalf("%s: the refusal is not marked unchanged: %v", what, err)
		}
		allExist(t, keep)
		if *commits != 0 {
			t.Fatalf("%s: a commit was reported", what)
		}
	}
	dir := filepath.Join(e.write, "withlink")
	paths := mkTree(t, dir)
	must(t, os.Symlink(e.outside, dir+"/b/out"))
	pv, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	_, err = e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
	check("symlink", err, protocol.CodeBackupFailed, append(paths, dir+"/b/out"))

	fifo := filepath.Join(e.write, "fifo")
	must(t, syscall.Mkfifo(fifo, 0o600))
	pv, err = e.fs.PreviewDeleteBound(fifo, false, binding)
	must(t, err)
	_, err = e.fs.DeleteExactBound(fifo, false, binding, pv.PreviewSHA256)
	check("fifo", err, protocol.CodeBackupFailed, []string{fifo})

	dir = filepath.Join(e.write, "hookfails")
	paths = mkTree(t, dir)
	pv, err = e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	b.fail = &Error{Code: protocol.CodeBackupFailed, Msg: "the backup store is full"}
	_, err = e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
	b.fail = nil
	check("hook", err, protocol.CodeBackupFailed, paths)

	for i, how := range []string{"replaced", "rewritten"} {
		dir = filepath.Join(e.write, how)
		paths = mkTree(t, dir)
		pv, err = e.fs.PreviewDeleteBound(dir, true, binding)
		must(t, err)
		victim := dir + "/b/c.txt"
		e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
			if s == DeleteStepBeforeBackupEntry && p == victim {
				if i == 0 {
					replaceFile(t, staging, victim, "racer")
				} else {
					must(t, os.WriteFile(victim, []byte("RACER"), 0o600))
				}
			}
		}
		_, err = e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
		e.fs.cfg.InjectDeleteStep = nil
		check(how, err, protocol.CodeExists, paths)
		if !strings.Contains(err.Error(), "nothing was deleted") {
			t.Fatalf("%s: %v", how, err)
		}
	}
}

// TestDeleteAfterBackupStops: a file written after the backup read it
// stops the delete before that entry is removed (its change time moved),
// so nothing is removed that the backup does not hold as it is now.
func TestDeleteAfterBackupStops(t *testing.T) {
	e, _, commits := newBoundEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	pv, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	victim := dir + "/a.txt" // the first entry the pass removes
	fired := false
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, _ string) {
		if s == DeleteStepAfterBackup {
			fired = true
			spin(20 * time.Millisecond) // a new clock tick for the change time
			must(t, os.WriteFile(victim, []byte("written after the backup"), 0o600))
		}
	}
	r, err := e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
	e.fs.cfg.InjectDeleteStep = nil
	if !fired {
		t.Fatal("the pass never reached the point after the backup")
	}
	wantCode(t, err, protocol.CodeExists)
	if read(t, victim) != "written after the backup" || len(r.Removed) != 0 {
		t.Fatalf("removed %v", r.Removed)
	}
	var fe *Error
	if !errors.As(err, &fe) || !fe.Unchanged || *commits != 0 {
		t.Fatalf("nothing removed, but unchanged %v commits %d", err, *commits)
	}
}

// TestDeleteCommitSignals: a deletion that stops after removing entries
// reports a commit, is not unchanged, and lists exactly the entries it
// removed; one that removed nothing reports none and is unchanged.
func TestDeleteCommitSignals(t *testing.T) {
	e, _, commits := newBoundEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	dir := filepath.Join(e.write, "tree")
	paths := mkTree(t, dir)
	pv, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	victim := dir + "/b/c.txt"
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
		if s == DeleteStepBeforeEntry && p == victim {
			replaceFile(t, staging, victim, "racer")
		}
	}
	r, err := e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
	e.fs.cfg.InjectDeleteStep = nil
	wantCode(t, err, protocol.CodeExists)
	var fe *Error
	if !errors.As(err, &fe) || fe.Unchanged || *commits == 0 || len(r.Removed) == 0 {
		t.Fatalf("a partial deletion: unchanged %v commits %d removed %v", fe != nil && fe.Unchanged, *commits, r.Removed)
	}
	for _, p := range paths {
		if slices.Contains(r.Removed, p) == exists(p) {
			t.Fatalf("%s: removed %v but exists %v", p, slices.Contains(r.Removed, p), exists(p))
		}
	}
	if read(t, victim) != "racer" {
		t.Fatal("the racer's file was changed")
	}
}

// TestDeleteBackupTooLarge: a tree above max_delete_entries is refused by
// the walk, before anything is backed up or removed.
func TestDeleteBackupTooLarge(t *testing.T) {
	e, b, _ := newBoundEnv(t, 20)
	dir := filepath.Join(e.write, "big")
	for i := range 25 {
		put(t, filepath.Join(dir, "f"+strings.Repeat("x", i)), "x")
	}
	_, err := e.fs.PreviewDeleteBound(dir, true, binding)
	wantCode(t, err, protocol.CodeTooLarge)
	_, err = e.fs.DeleteExactBound(dir, true, binding, zeroHash)
	wantCode(t, err, protocol.CodeTooLarge)
	if b.calls != 0 || !exists(filepath.Join(dir, "f")) {
		t.Fatalf("backups %d", b.calls)
	}
}

// TestDeleteStopAfterSetAside: a deletion that stops right after setting an
// entry aside, without unlinking it or putting it back (and so without
// reporting a commit), is not unchanged: the entry is under its temporary
// name, and only explicit accounting (every entry set aside put back, none
// unlinked, none stranded) may say otherwise.
func TestDeleteStopAfterSetAside(t *testing.T) {
	e, _, commits := newBoundEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	pv, err := e.fs.PreviewDeleteBound(dir, true, binding)
	must(t, err)
	victim := dir + "/a.txt" // the first entry the pass handles
	e.fs.cfg.InjectStopAfterSetAside = func(p string) error {
		if p == victim {
			return errors.New("stopped after the set-aside")
		}
		return nil
	}
	r, err := e.fs.DeleteExactBound(dir, true, binding, pv.PreviewSHA256)
	e.fs.cfg.InjectStopAfterSetAside = nil
	if err == nil {
		t.Fatal("the deletion did not stop")
	}
	if exists(victim) || tempNameIn(t, dir) == "" || len(r.Removed) != 0 || *commits != 0 {
		t.Fatalf("victim exists %v, set aside %q, removed %v, commits %d", exists(victim), tempNameIn(t, dir), r.Removed, *commits)
	}
	var fe *Error
	if !errors.As(err, &fe) || fe.Unchanged {
		t.Fatalf("an entry left set aside, neither unlinked nor put back, was reported unchanged: %v", err)
	}
}
