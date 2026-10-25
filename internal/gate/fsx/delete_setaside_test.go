//go:build linux

package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Entries a delete set aside and could not put back, hard links, and the
// RENAME_NOREPLACE probe. Every layout is invented.

// TestDeletePutBackFails: an entry replaced under a listed name is set
// aside, fails its check, and cannot be put back because its name was
// taken again meanwhile. It stays under the fixed-prefix temporary name,
// the refusal names that path (also in Error.SetAside), it is never
// deleted, and no later preview or delete touches it until an operator
// recovers it.
func TestDeletePutBackFails(t *testing.T) {
	e := newDelEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	pv, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	victim := dir + "/b/c.txt"
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
		if p != victim {
			return
		}
		switch s {
		case DeleteStepBeforeRename: // the object that will be set aside is not the listed one
			replaceFile(t, staging, victim, "newcomer A")
		case DeleteStepAfterRename: // and its name is taken again before it can be put back
			replaceFile(t, staging, victim, "newcomer B")
		default:
		}
	}
	_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	e.fs.cfg.InjectDeleteStep = nil
	wantCode(t, err, protocol.CodeExists)
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatal(err)
	}
	aside := tempNameIn(t, dir+"/b")
	if aside == "" || fe.SetAside != aside || !strings.Contains(fe.Msg, aside) || !strings.HasPrefix(filepath.Base(aside), ".shell-mcp-delete-") {
		t.Fatalf("set aside %q; error %+v", aside, fe)
	}
	if contentAt(t, aside) != "newcomer A" || contentAt(t, victim) != "newcomer B" {
		t.Fatal("a newcomer was changed")
	}
	// Never deleted afterwards, under any path.
	_, err = e.fs.PreviewDelete(dir, true)
	wantCode(t, err, protocol.CodePathDenied)
	if !strings.Contains(err.Error(), "set aside") {
		t.Fatalf("refusal does not say why: %v", err)
	}
	_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	wantCode(t, err, protocol.CodePathDenied)
	for _, p := range []string{aside, dir + "/b"} {
		_, err = e.fs.PreviewDelete(p, true)
		wantCode(t, err, protocol.CodePathDenied)
		_, err = e.fs.DeleteExact(p, true, zeroHash)
		wantCode(t, err, protocol.CodePathDenied)
	}
	if contentAt(t, aside) != "newcomer A" {
		t.Fatal("the set-aside entry was changed")
	}
}

// TestDeletePutBackFailsForADirectory: a directory that gained an entry
// while set aside cannot be removed and cannot be put back (its name was
// taken again); it stays set aside with the newcomer inside.
func TestDeletePutBackFailsForADirectory(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	pv, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	victim := dir + "/b/d"
	e.fs.cfg.InjectDeleteStep = func(s DeleteStep, p string) {
		if p != victim || s != DeleteStepAfterRename {
			return
		}
		tmp := tempNameIn(t, dir+"/b")
		must(t, os.WriteFile(tmp+"/inside", []byte("newcomer inside"), 0o600))
		must(t, os.WriteFile(victim, []byte("name taken"), 0o600))
	}
	_, err = e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	e.fs.cfg.InjectDeleteStep = nil
	wantCode(t, err, protocol.CodeExists)
	aside := tempNameIn(t, dir+"/b")
	var fe *Error
	if !errors.As(err, &fe) || aside == "" || fe.SetAside != aside || !strings.Contains(fe.Msg, aside) {
		t.Fatalf("set aside %q; error %v", aside, err)
	}
	if contentAt(t, aside+"/inside") != "newcomer inside" || contentAt(t, victim) != "name taken" {
		t.Fatal("a newcomer was changed")
	}
}

// TestDeleteRefusesSetAsideNames: a name with the set-aside prefix, left
// by an earlier delete that could not put an entry back or that died
// part-way, is never previewed or deleted: an operator recovers it first.
func TestDeleteRefusesSetAsideNames(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	paths := mkTree(t, dir)
	stray := dir + "/b/.shell-mcp-delete-0123456789abcdef0123456789abcdef"
	put(t, stray, "left by a gate that died")
	for _, p := range []string{dir, dir + "/b", stray} {
		_, err := e.fs.PreviewDelete(p, true)
		wantCode(t, err, protocol.CodePathDenied)
		_, err = e.fs.DeleteExact(p, true, zeroHash)
		wantCode(t, err, protocol.CodePathDenied)
	}
	allExist(t, append(paths, stray))
}

// TestDeleteHardLinks: one inode under several listed names. Removing one
// name changes the inode's change time (its link count), which must not
// stop the removal of the others.
func TestDeleteHardLinks(t *testing.T) {
	e := newDelEnv(t, 100)
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	must(t, os.Link(dir+"/a.txt", dir+"/a-link"))
	must(t, os.Link(dir+"/a.txt", dir+"/b/d/a-link"))
	// Change times are coarse (a clock tick): let the removals land in a later
	// tick than the links, as they would on a real host.
	time.Sleep(20 * time.Millisecond)
	pv, err := e.fs.PreviewDelete(dir, true)
	must(t, err)
	time.Sleep(20 * time.Millisecond)
	d, err := e.fs.DeleteExact(dir, true, pv.PreviewSHA256)
	must(t, err)
	if !d.Deleted || d.Entries != 9 || exists(dir) {
		t.Fatalf("delete %+v", d)
	}
}

// TestProbeNoReplace: the probe answers for a write root's filesystem and
// leaves nothing behind.
func TestProbeNoReplace(t *testing.T) {
	d := t.TempDir()
	if err := ProbeNoReplace(d); err != nil {
		t.Fatalf("probe on the test filesystem: %v", err)
	}
	ents, err := os.ReadDir(d)
	must(t, err)
	if len(ents) != 0 {
		t.Fatalf("the probe left %v", ents)
	}
	if err := ProbeNoReplace(filepath.Join(d, "missing")); err == nil || errors.Is(err, ErrNoReplaceUnsupported) {
		t.Fatalf("missing directory: %v", err)
	}
}
