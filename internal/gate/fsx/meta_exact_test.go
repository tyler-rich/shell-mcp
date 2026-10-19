//go:build linux

package fsx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The helper's bound chown and chmod (PreviewMeta, ApplyMeta; handoff
// docs/handoff/S4C-PRIVILEGED.md D4, N-1, F-2, X-10): refusals, the
// preview binding, the chain rule, read-back, and what may change between
// the preview, the recompute and each entry's change. Every layout is
// invented. An unprivileged test cannot give a directory to another
// account, so "another account can write it" is a group- or world-writable
// directory here, or an untrusted owner (the trust set without the test's
// uid); e2e-host runs the real case as root.

// newMetaEnv is newDelEnv under a directory whose chain the test trust
// passes, with the helper's settings: read-back, and the test uid trusted
// as a directory owner.
func newMetaEnv(t *testing.T, limit int) *env {
	t.Helper()
	d := gatetest.SecureDir(t)
	e := &env{
		d:       d,
		read:    filepath.Join(d, "read"),
		write:   filepath.Join(d, "read", "config"),
		outside: filepath.Join(d, "outside"),
		secrets: filepath.Join(d, "read", "secrets"),
	}
	for _, p := range []string{e.write, e.outside, e.secrets} {
		must(t, os.MkdirAll(p, 0o750))
	}
	put(t, filepath.Join(e.read, "hello.txt"), "hello\n")
	put(t, filepath.Join(e.write, "app.yaml"), "key: value\n")
	put(t, filepath.Join(e.outside, "passwd"), "OUTSIDE")
	deny, err := pathx.NewMatcher([]string{e.secrets + "/**", "**/*.key"})
	must(t, err)
	prot, err := pathx.NewMatcher([]string{"**/.ssh", "**/.git", e.write + "/locked"})
	must(t, err)
	nested := filepath.Join(e.write, "holder", "inner")
	must(t, os.MkdirAll(nested, 0o750))
	trust := gatetest.Trust()
	e.fs = New(&Config{
		ReadRoots:       []string{e.read},
		WriteRoots:      []string{e.write, nested},
		Deny:            deny,
		Protected:       prot,
		Limits:          Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxFindResults: 100, MaxFindDepth: 8, MaxDeleteEntries: limit},
		VerifyMetadata:  true,
		TrustedDirOwner: trust.Owns,
	})
	return e
}

func chmodTo(m os.FileMode) MetaChange { return MetaChange{Op: MetaChmod, Mode: m} }

func chgrpTo(gid uint32) MetaChange { return MetaChange{Op: MetaChown, GID: &gid} }

const testBind = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"

// bound previews p and applies ch with the preview's hash.
func bound(t *testing.T, e *env, p string, ch MetaChange, recursive bool) (MetaPlan, error) {
	t.Helper()
	pv, err := e.fs.PreviewMeta(p, ch, recursive, testBind)
	if err != nil {
		return pv, err
	}
	return e.fs.ApplyMeta(p, ch, recursive, testBind, pv.PreviewSHA256)
}

// modesUnder records the mode, owner and inode of everything under dir
// (dir included), without following symlinks.
type inodeState struct {
	mode     os.FileMode
	uid, gid uint32
	ino      uint64
}

func statesUnder(t *testing.T, dir string) map[string]inodeState {
	t.Helper()
	out := map[string]inodeState{}
	must(t, filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		out[p] = inodeState{fi.Mode(), st.Uid, st.Gid, st.Ino}
		return nil
	}))
	return out
}

func sameStates(t *testing.T, what string, before, after map[string]inodeState) {
	t.Helper()
	for p, b := range before {
		if a, ok := after[p]; ok && a != b {
			t.Fatalf("%s: %s changed: %+v (was %+v)", what, p, a, b)
		}
	}
}

// mkMetaTree makes dir with the mkTree layout (7 entries) plus a symlink to
// a file outside every root and one to a file inside the tree: 9 entries.
func mkMetaTree(t *testing.T, e *env, dir string) []string {
	t.Helper()
	paths := mkTree(t, dir)
	must(t, os.Symlink(filepath.Join(e.outside, "passwd"), filepath.Join(dir, "out-link")))
	must(t, os.Symlink("a.txt", filepath.Join(dir, "b", "in-link")))
	return append(paths, dir+"/out-link", dir+"/b/in-link")
}

func TestPreviewMetaReportsTheTree(t *testing.T) {
	e := newMetaEnv(t, 50)
	dir := filepath.Join(e.write, "tree")
	mkMetaTree(t, e, dir)
	must(t, os.Chmod(filepath.Join(dir, "a.txt"), 0o700))
	pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
	must(t, err)
	// 9 entries; a.txt already 0700 and the two symlinks are not changed.
	if pv.Path != dir || pv.Type != "dir" || pv.Entries != 9 || pv.Changes != 6 || len(pv.First) != 9 || !ValidPreviewSHA256(pv.PreviewSHA256) {
		t.Fatalf("plan %+v", pv)
	}
	if pv.First[0].Path != dir || pv.Top.Path != dir {
		t.Fatalf("first %+v top %+v", pv.First[0], pv.Top)
	}
	byPath := map[string]MetaEntry{}
	for _, en := range pv.First {
		byPath[en.Path] = en
	}
	if a := byPath[dir+"/a.txt"]; a.Type != "file" || a.Change || a.Mode != 0o700 || a.NewMode != 0o700 {
		t.Fatalf("a.txt %+v", a)
	}
	if l := byPath[dir+"/out-link"]; l.Type != "symlink" || l.Change {
		t.Fatalf("symlink %+v", l)
	}
	if c := byPath[dir+"/b/c.txt"]; !c.Change || c.Mode != 0o600 || c.NewMode != 0o700 {
		t.Fatalf("c.txt %+v", c)
	}
	again, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
	must(t, err)
	if again.PreviewSHA256 != pv.PreviewSHA256 {
		t.Fatal("the same tree hashed differently")
	}
	// Non-recursive: the directory alone; its entries are not read.
	one, err := e.fs.PreviewMeta(dir, chmodTo(0o700), false, testBind)
	must(t, err)
	if one.Entries != 1 || one.Changes != 1 || one.PreviewSHA256 == pv.PreviewSHA256 {
		t.Fatalf("non-recursive %+v", one)
	}
	// More than 50 entries: the first 50, in walk order.
	big := filepath.Join(e.write, "big")
	for i := range 60 {
		put(t, fmt.Sprintf("%s/f%02d", big, i), "x")
	}
	e.fs.cfg.Limits.MaxDeleteEntries = 100
	bp, err := e.fs.PreviewMeta(big, chmodTo(0o640), true, testBind)
	must(t, err)
	if bp.Entries != 61 || len(bp.First) != 50 || bp.First[1].Path != big+"/f00" {
		t.Fatalf("big: %d entries, %d listed", bp.Entries, len(bp.First))
	}
}

func TestApplyMetaChangesThePlan(t *testing.T) {
	e := newMetaEnv(t, 50)
	dir := filepath.Join(e.write, "tree")
	paths := mkMetaTree(t, e, dir)
	outside := filepath.Join(e.outside, "passwd")
	must(t, os.Chmod(outside, 0o604)) //nolint:gosec // G302: a test fixture mode
	must(t, os.Chmod(filepath.Join(dir, "a.txt"), 0o700))
	links := map[string]os.FileMode{}
	for _, l := range []string{dir + "/out-link", dir + "/b/in-link"} {
		fi, err := os.Lstat(l)
		must(t, err)
		links[l] = fi.Mode()
	}
	r, err := bound(t, e, dir, chmodTo(0o700), true)
	must(t, err)
	if !r.Done || len(r.Changed) != 6 {
		t.Fatalf("result %+v", r)
	}
	for _, p := range paths {
		fi, err := os.Lstat(p)
		must(t, err)
		if fi.Mode()&os.ModeSymlink != 0 {
			if fi.Mode() != links[p] {
				t.Fatalf("symlink %s changed: %v", p, fi.Mode())
			}
			continue
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s is %04o", p, fi.Mode().Perm())
		}
	}
	if permOf(t, outside) != 0o604 {
		t.Fatal("the symlink's target outside the roots was changed")
	}
	// Children before their directory; the target last; old values kept.
	pos := map[string]int{}
	for i, c := range r.Changed {
		pos[c.Path] = i
		if c.Path == dir+"/b/c.txt" && c.Before.Mode != 0o600 {
			t.Fatalf("before %+v", c.Before)
		}
	}
	if pos[dir+"/b/d/e.txt"] > pos[dir+"/b/d"] || pos[dir+"/b"] > pos[dir] || r.Changed[len(r.Changed)-1].Path != dir {
		t.Fatalf("order %v", r.Changed)
	}
	if _, ok := pos[dir+"/a.txt"]; ok {
		t.Fatal("an entry already at the mode was changed")
	}
	// Non-recursive on a directory: its entries are untouched.
	must(t, os.Chmod(filepath.Join(dir, "b", "c.txt"), 0o600))
	r, err = bound(t, e, dir, chmodTo(0o750), false)
	must(t, err)
	if len(r.Changed) != 1 || permOf(t, dir) != 0o750 || permOf(t, filepath.Join(dir, "b", "c.txt")) != 0o600 {
		t.Fatalf("non-recursive %+v", r)
	}
	// chown to the group everything already has: nothing to change.
	_, gid := ids(t)
	r, err = bound(t, e, dir, chgrpTo(gid), true)
	must(t, err)
	if !r.Done || len(r.Changed) != 0 {
		t.Fatalf("chgrp to the current group %+v", r)
	}
	// chown to a group the test may not give: the plan says so, and the
	// first change fails; nothing was changed.
	pv, err := e.fs.PreviewMeta(dir, chgrpTo(0), true, testBind)
	must(t, err)
	if os.Getgid() != 0 && pv.Changes != 7 {
		t.Fatalf("changes %d", pv.Changes)
	}
	if os.Getuid() != 0 {
		r, err = e.fs.ApplyMeta(dir, chgrpTo(0), true, testBind, pv.PreviewSHA256)
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), "nothing was changed (0 of 7") || len(r.Changed) != 0 {
			t.Fatalf("%v %+v", err, r)
		}
	}
}

func TestApplyMetaReadBack(t *testing.T) {
	e := newMetaEnv(t, 50)
	dir := filepath.Join(e.write, "tree")
	mkTree(t, dir)
	e.fs.cfg.InjectMetadataReadBackFault = func(m Meta) Meta { m.Mode ^= 0o004; return m }
	r, err := bound(t, e, dir, chmodTo(0o700), true)
	wantCode(t, err, protocol.CodeVerifyFailed)
	if len(r.Changed) != 1 || r.Done || !strings.Contains(err.Error(), "1 of 7 entries were changed") {
		t.Fatalf("%v %+v", err, r)
	}
	// Read-back is the helper's, whatever VerifyMetadata says (only the
	// helper uses ApplyMeta).
	e.fs.cfg.VerifyMetadata = false
	_, err = bound(t, e, filepath.Join(dir, "a.txt"), chmodTo(0o640), false)
	wantCode(t, err, protocol.CodeVerifyFailed)
}

// metaRefusal checks that both PreviewMeta and ApplyMeta refuse p with
// code and that nothing under the write root changed.
func metaRefusal(t *testing.T, e *env, p string, ch MetaChange, recursive bool, code string) {
	t.Helper()
	before := statesUnder(t, e.write)
	_, err := e.fs.PreviewMeta(p, ch, recursive, testBind)
	wantCode(t, err, code)
	_, err = e.fs.ApplyMeta(p, ch, recursive, testBind, zeroHash)
	wantCode(t, err, code)
	sameStates(t, p, before, statesUnder(t, e.write))
}

func TestApplyMetaRefusals(t *testing.T) {
	e := newMetaEnv(t, 12)
	ch := chmodTo(0o700)
	tree := filepath.Join(e.write, "tree")
	mkTree(t, tree)
	metaRefusal(t, e, e.write, ch, false, protocol.CodePathDenied)                                  // a write root
	metaRefusal(t, e, filepath.Join(e.write, "holder", "inner"), ch, true, protocol.CodePathDenied) // a nested root
	metaRefusal(t, e, filepath.Join(e.write, "holder"), ch, true, protocol.CodePathDenied)          // a tree holding one
	metaRefusal(t, e, filepath.Join(e.outside, "passwd"), ch, false, protocol.CodePathDenied)       // outside every root
	metaRefusal(t, e, filepath.Join(e.read, "hello.txt"), ch, false, protocol.CodePathDenied)       // a read root
	metaRefusal(t, e, filepath.Join(e.write, "missing"), ch, false, protocol.CodeNotFound)
	metaRefusal(t, e, e.write+"/tree/../app.yaml", ch, false, protocol.CodeBadRequest)
	must(t, os.Symlink("app.yaml", filepath.Join(e.write, "final-link")))
	metaRefusal(t, e, filepath.Join(e.write, "final-link"), ch, false, protocol.CodePathDenied)

	// Inside a tree: a denied name, .git, a set-aside name, a FIFO, a
	// socket, special bits, a hard link; and too many entries.
	for name, mk := range map[string]func(dir string){
		"denied": func(dir string) { put(t, filepath.Join(dir, "id.key"), "k") },
		"git":    func(dir string) { must(t, os.MkdirAll(filepath.Join(dir, "repo", ".git"), 0o750)) },
		"set-aside": func(dir string) {
			put(t, filepath.Join(dir, deleteTempPrefix+"0123456789abcdef0123456789abcdef"), "x")
		},
		"fifo": func(dir string) { must(t, unix.Mkfifo(filepath.Join(dir, "pipe"), 0o600)) },
		"socket": func(dir string) {
			l, err := net.Listen("unix", filepath.Join(dir, "sock"))
			must(t, err)
			t.Cleanup(func() { _ = l.Close() })
		},
		"hard link": func(dir string) { must(t, os.Link(filepath.Join(e.outside, "passwd"), filepath.Join(dir, "linked"))) },
		"too many": func(dir string) {
			for i := range 12 {
				put(t, fmt.Sprintf("%s/n%02d", dir, i), "x")
			}
		},
	} {
		dir := filepath.Join(e.write, "case-"+strings.ReplaceAll(name, " ", "-"))
		put(t, filepath.Join(dir, "ok.txt"), "x")
		mk(dir)
		code := protocol.CodePathDenied
		if name == "too many" {
			code = protocol.CodeTooLarge
		}
		metaRefusal(t, e, dir, ch, true, code)
		if name == "hard link" {
			_, err := e.fs.PreviewMeta(dir, ch, true, testBind)
			if !strings.Contains(err.Error(), "2 links") {
				t.Fatalf("hard link: %v", err)
			}
		}
	}
	// Special bits, in a tree and on their own (chown refuses them too).
	sp := filepath.Join(e.write, "special")
	put(t, filepath.Join(sp, "suid"), "x")
	must(t, os.Chmod(filepath.Join(sp, "suid"), 0o700|os.ModeSetuid))
	metaRefusal(t, e, sp, ch, true, protocol.CodePolicyDenied)
	metaRefusal(t, e, filepath.Join(sp, "suid"), ch, false, protocol.CodePolicyDenied)
	_, gid := ids(t)
	metaRefusal(t, e, filepath.Join(sp, "suid"), chgrpTo(gid), false, protocol.CodePolicyDenied)
	sticky := filepath.Join(e.write, "sticky")
	must(t, os.Mkdir(sticky, 0o700))
	must(t, os.Chmod(sticky, 0o700|os.ModeSticky))
	metaRefusal(t, e, sticky, ch, false, protocol.CodePolicyDenied)
	// A hard-linked file on its own, and a FIFO on its own.
	must(t, os.Link(filepath.Join(e.outside, "passwd"), filepath.Join(e.write, "top-link")))
	metaRefusal(t, e, filepath.Join(e.write, "top-link"), ch, false, protocol.CodePathDenied)
	must(t, unix.Mkfifo(filepath.Join(e.write, "top-pipe"), 0o600))
	metaRefusal(t, e, filepath.Join(e.write, "top-pipe"), ch, false, protocol.CodeBadRequest)

	// The hash: required, well-formed, and the current one.
	p := filepath.Join(e.write, "app.yaml")
	before := statesUnder(t, e.write)
	for _, h := range []string{"", "xyz", strings.ToUpper(zeroHash[:1]) + zeroHash[1:]} {
		_, err := e.fs.ApplyMeta(p, ch, false, testBind, h)
		wantCode(t, err, protocol.CodeBadRequest)
	}
	_, err := e.fs.ApplyMeta(p, ch, false, testBind, zeroHash)
	wantCode(t, err, protocol.CodeExists)
	if !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("stale hash: %v", err)
	}
	sameStates(t, "bad hashes", before, statesUnder(t, e.write))
}

// TestMetaRefusesAMountPoint: a mount point, and a tree holding one, are
// never changed (skipped where no mount point is visible; e2e-host has one).
func TestMetaRefusesAMountPoint(t *testing.T) {
	mp := mountPoint(t)
	if mp == "" {
		t.Skip("no mount point under /etc is visible here; e2e-host covers mount points")
	}
	none, err := pathx.NewMatcher(nil)
	must(t, err)
	f := New(&Config{WriteRoots: []string{filepath.Dir(mp)}, Deny: none, Protected: none, Limits: Limits{MaxDeleteEntries: 10},
		TrustedDirOwner: func(uint32) bool { return true }})
	if _, err := f.PreviewMeta(mp, chmodTo(0o644), false, testBind); err == nil || !strings.Contains(err.Error(), "mount") {
		t.Fatalf("mount point: %v", err)
	}
}

// TestMetaChainRule (N-1): an entry is changed only when every directory
// from / to it, and every directory of the tree that holds entries, is
// owned by a trusted uid and neither group- nor world-writable; otherwise
// another account could have moved it in (and could move it out again).
func TestMetaChainRule(t *testing.T) {
	e := newMetaEnv(t, 50)
	drop := filepath.Join(e.write, "drop")
	must(t, os.Mkdir(drop, 0o750))
	must(t, os.Chmod(drop, 0o777)) //nolint:gosec // G302: another account's write access, simulated
	elsewhere := filepath.Join(e.outside, "incoming")
	must(t, os.Mkdir(elsewhere, 0o750))
	must(t, os.Chmod(elsewhere, 0o777)) //nolint:gosec // G302: the same account can write here
	secret := filepath.Join(elsewhere, "secret")
	put(t, secret, "SECRET")
	// Moved in, as the other account could.
	moved := filepath.Join(drop, "secret")
	must(t, os.Rename(secret, moved))
	for _, ch := range []MetaChange{chmodTo(0o644), chgrpTo(uint32(os.Getgid()))} { //nolint:gosec // G115: test ids fit
		for _, recursive := range []bool{false, true} {
			_, err := e.fs.PreviewMeta(moved, ch, recursive, testBind)
			wantCode(t, err, protocol.CodePathDenied)
			if !strings.Contains(err.Error(), drop) || !strings.Contains(err.Error(), "writable") {
				t.Fatalf("message does not name the directory and why: %v", err)
			}
			_, err = e.fs.ApplyMeta(moved, ch, recursive, testBind, zeroHash)
			wantCode(t, err, protocol.CodePathDenied)
		}
	}
	// And moved out again: never changed.
	must(t, os.Rename(moved, secret))
	if permOf(t, secret) != 0o600 {
		t.Fatalf("the moved-in file was changed: %04o", permOf(t, secret))
	}
	// Group-writable is the same.
	must(t, os.Chmod(drop, 0o770)) //nolint:gosec // G302: a group's write access
	put(t, filepath.Join(drop, "f"), "x")
	_, err := e.fs.PreviewMeta(filepath.Join(drop, "f"), chmodTo(0o640), false, testBind)
	wantCode(t, err, protocol.CodePathDenied)
	// The directory itself may be changed: its own path is trusted.
	_, err = bound(t, e, drop, chmodTo(0o750), false)
	must(t, err)

	// Inside a tree: a writable directory holding entries refuses the whole
	// tree; an empty one does not.
	tree := filepath.Join(e.write, "tree")
	mkTree(t, tree)
	sub := filepath.Join(tree, "b", "d")
	must(t, os.Chmod(sub, 0o777)) //nolint:gosec // G302: another account's write access, simulated
	before := statesUnder(t, tree)
	_, err = e.fs.PreviewMeta(tree, chmodTo(0o700), true, testBind)
	wantCode(t, err, protocol.CodePathDenied)
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("message does not name the directory: %v", err)
	}
	_, err = e.fs.ApplyMeta(tree, chmodTo(0o700), true, testBind, zeroHash)
	wantCode(t, err, protocol.CodePathDenied)
	sameStates(t, "writable directory in the tree", before, statesUnder(t, tree))
	must(t, os.Remove(filepath.Join(sub, "e.txt")))
	_, err = bound(t, e, tree, chmodTo(0o700), true)
	must(t, err)

	// An untrusted owner anywhere on the path: the test's own directories,
	// once its uid is not trusted.
	e.fs.cfg.TrustedDirOwner = func(uid uint32) bool { return uid == 0 }
	if os.Getuid() != 0 {
		_, err = e.fs.PreviewMeta(filepath.Join(e.write, "app.yaml"), chmodTo(0o640), false, testBind)
		wantCode(t, err, protocol.CodePathDenied)
		if !strings.Contains(err.Error(), fmt.Sprintf("uid %d", os.Getuid())) {
			t.Fatalf("message does not name the owner: %v", err)
		}
	}
	// nil trusts uid 0 only.
	e.fs.cfg.TrustedDirOwner = nil
	if os.Getuid() != 0 {
		_, err = e.fs.PreviewMeta(filepath.Join(e.write, "app.yaml"), chmodTo(0o640), false, testBind)
		wantCode(t, err, protocol.CodePathDenied)
	}
}

func TestCheckRootChain(t *testing.T) {
	d := gatetest.SecureDir(t)
	trust := gatetest.Trust()
	root := filepath.Join(d, "etc", "example-app")
	must(t, os.MkdirAll(root, 0o750))
	must(t, CheckRootChain(root, trust.Owns))
	ww := filepath.Join(d, "ww")
	must(t, os.Mkdir(ww, 0o750))
	must(t, os.Chmod(ww, 0o777)) //nolint:gosec // G302: a world-writable ancestor
	inner := filepath.Join(ww, "root")
	must(t, os.Mkdir(inner, 0o750))
	var ce *ChainError
	if err := CheckRootChain(inner, trust.Owns); !errors.As(err, &ce) || ce.Dir != ww || !ce.Writable || ce.Mode != 0o777 {
		t.Fatalf("world-writable ancestor: %v %+v", err, ce)
	}
	if os.Getuid() != 0 {
		err := CheckRootChain(root, func(uid uint32) bool { return uid == 0 })
		if !errors.As(err, &ce) || ce.UID != uint32(os.Getuid()) || ce.Writable { //nolint:gosec // G115: test ids fit
			t.Fatalf("untrusted owner: %v %+v", err, ce)
		}
	}
	if err := CheckRootChain(filepath.Join(d, "missing"), trust.Owns); err == nil || errors.As(err, &ce) {
		t.Fatalf("missing: %v", err)
	}
}

// TestMetaHashCoversEveryEntry: any change to the tree that matters to a
// chmod or chown changes the preview's hash; a content change does not
// (chown -R of a directory being written must stay approvable), and the
// request (the change, recursive, the policy bound in) is in it too.
func TestMetaHashCoversEveryEntry(t *testing.T) {
	e := newMetaEnv(t, 50)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	cases := map[string]func(dir string){
		"added":           func(dir string) { put(t, filepath.Join(dir, "b", "new.txt"), "n") },
		"added empty dir": func(dir string) { must(t, os.Mkdir(filepath.Join(dir, "b", "d", "new"), 0o750)) },
		"removed":         func(dir string) { must(t, os.Remove(filepath.Join(dir, "b", "d", "e.txt"))) },
		"renamed":         func(dir string) { must(t, os.Rename(filepath.Join(dir, "a.txt"), filepath.Join(dir, "z.txt"))) },
		"moved":           func(dir string) { must(t, os.Rename(filepath.Join(dir, "a.txt"), filepath.Join(dir, "f", "a.txt"))) },
		"replaced":        func(dir string) { replaceFile(t, staging, filepath.Join(dir, "b", "c.txt"), "cc") },
		"chmod-ed":        func(dir string) { must(t, os.Chmod(filepath.Join(dir, "b", "d", "e.txt"), 0o640)) },
		"chmod-ed dir":    func(dir string) { must(t, os.Chmod(filepath.Join(dir, "f"), 0o700)) },
		"symlink replaced": func(dir string) {
			must(t, os.Remove(filepath.Join(dir, "l")))
			must(t, os.Symlink("b", filepath.Join(dir, "l")))
		},
		"dir recreated": func(dir string) {
			must(t, os.Remove(filepath.Join(dir, "f")))
			must(t, os.Mkdir(filepath.Join(dir, "f"), 0o750))
		},
	}
	for name, change := range cases {
		dir := filepath.Join(e.write, "h-"+strings.ReplaceAll(name, " ", "-"))
		mkTree(t, dir)
		must(t, os.Symlink("a.txt", filepath.Join(dir, "l")))
		pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
		must(t, err)
		change(dir)
		again, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
		must(t, err)
		if again.PreviewSHA256 == pv.PreviewSHA256 {
			t.Errorf("%s: the hash did not change", name)
		}
	}
	dir := filepath.Join(e.write, "h-same")
	mkTree(t, dir)
	pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("other content, longer"), 0o600))
	for what, h := range map[string]func() (MetaPlan, error){
		"content written": func() (MetaPlan, error) { return e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind) },
	} {
		got, err := h()
		must(t, err)
		if got.PreviewSHA256 != pv.PreviewSHA256 {
			t.Errorf("%s changed the hash", what)
		}
	}
	// Every request hashes differently: the change, recursive and the
	// policy bound in are all in the hash.
	gid := uint32(os.Getgid()) //nolint:gosec // G115: test ids fit
	seen := map[string]string{pv.PreviewSHA256: "mode 0700, recursive"}
	for what, ch := range map[string]struct {
		ch        MetaChange
		recursive bool
		bind      string
	}{
		"another mode":    {chmodTo(0o750), true, testBind},
		"not recursive":   {chmodTo(0o700), false, testBind},
		"another policy":  {chmodTo(0o700), true, zeroHash},
		"group":           {chgrpTo(gid), true, testBind},
		"another group":   {chgrpTo(gid + 1), true, testBind},
		"owner":           {MetaChange{Op: MetaChown, UID: &gid}, true, testBind},
		"owner and group": {MetaChange{Op: MetaChown, UID: &gid, GID: &gid}, true, testBind},
	} {
		got, err := e.fs.PreviewMeta(dir, ch.ch, ch.recursive, ch.bind)
		must(t, err)
		if other, dup := seen[got.PreviewSHA256]; dup {
			t.Errorf("%s hashes as %s", what, other)
		}
		seen[got.PreviewSHA256] = what
	}
}

// decodeMetaEntry is appendMetaEntry's inverse, for the fuzz target.
func decodeMetaEntry(b []byte) (path string, id ident, rest []byte, ok bool) {
	n, k := binary.Uvarint(b)
	if k <= 0 || uint64(len(b)-k) < n { //nolint:gosec // G115: len(b)-k is not negative here
		return "", ident{}, nil, false
	}
	path, b = string(b[k:k+int(n)]), b[k+int(n):] //nolint:gosec // G115: n is at most len(b)
	if len(b) < 4+8*3+4*3+1 {
		return "", ident{}, nil, false
	}
	id.typ, b = binary.BigEndian.Uint32(b), b[4:]
	id.dev, b = binary.BigEndian.Uint64(b), b[8:]
	id.ino, b = binary.BigEndian.Uint64(b), b[8:]
	id.mnt, b = binary.BigEndian.Uint64(b), b[8:]
	id.uid, b = binary.BigEndian.Uint32(b), b[4:]
	id.gid, b = binary.BigEndian.Uint32(b), b[4:]
	id.perm, b = binary.BigEndian.Uint32(b), b[4:]
	switch b[0] {
	case 0:
		return path, id, b[1:], true
	case 1:
		b = b[1:]
		if len(b) < 12 {
			return "", ident{}, nil, false
		}
		id.hasBtime = true
		id.btime.Sec, b = int64(binary.BigEndian.Uint64(b)), b[8:] //nolint:gosec // G115: bits back
		id.btime.Nsec, b = binary.BigEndian.Uint32(b), b[4:]
		return path, id, b, true
	}
	return "", ident{}, nil, false
}

// TestMetaEntryEncodingCoversEveryField: each field of an entry changes its
// hash input (uid and gid included, which an unprivileged test cannot
// change on a real file).
func TestMetaEntryEncodingCoversEveryField(t *testing.T) {
	base := ident{dev: 1, ino: 2, mnt: 3, typ: unix.S_IFREG, perm: 0o640, uid: 5, gid: 6, hasBtime: true, btime: unix.StatxTimestamp{Sec: 7, Nsec: 8}}
	enc := string(appendMetaEntry(nil, "/srv/app/x", &base))
	for name, edit := range map[string]func(*ident){
		"dev": func(i *ident) { i.dev++ }, "ino": func(i *ident) { i.ino++ }, "mnt": func(i *ident) { i.mnt++ },
		"type": func(i *ident) { i.typ = unix.S_IFDIR }, "mode": func(i *ident) { i.perm = 0o600 },
		"uid": func(i *ident) { i.uid++ }, "gid": func(i *ident) { i.gid++ },
		"btime": func(i *ident) { i.btime.Nsec++ }, "no btime": func(i *ident) { i.hasBtime = false; i.btime = unix.StatxTimestamp{} },
	} {
		id := base
		edit(&id)
		if string(appendMetaEntry(nil, "/srv/app/x", &id)) == enc {
			t.Errorf("%s is not in the encoding", name)
		}
	}
	if string(appendMetaEntry(nil, "/srv/app/y", &base)) == enc {
		t.Error("the path is not in the encoding")
	}
	// Size and change time are not: content changes do not matter here.
	id := base
	id.size, id.ctime.Sec = 99, 99
	if string(appendMetaEntry(nil, "/srv/app/x", &id)) != enc {
		t.Error("size or change time is in the encoding")
	}
}

// --- windows -------------------------------------------------------------------

const metaWindowRuns = 200

// windowChange makes one change of kind k (0..3) to the mkTree layout at
// dir and returns the inodes it created (path → mode), which nothing may
// change.
func windowChange(t *testing.T, staging, dir string, k int) map[string]os.FileMode {
	t.Helper()
	made := map[string]os.FileMode{}
	switch k {
	case 0: // a newcomer
		p := filepath.Join(dir, "b", fmt.Sprintf("new-%s", randHex(4)))
		put(t, p, "n")
		must(t, os.Chmod(p, 0o604)) //nolint:gosec // G302: a mode the change would not set
		made[p] = 0o604
	case 1: // an entry replaced by another inode
		p := filepath.Join(dir, "b", "c.txt")
		replaceFile(t, staging, p, "cc")
		must(t, os.Chmod(p, 0o604)) //nolint:gosec // G302: as above
		made[p] = 0o604
	case 2: // an entry's mode changed
		must(t, os.Chmod(filepath.Join(dir, "b", "d", "e.txt"), 0o604)) //nolint:gosec // G302: as above
	case 3: // an entry removed
		must(t, os.Remove(filepath.Join(dir, "a.txt")))
	}
	return made
}

func untouched(t *testing.T, run int, made map[string]os.FileMode) {
	t.Helper()
	for p, m := range made {
		if permOf(t, p) != m {
			t.Fatalf("run %d: %s, which the preview never saw, was changed to %04o", run, p, permOf(t, p))
		}
	}
}

// TestMetaWindowBeforeTheRecompute: the tree changes between the preview
// and the operation: the recompute differs, exists, nothing is changed.
func TestMetaWindowBeforeTheRecompute(t *testing.T) {
	e := newMetaEnv(t, 50)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	for i := range metaWindowRuns {
		dir := filepath.Join(e.write, fmt.Sprintf("w%d", i))
		mkTree(t, dir)
		pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
		must(t, err)
		made := windowChange(t, staging, dir, i%4)
		before := statesUnder(t, dir)
		r, err := e.fs.ApplyMeta(dir, chmodTo(0o700), true, testBind, pv.PreviewSHA256)
		wantCode(t, err, protocol.CodeExists)
		if len(r.Changed) != 0 || !strings.Contains(err.Error(), "nothing was changed") {
			t.Fatalf("run %d: %v %+v", i, err, r.Changed)
		}
		sameStates(t, fmt.Sprintf("run %d", i), before, statesUnder(t, dir))
		untouched(t, i, made)
	}
}

// TestMetaWindowAfterTheRecompute: the same changes after the hash matched
// and before anything is changed. A newcomer is never changed (the pass
// does not read directories again); a replaced, changed or removed entry
// stops the pass with exists and the counts; nothing outside the plan
// changes.
func TestMetaWindowAfterTheRecompute(t *testing.T) {
	e := newMetaEnv(t, 50)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	outcomes := map[string]int{}
	for i := range metaWindowRuns {
		dir := filepath.Join(e.write, fmt.Sprintf("w%d", i))
		mkTree(t, dir)
		pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
		must(t, err)
		var made map[string]os.FileMode
		e.fs.cfg.InjectMetaStep = func(s MetaStep, _ string) {
			if s == MetaStepAfterCompare {
				made = windowChange(t, staging, dir, i%4)
			}
		}
		_, err = e.fs.ApplyMeta(dir, chmodTo(0o700), true, testBind, pv.PreviewSHA256)
		e.fs.cfg.InjectMetaStep = nil
		switch {
		case err == nil:
			outcomes["completed"]++
			if i%4 != 0 {
				t.Fatalf("run %d: completed after change %d", i, i%4)
			}
		default:
			wantCode(t, err, protocol.CodeExists)
			outcomes["stopped"]++
		}
		untouched(t, i, made)
	}
	t.Logf("after the recompute: %v", outcomes)
}

// TestMetaWindowDuringThePass: at each point of each entry's change (before
// it is opened by name; after its check on the descriptor, before the
// change), its name is taken by a newcomer, or it gains a hard link from
// outside the roots. A newcomer is never changed. An entry checked on its
// descriptor is the one changed, whatever happens to its name afterwards;
// a link made after the check is equivalent to one made after the change.
func TestMetaWindowDuringThePass(t *testing.T) {
	e := newMetaEnv(t, 50)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	outcomes := map[string]int{}
	for i := range metaWindowRuns {
		dir := filepath.Join(e.write, fmt.Sprintf("w%d", i))
		paths := mkTree(t, dir)
		pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
		must(t, err)
		files := []string{paths[1], paths[3], paths[5]} // a.txt, b/c.txt, b/d/e.txt
		victim := files[i%3]
		step := []MetaStep{MetaStepBeforeEntry, MetaStepBeforeChange}[(i/3)%2]
		kind := (i / 6) % 2
		made := map[string]os.FileMode{}
		outsideLink := filepath.Join(e.outside, fmt.Sprintf("link-%d", i))
		e.fs.cfg.InjectMetaStep = func(s MetaStep, p string) {
			if s != step || p != victim {
				return
			}
			switch kind {
			case 0: // the name is taken by a newcomer
				replaceFile(t, staging, victim, "newcomer")
				must(t, os.Chmod(victim, 0o604)) //nolint:gosec // G302: a mode the change would not set
				made[victim] = 0o604
			case 1: // a hard link from outside the roots
				must(t, os.Link(victim, outsideLink))
			}
		}
		_, err = e.fs.ApplyMeta(dir, chmodTo(0o700), true, testBind, pv.PreviewSHA256)
		e.fs.cfg.InjectMetaStep = nil
		key := fmt.Sprintf("step %d kind %d: ", step, kind)
		switch {
		case err == nil:
			outcomes[key+"completed"]++
		default:
			var fe *Error
			if !errors.As(err, &fe) || (fe.Code != protocol.CodeExists && fe.Code != protocol.CodePathDenied) {
				t.Fatalf("run %d: %v", i, err)
			}
			outcomes[key+fe.Code]++
		}
		untouched(t, i, made)
		switch {
		case kind == 0 && step == MetaStepBeforeEntry && err == nil:
			t.Fatalf("run %d: a replaced entry did not stop the pass", i)
		case kind == 1 && step == MetaStepBeforeEntry && err == nil:
			t.Fatalf("run %d: a hard-linked entry was changed", i)
		case kind == 1 && step == MetaStepBeforeEntry && permOf(t, outsideLink) == 0o700:
			t.Fatalf("run %d: the file outside the roots was changed through its new link", i)
		case kind == 0 && step == MetaStepBeforeChange && err != nil:
			t.Fatalf("run %d: the entry checked on its descriptor was not changed: %v", i, err)
		}
	}
	t.Logf("during the pass: %v", outcomes)
}

// TestMetaConcurrentRacer: 400 runs with a racer that, until the operation
// returns, adds newcomers, replaces entries by new inodes and adds hard
// links (newcomers linked into the tree, and tree files linked from
// outside the roots). No inode the racer created is ever changed.
func TestMetaConcurrentRacer(t *testing.T) {
	const runs = 400
	e := newMetaEnv(t, 100)
	staging := filepath.Join(e.write, "staging")
	must(t, os.Mkdir(staging, 0o750))
	mk := func(dir string) []string {
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
	var durs []time.Duration
	for i := range 9 {
		cal := filepath.Join(e.write, fmt.Sprintf("calibrate%d", i))
		mk(cal)
		start := time.Now()
		_, err := bound(t, e, cal, chmodTo(0o700), true)
		must(t, err)
		durs = append(durs, time.Since(start))
	}
	slices.Sort(durs)
	dur := max(durs[len(durs)/2], 20*time.Microsecond)

	outcomes := map[string]int{}
	planted := 0
	for i := range runs {
		dir := filepath.Join(e.write, fmt.Sprintf("r%d", i))
		files := mk(dir)
		pv, err := e.fs.PreviewMeta(dir, chmodTo(0o700), true, testBind)
		must(t, err)
		var mu sync.Mutex
		var made []uint64 // the racer's inodes
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
				tmp := filepath.Join(staging, fmt.Sprintf("racer-%d-%d", i, k))
				if os.WriteFile(tmp, []byte("racer"), 0o604) != nil || os.Chmod(tmp, 0o604) != nil { //nolint:gosec // G306: a mode the change would not set
					return
				}
				fi, lerr := os.Lstat(tmp)
				if lerr != nil {
					return
				}
				mu.Lock()
				made = append(made, fi.Sys().(*syscall.Stat_t).Ino)
				mu.Unlock()
				switch k % 4 {
				case 0: // a newcomer
					_ = os.Rename(tmp, fmt.Sprintf("%s/s%d/new-%d", dir, 1+pick(3), k))
				case 1: // an entry replaced
					_ = os.Rename(tmp, files[pick(len(files))])
				case 2: // a newcomer hard-linked into the tree under a second name
					_ = os.Link(tmp, fmt.Sprintf("%s/s%d/link-%d", dir, 1+pick(3), k))
					_ = os.Rename(tmp, fmt.Sprintf("%s/s%d/new-%d", dir, 1+pick(3), k))
				case 3: // a tree file linked from outside the roots
					_ = os.Remove(tmp)
					_ = os.Link(files[pick(len(files))], filepath.Join(e.outside, fmt.Sprintf("racer-link-%d-%d", i, k)))
				}
				spin(time.Duration(jitter(int64(dur/8) + 1)))
			}
		})
		_, err = e.fs.ApplyMeta(dir, chmodTo(0o700), true, testBind, pv.PreviewSHA256)
		close(done)
		wg.Wait()
		switch {
		case err == nil:
			outcomes["completed"]++
		case strings.Contains(err.Error(), "changed since the preview"):
			wantCode(t, err, protocol.CodeExists)
			outcomes["refused at the recompute"]++
		default:
			var fe *Error
			if !errors.As(err, &fe) || (fe.Code != protocol.CodeExists && fe.Code != protocol.CodePathDenied) {
				t.Fatalf("run %d: %v", i, err)
			}
			outcomes["stopped during the pass ("+fe.Code+")"]++
		}
		racer := map[uint64]bool{}
		for _, ino := range made {
			racer[ino] = true
		}
		planted += len(made)
		for _, root := range []string{dir, e.outside} {
			for p, st := range statesUnder(t, root) {
				if racer[st.ino] && st.mode.Perm() == 0o700 {
					t.Fatalf("run %d: %s, an inode the racer created, was changed", i, p)
				}
			}
		}
	}
	t.Logf("concurrent racer: %d runs (an operation takes ~%v): %v; %d racer inodes, none changed", runs, dur, outcomes, planted)
}

// FuzzMetaEntryEncoding: an entry's hash input decodes back to exactly that
// entry, so different entries (or lists of entries) never feed the preview
// hash the same bytes.
func FuzzMetaEntryEncoding(f *testing.F) {
	f.Add("/srv/app/conf.d", uint32(unix.S_IFDIR), uint64(2049), uint64(77), uint64(31), true, int64(1750000000), uint32(9), uint32(0), uint32(1001), uint32(0o750), "/srv/app/conf.d/a")
	f.Add("", uint32(0), uint64(0), uint64(0), uint64(0), false, int64(0), uint32(0), uint32(0), uint32(0), uint32(0), "")
	f.Fuzz(func(t *testing.T, path string, typ uint32, dev, ino, mnt uint64, hasB bool, bs int64, bn, uid, gid, perm uint32, path2 string) {
		id := ident{typ: typ, dev: dev, ino: ino, mnt: mnt, hasBtime: hasB, uid: uid, gid: gid, perm: perm}
		if hasB {
			id.btime = unix.StatxTimestamp{Sec: bs, Nsec: bn}
		}
		b := appendMetaEntry(nil, path, &id)
		b = appendMetaEntry(b, path2, &id)
		p, got, rest, ok := decodeMetaEntry(b)
		if !ok || p != path || got != id {
			t.Fatalf("first entry: %q %+v ok %v; want %q %+v", p, got, ok, path, id)
		}
		p, got, rest, ok = decodeMetaEntry(rest)
		if !ok || p != path2 || got != id || len(rest) != 0 {
			t.Fatalf("second entry: %q %+v ok %v rest %d", p, got, ok, len(rest))
		}
	})
}

// TestChmodRefusesSpecialBits (N-2): chmod, the gate's included, never
// changes a file or directory with setuid, setgid or sticky bits, as chown
// never did; it could only clear them, and clearing them is not always
// harmless (a shared directory's sticky bit, a setgid directory's group).
func TestChmodRefusesSpecialBits(t *testing.T) {
	e := newEnv(t)
	suid := filepath.Join(e.write, "suid")
	put(t, suid, "x")
	must(t, os.Chmod(suid, 0o700|os.ModeSetuid))
	sgid := filepath.Join(e.write, "sgid")
	put(t, sgid, "x")
	must(t, os.Chmod(sgid, 0o700|os.ModeSetgid))
	sticky := filepath.Join(e.write, "sticky")
	must(t, os.Mkdir(sticky, 0o700))
	must(t, os.Chmod(sticky, 0o700|os.ModeSticky))
	for _, p := range []string{suid, sgid, sticky} {
		fi, err := os.Lstat(p)
		must(t, err)
		if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 {
			t.Skipf("%s did not keep its special bit here", p)
		}
		_, err = e.fs.Chmod(p, 0o750)
		wantCode(t, err, protocol.CodePolicyDenied)
		if after, _ := os.Lstat(p); after.Mode() != fi.Mode() {
			t.Fatalf("%s changed: %v (was %v)", p, after.Mode(), fi.Mode())
		}
	}
}
