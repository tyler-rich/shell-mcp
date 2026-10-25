//go:build linux

package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

func permOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	must(t, err)
	return fi.Mode().Perm()
}

func statOf(t *testing.T, p string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Lstat(p)
	must(t, err)
	return fi.Sys().(*syscall.Stat_t)
}

// With ModesMax (the helper), every new inode's mode is masked: a new
// file, a write over a file, a copy and a copy over a file, and a created
// directory. Without it (the gate) nothing changes.
func TestModesMaxMasksNewInodes(t *testing.T) {
	for _, masked := range []bool{true, false} {
		e := newEnv(t)
		if masked {
			m := os.FileMode(0o700)
			e.fs.cfg.ModesMax = &m
		}
		want := func(gate os.FileMode) os.FileMode {
			if masked {
				return gate & 0o700
			}
			return gate
		}
		check := func(what, p, reported string, w os.FileMode) {
			t.Helper()
			if got := permOf(t, p); got != w || reported != fmt.Sprintf("%04o", uint32(w)) {
				t.Errorf("masked=%v %s: %04o on disk, reported %q; want %04o", masked, what, got, reported, w)
			}
		}
		r, err := e.fs.WriteFile(filepath.Join(e.write, "new.txt"), []byte("n"), WriteOptions{Create: true})
		must(t, err)
		check("new file", filepath.Join(e.write, "new.txt"), r.Mode, want(0o640))

		must(t, os.Chmod(filepath.Join(e.write, "app.yaml"), 0o664)) //nolint:gosec // G302: a test fixture mode
		r, err = e.fs.WriteFile(filepath.Join(e.write, "app.yaml"), []byte("w"), WriteOptions{Create: true})
		must(t, err)
		check("write over a file", filepath.Join(e.write, "app.yaml"), r.Mode, want(0o664))

		src := filepath.Join(e.read, "hello.txt")
		must(t, os.Chmod(src, 0o644)) //nolint:gosec // G302: a test fixture mode
		r, err = e.fs.Copy(src, filepath.Join(e.write, "copy.txt"), false)
		must(t, err)
		check("copy", filepath.Join(e.write, "copy.txt"), r.Mode, want(0o644))

		over := filepath.Join(e.write, "over.txt")
		put(t, over, "old")
		must(t, os.Chmod(over, 0o654)) //nolint:gosec // G302: a test fixture mode
		r, err = e.fs.Copy(src, over, true)
		must(t, err)
		check("copy over a file", over, r.Mode, want(0o654))

		m := os.FileMode(0o755)
		md, err := e.fs.MkdirAs(filepath.Join(e.write, "x", "y"), &m, true, nil)
		must(t, err)
		check("mkdir", filepath.Join(e.write, "x", "y"), md.Mode, want(0o755))
		check("mkdir's parent", filepath.Join(e.write, "x"), md.Mode, want(0o755))
	}
}

// The gate's Chmod refuses a non-directory with more than one link, read by
// fstat on the descriptor it would change: its other name can lie outside
// the write roots. The other name's inode is unchanged. Single-link files and
// directories are still changed. (The helper's chown and chmod, ApplyMeta,
// apply the same rule to every entry: TestApplyMetaRefusals and the window
// tests in meta_exact_test.go.)
func TestChmodRefusesHardLinks(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(e.outside, "passwd")
	must(t, os.Chmod(outside, 0o644)) //nolint:gosec // G302: a test fixture mode
	link := filepath.Join(e.write, "linked")
	must(t, os.Link(outside, link))
	before := statOf(t, outside)

	_, err := e.fs.Chmod(link, 0o600)
	wantCode(t, err, protocol.CodePathDenied)
	if fe := err.(*Error); !strings.Contains(fe.Msg, link) || !strings.Contains(fe.Msg, "2 links") { //nolint:errorlint // wantCode checked the type
		t.Fatalf("message %q does not name the path and the link count", fe.Msg)
	}
	after := statOf(t, outside)
	if permOf(t, outside) != 0o644 || after.Ctim != before.Ctim || after.Uid != before.Uid || after.Gid != before.Gid {
		t.Fatalf("the outside inode changed: %04o ctime %v (was %v)", permOf(t, outside), after.Ctim, before.Ctim)
	}

	// Three links: the count is in the message.
	must(t, os.Link(outside, filepath.Join(e.write, "linked2")))
	_, err = e.fs.Chmod(link, 0o600)
	wantCode(t, err, protocol.CodePathDenied)
	if fe := err.(*Error); !strings.Contains(fe.Msg, "3 links") { //nolint:errorlint // wantCode checked the type
		t.Fatalf("message %q", fe.Msg)
	}

	// Once the other names are gone, the file is changed.
	must(t, os.Remove(outside))
	must(t, os.Remove(filepath.Join(e.write, "linked2")))
	_, err = e.fs.Chmod(link, 0o600)
	must(t, err)
	dir := filepath.Join(e.write, "dir")
	must(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o750))
	_, err = e.fs.Chmod(dir, 0o700)
	must(t, err)
	if permOf(t, link) != 0o600 || permOf(t, dir) != 0o700 {
		t.Fatalf("modes %04o %04o", permOf(t, link), permOf(t, dir))
	}
}

// With VerifyMetadata, Chmod re-reads the inode through the descriptor it
// changed and refuses a mismatch with verify_failed; the result carries the
// values before the change. Without it nothing is re-read (both the gate,
// since N-4, and the helper set it).
// (ApplyMeta, the helper's, always reads back: TestApplyMetaReadBack.)
func TestChmodReadBack(t *testing.T) {
	e := newEnv(t)
	uid, gid := ids(t)
	p := filepath.Join(e.write, "app.yaml") // 0600
	e.fs.cfg.InjectMetadataReadBackFault = func(m Meta) Meta { m.Mode ^= 0o004; return m }
	_, err := e.fs.Chmod(p, 0o640)
	must(t, err) // not re-read without VerifyMetadata
	e.fs.cfg.VerifyMetadata = true
	_, err = e.fs.Chmod(p, 0o600)
	wantCode(t, err, protocol.CodeVerifyFailed)

	e.fs.cfg.InjectMetadataReadBackFault = nil
	must(t, os.Chmod(p, 0o640)) //nolint:gosec // G302: a test fixture mode
	ch, err := e.fs.Chmod(p, 0o600)
	must(t, err)
	if ch.Before != (Meta{Mode: 0o640, UID: uid, GID: gid}) || !ch.Changed {
		t.Fatalf("chmod before %+v changed %v", ch.Before, ch.Changed)
	}
}
