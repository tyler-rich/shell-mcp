//go:build e2e && linux

package e2e

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// In the helper's core unit, priv_chmod and priv_chown refuse a hard link
// inside the write root whose inode also has a name outside it
// (/etc/example-other is on the same filesystem and in no root), and that
// file keeps its mode, owner and change time. Root makes the link here; on
// a real host any account with read and write access to the file could.
func TestHelperHardLinkChmodChown(t *testing.T) {
	outside := "/etc/example-other/secret.txt" // root:root 0644, setup.sh
	link := "/etc/example-app/e2e-hardlink.conf"
	_ = os.Remove(link)
	if err := os.Link(outside, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	stat := func() (os.FileMode, *syscall.Stat_t) {
		fi, err := os.Lstat(outside)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t)
	}
	mode0, st0 := stat()
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		{"priv_chmod", map[string]any{"path": link, "mode": "0600"}},
		{"priv_chown", map[string]any{"path": link, "owner": "example-app", "group": "example-app"}},
	} {
		r, _ := gate(t, svcShell, c.op, c.args)
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, link) || !strings.Contains(r.Error.Message, "2 links") {
			t.Fatalf("%s through a hard link: %s %+v, want path_denied naming the path and 2 links", c.op, r.code(), r.Error)
		}
	}
	mode1, st1 := stat()
	if mode1 != mode0 || st1.Uid != st0.Uid || st1.Gid != st0.Gid || st1.Ctim != st0.Ctim {
		t.Fatalf("the outside file changed: %04o %d:%d (was %04o %d:%d)", mode1, st1.Uid, st1.Gid, mode0, st0.Uid, st0.Gid)
	}
	// With its other name gone, the same file is changed (a single link).
	single := "/etc/example-app/e2e-single.conf"
	mustGate(t, "priv_write_file", map[string]any{"path": single, "content_b64": "eAo="}, nil)
	t.Cleanup(func() { _ = os.Remove(single) })
	mustGate(t, "priv_chmod", map[string]any{"path": single, "mode": "0600"}, nil)
	mustGate(t, "priv_chown", map[string]any{"path": single, "group": "example-app"}, nil)
}

// In the core unit, a write over a file and a copy of a file whose modes
// are wider than modes.max (0755 in the e2e policy: 0664 has group-write)
// are narrowed to the mask, and the result reports the mode set.
func TestHelperModesMaxClamp(t *testing.T) {
	dir := "/etc/example-app/e2e-modes"
	mustGate(t, "priv_mkdir", map[string]any{"path": dir, "mode": "0755"}, nil)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	wide := dir + "/wide.conf"
	if err := os.WriteFile(wide, []byte("wide\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o664); err != nil { //nolint:gosec // G302: a mode wider than the mask, deliberately
		t.Fatal(err)
	}
	var w struct {
		Mode string `json:"mode"`
	}
	mustGate(t, "priv_copy", map[string]any{"source": wide, "destination": dir + "/copy.conf"}, &w)
	if fi, err := os.Stat(dir + "/copy.conf"); err != nil || fi.Mode().Perm() != 0o644 || w.Mode != "0644" {
		t.Fatalf("copy of a 0664 file: %v reported %q, want 0644", fi.Mode(), w.Mode)
	}
	mustGate(t, "priv_write_file", map[string]any{"path": wide, "content_b64": "bmFycm93Cg=="}, &w) // "narrow\n"
	if fi, err := os.Stat(wide); err != nil || fi.Mode().Perm() != 0o644 || w.Mode != "0644" || readFile(t, wide) != "narrow\n" {
		t.Fatalf("write over a 0664 file: %v reported %q, want 0644", fi.Mode(), w.Mode)
	}
}
