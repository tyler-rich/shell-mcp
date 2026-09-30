//go:build linux

package ops_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm() | fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
}

func TestReads(t *testing.T) {
	f := newFixture(t)
	var rr struct {
		Content string `json:"content"`
	}
	f.ok("priv_read_file", m{"path": filepath.Join(f.read, "hello.txt")}, &rr)
	if rr.Content != "hello\nworld\n" {
		t.Fatalf("content %q", rr.Content)
	}
	// Write roots are readable.
	f.ok("priv_read_file", m{"path": filepath.Join(f.write, "app.conf")}, nil)
	var ls struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	f.ok("priv_list_dir", m{"path": f.read}, &ls)
	for _, e := range ls.Entries {
		if e.Name == "secrets" {
			t.Error("denied directory listed")
		}
	}
	f.fail("priv_read_file", m{"path": filepath.Join(f.read, "secrets", "token")}, "path_denied")
	f.fail("priv_read_file", m{"path": filepath.Join(f.d, "outside.txt")}, "path_denied")
	f.fail("priv_read_file", m{"path": f.read + "/../srv/app/hello.txt"}, "bad_request")
	// The built-in deny list (POLICY §3) and private-key sniffing apply.
	gatetest.WriteFile(t, filepath.Join(f.read, ".ssh", "id_ed25519"), "x", 0o600)
	f.fail("priv_read_file", m{"path": filepath.Join(f.read, ".ssh", "id_ed25519")}, "path_denied")
	gatetest.WriteFile(t, filepath.Join(f.read, "key.pem"), "-----BEGIN "+"OPENSSH PRIVATE KEY-----\nAAAA\n", 0o600)
	f.fail("priv_read_file", m{"path": filepath.Join(f.read, "key.pem")}, "path_denied")
	// Redaction applies to content.
	gatetest.WriteFile(t, filepath.Join(f.read, "auth.txt"), "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\n", 0o644)
	r := f.ok("priv_read_file", m{"path": filepath.Join(f.read, "auth.txt")}, &rr)
	if strings.Contains(rr.Content, "abcdefghijklmnopqrstuvwxyz0123456789") || len(r.Warnings) == 0 {
		t.Fatalf("not redacted: %q %v", rr.Content, r.Warnings)
	}
}

func TestWriteFile(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.write, "new.conf")
	var w struct {
		SHA256    string   `json:"sha256"`
		Verified  bool     `json:"verified"`
		Created   bool     `json:"created"`
		Mode      string   `json:"mode"`
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("a\n")}, &w)
	if !w.Verified || !w.Created || w.Mode != "0640" || len(w.BackupIDs) != 0 || readFile(t, p) != "a\n" {
		t.Fatalf("new file %+v", w)
	}
	// Mode and owner are preserved on overwrite unless given.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("b\n")}, &w)
	if modeOf(t, p) != 0o600 || len(w.BackupIDs) != 1 || readFile(t, p) != "b\n" {
		t.Fatalf("overwrite %+v mode %04o", w, modeOf(t, p))
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("c\n"), "mode": "0644", "owner": "tester", "group": "tester"}, &w)
	if modeOf(t, p) != 0o644 {
		t.Fatalf("mode %04o", modeOf(t, p))
	}
	st := mustStat(t, p)
	if st.Uid != f.uid || st.Gid != f.gid {
		t.Fatalf("owner %d:%d", st.Uid, st.Gid)
	}
	// Modes within modes.max only; never setuid/setgid/sticky.
	for _, mode := range []string{"0777", "0775", "4755", "2750", "1755", "0757"} {
		f.fail("priv_write_file", m{"path": p, "content_b64": b64("x"), "mode": mode}, "policy_denied")
	}
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("x"), "mode": "banana"}, "bad_request")
	// Owners and groups from the allow-list only.
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("x"), "owner": "example-app"}, "policy_denied")
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("x"), "group": "svc-shell-priv"}, "policy_denied")
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("x"), "owner": "nobody-at-all"}, "policy_denied")
	// Optimistic concurrency.
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("x"), "expected_sha256": strings.Repeat("0", 64)}, "exists")
	// Roots, protected paths and .git.
	f.fail("priv_write_file", m{"path": filepath.Join(f.read, "x"), "content_b64": b64("x")}, "path_denied")
	gatetest.Mkdir(t, filepath.Join(f.write, "repo", ".git"), 0o755)
	f.fail("priv_write_file", m{"path": filepath.Join(f.write, "repo", ".git", "config"), "content_b64": b64("x")}, "path_denied")
	f.fail("priv_write_file", m{"path": filepath.Join(f.write, "authorized_keys"), "content_b64": b64("x")}, "path_denied")
	f.fail("priv_write_file", m{"path": filepath.Join(f.write, "shell-mcp-gate"), "content_b64": b64("x")}, "path_denied")
	f.fail("priv_write_file", m{"path": p, "content_b64": b64(strings.Repeat("x", 65537))}, "too_large")
	if readFile(t, p) != "c\n" {
		t.Fatalf("a refused write changed the file: %q", readFile(t, p))
	}
}

func TestWriteReadBackFailure(t *testing.T) {
	f := newFixture(t)
	f.opts.InjectReadBackFault = func(b []byte) []byte { return append(b, '!') }
	f.fail("priv_write_file", m{"path": filepath.Join(f.write, "v.conf"), "content_b64": b64("v\n")}, "verify_failed")
}

func mustStat(t *testing.T, p string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}

func TestMkdirChownChmod(t *testing.T) {
	f := newFixture(t)
	d := filepath.Join(f.write, "a", "b")
	f.ok("priv_mkdir", m{"path": d, "parents": true, "mode": "0750", "owner": "tester"}, nil)
	if modeOf(t, d) != 0o750 || mustStat(t, d).Uid != f.uid {
		t.Fatalf("mkdir mode %04o", modeOf(t, d))
	}
	f.fail("priv_mkdir", m{"path": filepath.Join(f.write, "c"), "mode": "0777"}, "policy_denied")
	f.fail("priv_mkdir", m{"path": filepath.Join(f.write, "c"), "owner": "example-app"}, "policy_denied")
	p := filepath.Join(f.write, "app.conf")
	var c struct {
		UID uint32 `json:"uid"`
		GID uint32 `json:"gid"`
	}
	f.ok("priv_chown", m{"path": p, "group": "tester"}, &c)
	if c.GID != f.gid {
		t.Fatalf("chown %+v", c)
	}
	f.fail("priv_chown", m{"path": p}, "bad_request")
	f.fail("priv_chown", m{"path": p, "owner": "example-app"}, "policy_denied")
	f.fail("priv_chown", m{"path": filepath.Join(f.read, "hello.txt"), "owner": "tester"}, "path_denied")
	f.ok("priv_chmod", m{"path": p, "mode": "0600"}, nil)
	if modeOf(t, p) != 0o600 {
		t.Fatalf("chmod %04o", modeOf(t, p))
	}
	f.fail("priv_chmod", m{"path": p, "mode": "0777"}, "policy_denied")
	f.fail("priv_chmod", m{"path": p, "mode": "4700"}, "policy_denied")
	f.fail("priv_chmod", m{"path": p}, "bad_request")
}

func TestCopyMoveDelete(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.read, "hello.txt")
	dst := filepath.Join(f.write, "copy.txt")
	f.ok("priv_copy", m{"source": src, "destination": dst}, nil)
	f.fail("priv_copy", m{"source": src, "destination": dst}, "exists")
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	gatetest.WriteFile(t, dst, "old copy\n", 0o640)
	f.ok("priv_copy", m{"source": src, "destination": dst, "overwrite": true}, &w)
	if len(w.BackupIDs) != 1 {
		t.Fatalf("copy-over backups %v", w.BackupIDs)
	}
	mv := filepath.Join(f.write, "moved.txt")
	f.ok("priv_move", m{"source": dst, "destination": mv}, &w)
	if len(w.BackupIDs) != 0 {
		t.Fatalf("move to a new name backed up %v", w.BackupIDs)
	}
	gatetest.WriteFile(t, dst, "replaced\n", 0o640)
	f.ok("priv_move", m{"source": mv, "destination": dst, "overwrite": true}, &w)
	if len(w.BackupIDs) != 1 || readFile(t, dst) != "hello\nworld\n" {
		t.Fatalf("move-over %v", w.BackupIDs)
	}
	f.fail("priv_move", m{"source": src, "destination": filepath.Join(f.write, "x")}, "path_denied")
	var del struct {
		Deleted   bool     `json:"deleted"`
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_delete", m{"path": dst}, &del)
	if !del.Deleted || len(del.BackupIDs) != 1 {
		t.Fatalf("delete %+v", del)
	}
	tree := filepath.Join(f.write, "tree")
	gatetest.WriteFile(t, filepath.Join(tree, "a.txt"), "A", 0o640)
	f.fail("priv_delete", m{"path": tree}, "bad_request")
	f.ok("priv_delete", m{"path": tree, "recursive": true}, &del)
	if !del.Deleted || len(del.BackupIDs) != 1 {
		t.Fatalf("tree delete %+v", del)
	}
	// Above max_delete_entries: refused, nothing backed up or removed.
	big := filepath.Join(f.write, "big")
	for i := range 25 {
		gatetest.WriteFile(t, filepath.Join(big, strings.Repeat("f", i+1)), "x", 0o640)
	}
	before := len(f.backupFiles())
	f.fail("priv_delete", m{"path": big, "recursive": true}, "too_large")
	if len(f.backupFiles()) != before {
		t.Fatal("a refused delete wrote a backup")
	}
	if _, err := os.Stat(filepath.Join(big, "f")); err != nil {
		t.Fatal("a refused delete removed something")
	}
}

// A new file's or directory's default mode (0640, 0750) is capped by
// modes.max, like a requested one; an existing file keeps its mode.
func TestDefaultModesWithinMask(t *testing.T) {
	f := newFixture(t, func(_ *fixture, s *string) { *s = strings.Replace(*s, `max: "0755"`, `max: "0700"`, 1) })
	p := filepath.Join(f.write, "new.conf")
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("x")}, nil)
	d := filepath.Join(f.write, "newdir")
	f.ok("priv_mkdir", m{"path": d}, nil)
	if modeOf(t, p) != 0o600 || modeOf(t, d) != 0o700 {
		t.Fatalf("defaults %04o %04o, want 0600 0700", modeOf(t, p), modeOf(t, d))
	}
	// The existing 0640 file keeps its mode on overwrite.
	f.ok("priv_write_file", m{"path": filepath.Join(f.write, "app.conf"), "content_b64": b64("y")}, nil)
	if modeOf(t, filepath.Join(f.write, "app.conf")) != 0o640 {
		t.Fatalf("existing mode changed to %04o", modeOf(t, filepath.Join(f.write, "app.conf")))
	}
}
