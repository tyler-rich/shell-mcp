//go:build linux

package ops_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

var backupIDRE = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{16}$`)

type backupMeta struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Mode    string `json:"mode"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
	Created string `json:"created"`
	Op      string `json:"op"`
	Request string `json:"request_id"`
}

func (f *fixture) meta(id string) backupMeta {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.backups, id+".meta.json")) //nolint:gosec // G304: test fixture
	if err != nil {
		f.t.Fatal(err)
	}
	var bm backupMeta
	if err := json.Unmarshal(b, &bm); err != nil {
		f.t.Fatal(err)
	}
	return bm
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestBackupFormat: the store is root-only, one metadata file and one data
// file per backup, written before the change and recording the original
// path, owner, mode and SHA-256.
func TestBackupFormat(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("v2\n")}, &w)
	if len(w.BackupIDs) != 1 || !backupIDRE.MatchString(w.BackupIDs[0]) {
		t.Fatalf("backup ids %v", w.BackupIDs)
	}
	id := w.BackupIDs[0]
	bm := f.meta(id)
	if bm.V != 1 || bm.ID != id || bm.Kind != "file" || bm.Path != p || bm.UID != f.uid || bm.GID != f.gid ||
		bm.Mode != "0640" || bm.Size != int64(len("key: value\n")) || bm.SHA256 != sum("key: value\n") ||
		bm.Op != "priv_write_file" || bm.Request != reqID || !strings.HasPrefix(bm.Created, "2026-09-29T12:00:00") {
		t.Fatalf("meta %+v", bm)
	}
	data := filepath.Join(f.backups, id+".data")
	if readFile(t, data) != "key: value\n" || modeOf(t, data) != 0o600 || modeOf(t, filepath.Join(f.backups, id+".meta.json")) != 0o600 {
		t.Fatalf("data file %q mode %04o", readFile(t, data), modeOf(t, data))
	}
	for _, n := range f.backupFiles() {
		if strings.Contains(n, ".tmp") {
			t.Fatalf("temp file %s left in the store", n)
		}
	}
	// The audit line names the backup, never the content.
	l := f.lastAudit()
	if !strings.Contains(l, id) || strings.Contains(l, "v2") || strings.Contains(l, b64("v2\n")) {
		t.Fatalf("audit %q", l)
	}
}

// A backup that cannot be written aborts the operation with backup_failed
// and changes nothing.
func TestBackupFailureChangesNothing(t *testing.T) {
	p := func(f *fixture) string { return filepath.Join(f.write, "app.conf") }
	for name, breakStore := range map[string]func(f *fixture){
		"missing store":        func(f *fixture) { _ = os.Remove(f.backups) },
		"group-readable store": func(f *fixture) { _ = os.Chmod(f.backups, 0o750) }, //nolint:gosec // G302: a deliberately insecure or test fixture mode
		"store is a file": func(f *fixture) {
			_ = os.Remove(f.backups)
			gatetest.WriteFile(t, f.backups, "x", 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			breakStore(f)
			f.fail("priv_write_file", m{"path": p(f), "content_b64": b64("v2\n")}, "backup_failed")
			f.fail("priv_delete", m{"path": p(f)}, "backup_failed")
			gatetest.WriteFile(t, filepath.Join(f.write, "src"), "s", 0o640)
			f.fail("priv_move", m{"source": filepath.Join(f.write, "src"), "destination": p(f), "overwrite": true}, "backup_failed")
			if readFile(t, p(f)) != "key: value\n" {
				t.Fatal("changed after a failed backup")
			}
			// Creating a new file replaces nothing and needs no backup.
			f.ok("priv_write_file", m{"path": filepath.Join(f.write, "fresh"), "content_b64": b64("x")}, nil)
		})
	}
}

func TestBackupsDisabled(t *testing.T) {
	f := newFixture(t, keep(0))
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": filepath.Join(f.write, "app.conf"), "content_b64": b64("v2\n")}, &w)
	if len(w.BackupIDs) != 0 || len(f.backupFiles()) != 0 {
		t.Fatalf("keep 0 wrote backups %v %v", w.BackupIDs, f.backupFiles())
	}
}

// backups.keep versions are kept per path; older ones are removed.
func TestBackupRetention(t *testing.T) {
	f := newFixture(t) // keep: 3
	p := filepath.Join(f.write, "app.conf")
	other := filepath.Join(f.write, "other.conf")
	gatetest.WriteFile(t, other, "o\n", 0o640)
	f.ok("priv_write_file", m{"path": other, "content_b64": b64("o2\n")}, nil)
	var ids []string
	for i := range 5 {
		var w struct {
			BackupIDs []string `json:"backup_ids"`
		}
		f.ok("priv_write_file", m{"path": p, "content_b64": b64(strings.Repeat("v", i+2) + "\n")}, &w)
		ids = append(ids, w.BackupIDs...)
	}
	var lb struct {
		Backups []backupMeta `json:"backups"`
	}
	f.ok("priv_list_backups", m{"path": p}, &lb)
	if len(lb.Backups) != 3 {
		t.Fatalf("%d backups kept for the path, want 3: %+v", len(lb.Backups), lb.Backups)
	}
	// Newest first; the two oldest are gone from the store.
	if lb.Backups[0].ID != ids[4] || lb.Backups[2].ID != ids[2] {
		t.Fatalf("order %v, written %v", lb.Backups, ids)
	}
	for _, gone := range ids[:2] {
		if _, err := os.Stat(filepath.Join(f.backups, gone+".data")); err == nil {
			t.Fatalf("backup %s was not pruned", gone)
		}
	}
	f.ok("priv_list_backups", m{"path": other}, &lb)
	if len(lb.Backups) != 1 {
		t.Fatalf("retention crossed paths: %+v", lb.Backups)
	}
	f.ok("priv_list_backups", m{}, &lb)
	if len(lb.Backups) != 4 {
		t.Fatalf("all backups %d", len(lb.Backups))
	}
}

func TestRestoreFile(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("broken\n"), "mode": "0600"}, &w)
	id := w.BackupIDs[0]
	var r struct {
		ID        string   `json:"id"`
		Path      string   `json:"path"`
		Kind      string   `json:"kind"`
		SHA256    string   `json:"sha256"`
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_restore_backup", m{"id": id}, &r)
	if readFile(t, p) != "key: value\n" || modeOf(t, p) != 0o640 || r.Path != p || r.Kind != "file" || r.SHA256 != sum("key: value\n") {
		t.Fatalf("restore %+v content %q mode %04o", r, readFile(t, p), modeOf(t, p))
	}
	// The restore itself was backed up first: the broken version can come back.
	if len(r.BackupIDs) != 1 || f.meta(r.BackupIDs[0]).SHA256 != sum("broken\n") {
		t.Fatalf("restore did not back up the current version: %v", r.BackupIDs)
	}
	f.ok("priv_restore_backup", m{"id": r.BackupIDs[0]}, nil)
	if readFile(t, p) != "broken\n" {
		t.Fatal("restoring the restore's backup failed")
	}
	// A deleted file comes back.
	var del struct {
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_delete", m{"path": p}, &del)
	f.ok("priv_restore_backup", m{"id": del.BackupIDs[0]}, nil)
	if readFile(t, p) != "broken\n" {
		t.Fatal("deleted file not restored")
	}
}

func TestRestoreTree(t *testing.T) {
	f := newFixture(t)
	tree := filepath.Join(f.write, "tree")
	gatetest.WriteFile(t, filepath.Join(tree, "a.txt"), "A", 0o640)
	gatetest.WriteFile(t, filepath.Join(tree, "sub", "b.txt"), "B", 0o600)
	gatetest.Mkdir(t, filepath.Join(tree, "sub"), 0o750)
	gatetest.Mkdir(t, filepath.Join(tree, "empty"), 0o700)
	var del struct {
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_delete", m{"path": tree, "recursive": true}, &del)
	if bm := f.meta(del.BackupIDs[0]); bm.Kind != "tree" || bm.Entries != 4 {
		t.Fatalf("tree meta %+v", bm)
	}
	f.ok("priv_restore_backup", m{"id": del.BackupIDs[0]}, nil)
	if readFile(t, filepath.Join(tree, "a.txt")) != "A" || readFile(t, filepath.Join(tree, "sub", "b.txt")) != "B" ||
		modeOf(t, filepath.Join(tree, "sub", "b.txt")) != 0o600 || modeOf(t, filepath.Join(tree, "sub")) != 0o750 ||
		modeOf(t, filepath.Join(tree, "empty")) != 0o700 {
		t.Fatal("tree not restored with its modes")
	}
	// A tree is restored only where nothing exists.
	f.fail("priv_restore_backup", m{"id": del.BackupIDs[0]}, "exists")
}

func TestRestoreRefusals(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("v2\n")}, &w)
	id := w.BackupIDs[0]
	f.fail("priv_restore_backup", m{"id": "20260101T000000Z-0000000000000000"}, "not_found")
	for _, bad := range []string{"", "../x", id + ".meta.json", strings.ToUpper(id), "x"} {
		f.fail("priv_restore_backup", m{"id": bad}, "bad_request")
	}
	// Tampered data is never restored.
	if err := os.WriteFile(filepath.Join(f.backups, id+".data"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.fail("priv_restore_backup", m{"id": id}, "backup_failed")
	if readFile(t, p) != "v2\n" {
		t.Fatal("tampered backup restored")
	}
}
