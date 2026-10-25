//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The helper's restore (handoff docs/handoff/S4C-PRIVILEGED.md S4c-5: P-2c,
// P-3, P-10, Q3, Q12, D3, R-1; PRIVILEGED §6, "Restore"), and the moved-in
// rule through the helper's request handling (N-6, N-7; "Files another
// account could have moved in"). Every layout is invented.

type restoreEntryOut struct {
	Path         string `json:"path"`
	Type         string `json:"type"`
	RecordedMode string `json:"recorded_mode"`
	Mode         string `json:"mode"`
}

type restorePreviewOut struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Backup struct {
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
		Entries int    `json:"entries"`
		UID     uint32 `json:"uid"`
		GID     uint32 `json:"gid"`
		Owner   string `json:"owner"`
		Group   string `json:"group"`
		Mode    string `json:"mode"`
		Created string `json:"created"`
		Op      string `json:"op"`
	} `json:"backup"`
	Current struct {
		State  string  `json:"state"`
		Size   int64   `json:"size"`
		Mode   string  `json:"mode"`
		UID    *uint32 `json:"uid"`
		GID    *uint32 `json:"gid"`
		Owner  string  `json:"owner"`
		Group  string  `json:"group"`
		SHA256 string  `json:"sha256"`
	} `json:"current"`
	Restore struct {
		UID          uint32            `json:"uid"`
		GID          uint32            `json:"gid"`
		Mode         string            `json:"mode"`
		RecordedMode string            `json:"recorded_mode"`
		Narrowed     int               `json:"narrowed"`
		First        []restoreEntryOut `json:"first"`
		Truncated    bool              `json:"truncated"`
	} `json:"restore"`
	CurrentBackup struct {
		Written bool  `json:"written"`
		Bytes   int64 `json:"bytes"`
	} `json:"current_backup"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type restoreOut struct {
	ID           string            `json:"id"`
	Path         string            `json:"path"`
	Kind         string            `json:"kind"`
	SHA256       string            `json:"sha256"`
	Entries      int               `json:"entries"`
	Verified     bool              `json:"verified"`
	BackupIDs    []string          `json:"backup_ids"`
	Mode         string            `json:"mode"`
	RecordedMode string            `json:"recorded_mode"`
	Narrowed     int               `json:"narrowed"`
	First        []restoreEntryOut `json:"first"`
	Truncated    bool              `json:"truncated"`
}

var hash64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (f *fixture) previewRestore(id string) restorePreviewOut {
	f.t.Helper()
	var pv restorePreviewOut
	f.ok("priv_restore_preview", m{"id": id}, &pv)
	if !hash64.MatchString(pv.PreviewSHA256) {
		f.t.Fatalf("restore preview hash %q", pv.PreviewSHA256)
	}
	return pv
}

// restoreBound previews the restore of id and restores it with the
// preview's hash.
func (f *fixture) restoreBound(id string) (restorePreviewOut, restoreOut) {
	f.t.Helper()
	pv := f.previewRestore(id)
	var out restoreOut
	f.ok("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, &out)
	return pv, out
}

// overwrite writes content to p through the helper and returns the id of
// the backup of what it replaced.
func (f *fixture) overwrite(p, content string) string {
	f.t.Helper()
	var w writeOut
	f.ok("priv_write_file", m{"path": p, "content_b64": b64(content)}, &w)
	if len(w.BackupIDs) != 1 {
		f.t.Fatalf("overwrite of %s wrote backups %v", p, w.BackupIDs)
	}
	return w.BackupIDs[0]
}

// clearStore empties the backup store, so that long loops do not make every
// backup count thousands of metadata files.
func (f *fixture) clearStore() {
	f.t.Helper()
	for _, n := range f.backupFiles() {
		if err := os.Remove(filepath.Join(f.backups, n)); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) failMsg(op string, args any, code, msg string) {
	f.t.Helper()
	r := f.serve(op, args)
	if r.OK || r.Error == nil || r.Error.Code != code || !strings.Contains(r.Error.Message, msg) {
		f.t.Fatalf("%s %v: got ok=%v error %+v, want %s (%q)", op, args, r.OK, r.Error, code, msg)
	}
}

// TestPrivRestorePreview (P-2c): the backup's record, the current state at
// its path, what will be set and whether the current version is backed up,
// with both hashes; at ceiling read; changing nothing.
func TestPrivRestorePreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	id := f.overwrite(p, "broken\n")
	before := f.backupFiles()
	pv := f.previewRestore(id)
	b, c, r := pv.Backup, pv.Current, pv.Restore
	if pv.ID != id || pv.Kind != "file" || pv.Path != p || b.Size != int64(len("key: value\n")) || b.SHA256 != sum("key: value\n") ||
		b.UID != f.uid || b.GID != f.gid || b.Owner != "tester" || b.Group != "tester" || b.Mode != "0640" || b.Op != "priv_write_file" ||
		!strings.HasPrefix(b.Created, "2026-09-29T12:00:00") || b.Entries != 0 {
		t.Fatalf("backup %+v", pv)
	}
	if c.State != "file" || c.Size != int64(len("broken\n")) || c.Mode != "0640" || c.UID == nil || *c.UID != f.uid || c.SHA256 != sum("broken\n") || c.Owner != "tester" {
		t.Fatalf("current %+v", c)
	}
	if r.UID != f.uid || r.GID != f.gid || r.Mode != "0640" || r.RecordedMode != "0640" || r.Narrowed != 0 || len(r.First) != 0 || r.Truncated {
		t.Fatalf("restore %+v", r)
	}
	if !pv.CurrentBackup.Written || pv.CurrentBackup.Bytes != int64(len("broken\n")) || pv.PolicySHA256 != f.opts.ExpectedSHA256 {
		t.Fatalf("current backup %+v policy %s", pv.CurrentBackup, pv.PolicySHA256)
	}
	if again := f.previewRestore(id); again.PreviewSHA256 != pv.PreviewSHA256 {
		t.Fatal("the same preview hashes differently")
	}
	if rr := f.serveAt("read", "priv_restore_preview", m{"id": id}); !rr.OK {
		t.Fatalf("preview at ceiling read: %+v", rr.Error)
	}
	if rr := f.serveAt("read", "priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}); rr.OK || rr.Error.Code != "tier_denied" {
		t.Fatalf("restore at ceiling read: %+v", rr.Error)
	}
	f.fail("priv_restore_preview", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, "bad_request")
	if readFile(t, p) != "broken\n" || !slices.Equal(f.backupFiles(), before) {
		t.Fatal("a preview changed something")
	}
	// A deleted file: nothing there now, nothing to back up.
	_, del := f.deleteBound(p, false)
	pv = f.previewRestore(del.BackupIDs[0])
	if pv.Current.State != "absent" || pv.Current.SHA256 != "" || pv.CurrentBackup.Written || pv.Backup.SHA256 != sum("broken\n") {
		t.Fatalf("absent: %+v", pv)
	}
}

// TestPrivRestoreBindsThePreview (P-3): the restore requires the preview's
// hash; another one, or a change to the file or the policy after the
// preview, is exists and nothing is restored or backed up.
func TestPrivRestoreBindsThePreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	id := f.overwrite(p, "broken\n")
	pv := f.previewRestore(id)
	before := f.backupFiles()
	f.fail("priv_restore_backup", m{"id": id}, "bad_request")
	for _, bad := range []string{"", "abc", strings.ToUpper(pv.PreviewSHA256), pv.PreviewSHA256 + "0"} {
		f.fail("priv_restore_backup", m{"id": id, "expected_preview_sha256": bad}, "bad_request")
	}
	f.failMsg("priv_restore_backup", m{"id": id, "expected_preview_sha256": strings.Repeat("0", 64)}, "exists", "nothing was restored")
	if readFile(t, p) != "broken\n" || !slices.Equal(f.backupFiles(), before) {
		t.Fatal("a refused restore changed something")
	}
	// The file changed after the preview.
	writeTestFile(t, p, "changed\n")
	f.fail("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	if readFile(t, p) != "changed\n" || !slices.Equal(f.backupFiles(), before) {
		t.Fatal("a file changed after the preview was replaced")
	}
	// The privileged policy changed after the preview.
	pv = f.previewRestore(id)
	gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), "max_output_bytes: 4096", "max_output_bytes: 4097", 1), 0o600)
	f.rehash()
	if again := f.previewRestore(id); again.PreviewSHA256 == pv.PreviewSHA256 || again.PolicySHA256 == pv.PolicySHA256 {
		t.Fatal("the preview hash does not cover the privileged policy")
	}
	f.fail("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	if readFile(t, p) != "changed\n" {
		t.Fatal("restored under an edited policy")
	}
}

// TestPrivRestoreFile: restored over the previewed file with its recorded
// owner and mode, the current version backed up first (and bound to it);
// that backup restores in turn; a deleted file comes back create-only.
func TestPrivRestoreFile(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	var w writeOut
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("broken\n"), "mode": "0600"}, &w)
	id := w.BackupIDs[0]
	_, r := f.restoreBound(id)
	if readFile(t, p) != "key: value\n" || modeOf(t, p) != 0o640 || r.ID != id || r.Path != p || r.Kind != "file" || r.SHA256 != sum("key: value\n") ||
		!r.Verified || r.Mode != "0640" || r.RecordedMode != "0640" || r.Narrowed != 0 || len(r.First) != 0 {
		t.Fatalf("restore %+v content %q mode %04o", r, readFile(t, p), modeOf(t, p))
	}
	if len(r.BackupIDs) != 1 {
		t.Fatalf("backups %v", r.BackupIDs)
	}
	md := f.metas()
	i := slices.IndexFunc(md, func(x map[string]any) bool { return x["id"] == r.BackupIDs[0] })
	if i < 0 || md[i]["sha256"] != sum("broken\n") || md[i]["preview_sha256"] != sum("broken\n") || md[i]["op"] != "priv_restore_backup" {
		t.Fatalf("the current version's backup %v", md)
	}
	// The audit line names the backup restored and the one written, never the hash.
	l := f.lastAudit()
	if !strings.Contains(l, `"backup_id":"`+id+`"`) || !strings.Contains(l, `"backup_ids":["`+r.BackupIDs[0]+`"]`) || strings.Contains(l, "expected_preview_sha256") {
		t.Fatalf("audit %q", l)
	}
	f.restoreBound(r.BackupIDs[0])
	if readFile(t, p) != "broken\n" || modeOf(t, p) != 0o600 {
		t.Fatal("restoring the restore's backup failed")
	}
	_, del := f.deleteBound(p, false)
	_, r = f.restoreBound(del.BackupIDs[0])
	if readFile(t, p) != "broken\n" || len(r.BackupIDs) != 0 {
		t.Fatalf("deleted file not restored: %+v", r)
	}
}

// TestPrivRestoreTree: a tree comes back where nothing exists, with its
// recorded modes, the entry count checked; a second restore is refused at
// the preview.
func TestPrivRestoreTree(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tree := filepath.Join(f.write, "tree")
	gatetest.WriteFile(t, filepath.Join(tree, "a.txt"), "A", 0o640)
	gatetest.WriteFile(t, filepath.Join(tree, "sub", "b.txt"), "B", 0o600)
	gatetest.Mkdir(t, filepath.Join(tree, "sub"), 0o750)
	gatetest.Mkdir(t, filepath.Join(tree, "empty"), 0o700)
	_, del := f.deleteBound(tree, true)
	pv, r := f.restoreBound(del.BackupIDs[0])
	if pv.Kind != "tree" || pv.Backup.Entries != 4 || pv.Current.State != "absent" || pv.CurrentBackup.Written || len(pv.Restore.First) != 4 {
		t.Fatalf("preview %+v", pv)
	}
	if r.Kind != "tree" || r.Entries != 4 || !r.Verified || len(r.BackupIDs) != 0 || len(r.First) != 4 || r.Narrowed != 0 {
		t.Fatalf("restore %+v", r)
	}
	if readFile(t, filepath.Join(tree, "a.txt")) != "A" || readFile(t, filepath.Join(tree, "sub", "b.txt")) != "B" ||
		modeOf(t, filepath.Join(tree, "sub", "b.txt")) != 0o600 || modeOf(t, filepath.Join(tree, "sub")) != 0o750 ||
		modeOf(t, filepath.Join(tree, "empty")) != 0o700 {
		t.Fatal("tree not restored with its modes")
	}
	f.failMsg("priv_restore_preview", m{"id": del.BackupIDs[0]}, "exists", "only where nothing exists")
}

// TestPrivRestoreModeNarrowed (R-1, P-10): a recorded mode wider than
// modes.max is narrowed, and the preview and the result say so, for a file
// and for every entry of a tree.
func TestPrivRestoreModeNarrowed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mask0700())
	p := filepath.Join(f.write, "wide.conf")
	gatetest.WriteFile(t, p, "wide\n", 0o644)
	id := f.overwrite(p, "narrow\n")
	pv, r := f.restoreBound(id)
	if pv.Backup.Mode != "0644" || pv.Restore.RecordedMode != "0644" || pv.Restore.Mode != "0600" || pv.Restore.Narrowed != 1 {
		t.Fatalf("file preview %+v", pv)
	}
	if r.RecordedMode != "0644" || r.Mode != "0600" || r.Narrowed != 1 || modeOf(t, p) != 0o600 {
		t.Fatalf("file result %+v, mode %04o", r, modeOf(t, p))
	}
	tree := filepath.Join(f.write, "tree")
	gatetest.Mkdir(t, filepath.Join(tree, "sub"), 0o755)
	gatetest.WriteFile(t, filepath.Join(tree, "a.txt"), "A", 0o644)
	gatetest.WriteFile(t, filepath.Join(tree, "sub", "w.txt"), "W", 0o600)
	if err := os.Chmod(tree, 0o755); err != nil { //nolint:gosec // G302: a recorded mode wider than the mask
		t.Fatal(err)
	}
	_, del := f.deleteBound(tree, true)
	pv, r = f.restoreBound(del.BackupIDs[0])
	want := []restoreEntryOut{
		{tree + "/a.txt", "file", "0644", "0600"},
		{tree + "/sub", "dir", "0755", "0700"},
		{tree + "/sub/w.txt", "file", "0600", "0600"},
	}
	if pv.Restore.RecordedMode != "0755" || pv.Restore.Mode != "0700" || pv.Restore.Narrowed != 3 || !slices.Equal(pv.Restore.First, want) {
		t.Fatalf("tree preview %+v", pv.Restore)
	}
	if r.RecordedMode != "0755" || r.Mode != "0700" || r.Narrowed != 3 || !slices.Equal(r.First, want) {
		t.Fatalf("tree result %+v", r)
	}
	for q, mode := range map[string]os.FileMode{tree: 0o700, tree + "/a.txt": 0o600, tree + "/sub": 0o700, tree + "/sub/w.txt": 0o600} {
		if modeOf(t, q) != mode {
			t.Fatalf("%s: %04o, want %04o", q, modeOf(t, q), mode)
		}
	}
}

// TestPrivRestoreRefusals: each refusal at the preview, and at the restore
// where it can arise after the preview, changing nothing.
func TestPrivRestoreRefusals(t *testing.T) {
	t.Parallel()
	t.Run("ids", func(t *testing.T) {
		f := newFixture(t)
		for _, op := range []string{"priv_restore_preview", "priv_restore_backup"} {
			a := m{"id": "20260101T000000Z-0000000000000000"}
			if op == "priv_restore_backup" {
				a["expected_preview_sha256"] = strings.Repeat("0", 64)
			}
			f.fail(op, a, "not_found")
			for _, bad := range []string{"", "../x", "20260101T000000Z-0000000000000000.meta.json", "20260101T000000Z-000000000000000G", "x"} {
				a["id"] = bad
				f.fail(op, a, "bad_request")
			}
		}
		g := newFixture(t, keep(0))
		g.failMsg("priv_restore_preview", m{"id": "20260101T000000Z-0000000000000000"}, "not_found", "backups are disabled")
	})
	t.Run("tampered", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(f.write, "app.conf")
		id := f.overwrite(p, "v2\n")
		data := filepath.Join(f.backups, id+".data")
		writeTestFile(t, data, "tampered\n")
		f.failMsg("priv_restore_preview", m{"id": id}, "verify_failed", "does not match its record")
		// Tampered after the preview: refused at the restore, nothing restored or backed up.
		writeTestFile(t, data, "key: value\n")
		pv := f.previewRestore(id)
		before := f.backupFiles()
		writeTestFile(t, data, "key: valuf\n")
		f.failMsg("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, "verify_failed", "nothing was restored")
		if readFile(t, p) != "v2\n" || !slices.Equal(f.backupFiles(), before) {
			t.Fatal("a tampered backup was restored")
		}
		if err := os.Remove(data); err != nil {
			t.Fatal(err)
		}
		f.fail("priv_restore_preview", m{"id": id}, "backup_failed")
	})
	t.Run("path", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(f.write, "app.conf")
		id := f.overwrite(p, "v2\n")
		// Now denied.
		gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), `deny: ["`, `deny: ["`+p+`", "`, 1), 0o600)
		f.rehash()
		f.fail("priv_restore_preview", m{"id": id}, "path_denied")
		// No longer under a write root.
		gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), `deny: ["`+p+`", "`, `deny: ["`, 1), 0o600)
		gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), "write: ["+f.write+"]", "write: ["+f.write+"/elsewhere]", 1), 0o600)
		gatetest.Mkdir(t, filepath.Join(f.write, "elsewhere"), 0o755)
		f.rehash()
		f.fail("priv_restore_preview", m{"id": id}, "path_denied")
	})
	t.Run("current", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(f.write, "app.conf")
		id := f.overwrite(p, "v2\n")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("elsewhere", p); err != nil {
			t.Fatal(err)
		}
		f.fail("priv_restore_preview", m{"id": id}, "path_denied")
		_ = os.Remove(p)
		gatetest.Mkdir(t, p, 0o755)
		f.fail("priv_restore_preview", m{"id": id}, "is_a_directory")
		_ = os.Remove(p)
		gatetest.WriteFile(t, p, "ww\n", 0o600)
		if err := os.Chmod(p, 0o666); err != nil { //nolint:gosec // G302: a world-writable file the helper refuses to replace
			t.Fatal(err)
		}
		f.fail("priv_restore_preview", m{"id": id}, "policy_denied")
	})
	t.Run("tree", func(t *testing.T) {
		f := newFixture(t)
		tree := filepath.Join(f.write, "tree")
		files := delTree(t, tree)
		_, del := f.deleteBound(tree, true)
		id := del.BackupIDs[0]
		gatetest.Mkdir(t, tree, 0o755)
		f.fail("priv_restore_preview", m{"id": id}, "exists")
		if err := os.Remove(tree); err != nil {
			t.Fatal(err)
		}
		// An entry now denied.
		gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), `deny: ["`, `deny: ["`+files[3]+`", "`, 1), 0o600)
		f.rehash()
		f.fail("priv_restore_preview", m{"id": id}, "path_denied")
		// More entries than max_delete_entries now allows.
		gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), `deny: ["`+files[3]+`", "`, `deny: ["`, 1), 0o600)
		gatetest.WriteFile(t, f.policyPath, strings.Replace(readFile(t, f.policyPath), "max_delete_entries: 20", "max_delete_entries: 3", 1), 0o600)
		f.rehash()
		f.fail("priv_restore_preview", m{"id": id}, "too_large")
		if present(tree) {
			t.Fatal("a refused tree restore created something")
		}
	})
	t.Run("store cap", func(t *testing.T) {
		f := newFixture(t, storeCap(minStore))
		p := filepath.Join(f.write, "app.conf")
		id := f.overwrite(p, "v2\n")
		pv := f.previewRestore(id)
		f.junk(minStore - f.storeUse())
		before := f.backupFiles()
		f.failMsg("priv_restore_preview", m{"id": id}, "backup_failed", "backup store is full")
		f.failMsg("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, "backup_failed", "backup store is full")
		if readFile(t, p) != "v2\n" || !slices.Equal(f.backupFiles(), before) {
			t.Fatal("a restore refused by the store cap changed something")
		}
	})
}

// TestPrivRestoreKeepsTheRestoredBackup (Q12): the retention of the backup
// a restore writes never removes the backup being restored, and the store's
// cap does not count it as freed.
func TestPrivRestoreKeepsTheRestoredBackup(t *testing.T) {
	t.Parallel()
	f := newFixture(t) // keep: 3
	p := filepath.Join(f.write, "app.conf")
	b1 := f.overwrite(p, "v2\n")
	f.overwrite(p, "v3\n")
	f.overwrite(p, "v4\n")
	_, r := f.restoreBound(b1)
	if readFile(t, p) != "key: value\n" || len(r.BackupIDs) != 1 {
		t.Fatalf("restore %+v", r)
	}
	for _, suffix := range []string{".meta.json", ".data"} {
		if !present(filepath.Join(f.backups, b1+suffix)) {
			t.Fatalf("the restored backup %s was pruned", b1)
		}
	}
	// Restored again at once: still there, and still kept.
	f.restoreBound(b1)
	if readFile(t, p) != "key: value\n" || !present(filepath.Join(f.backups, b1+".data")) {
		t.Fatal("the restored backup does not restore again, or was pruned")
	}

	// The cap: a 1 MiB oldest version would be freed by retention, but not
	// when it is the backup being restored.
	g := newFixture(t, storeCap(minStore))
	q := filepath.Join(g.write, "big.conf")
	gatetest.WriteFile(t, q, strings.Repeat("b", 1<<20), 0o640)
	big := g.overwrite(q, "v2\n")
	g.overwrite(q, "v3\n")
	g.overwrite(q, "v4\n")
	g.junk(minStore - g.storeUse())
	g.failMsg("priv_restore_preview", m{"id": big}, "backup_failed", "backup store is full")
}

// TestPrivRestoreWindows: the target changes at each point of the restore;
// a racing file is never replaced. 100 runs per point, each counted.
func TestPrivRestoreWindows(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	replaceWithRacer := func(p, racer string) {
		writeTestFile(t, p+".racer", racer)
		if err := os.Rename(p+".racer", p); err != nil {
			t.Error(err)
		}
	}
	rewriteInPlace := func(p, racer string) {
		time.Sleep(2 * time.Millisecond) // a new mtime, whatever the clock's granularity
		writeTestFile(t, p, racer)
	}
	type point struct {
		name   string
		absent bool
		hook   func(p, racer string) // InjectBeforeCommit, InjectBeforeBackup or before the request
		at     string                // "request", "backup" or "commit"
	}
	points := []point{
		{"replaced after the preview", false, replaceWithRacer, "request"},
		{"replaced before the backup", false, replaceWithRacer, "backup"},
		{"replaced before the commit", false, replaceWithRacer, "commit"},
		{"rewritten in place before the commit", false, rewriteInPlace, "commit"},
		{"created after the preview", true, replaceWithRacer, "request"},
		{"created before the commit", true, replaceWithRacer, "commit"},
	}
	for _, pt := range points {
		counts := map[string]int{}
		for i := range helperWindowRuns {
			f.clearStore()
			p := filepath.Join(f.write, fmt.Sprintf("w-%d-%d.conf", slices.IndexFunc(points, func(x point) bool { return x.name == pt.name }), i))
			writeTestFile(t, p, "approved old\n")
			id := f.overwrite(p, "current\n")
			if pt.absent {
				_, del := f.deleteBound(p, false)
				id = del.BackupIDs[0]
			}
			pv := f.previewRestore(id)
			racer := fmt.Sprintf("racer %d\n", i)
			hook := func() { pt.hook(p, racer) }
			switch pt.at {
			case "request":
				hook()
			case "backup":
				f.opts.InjectBeforeBackup = hook
			case "commit":
				f.opts.InjectBeforeCommit = hook
			}
			before := len(f.metas())
			r := f.serve("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256})
			f.opts.InjectBeforeBackup, f.opts.InjectBeforeCommit = nil, nil
			if r.OK {
				t.Fatalf("%s, run %d: restored over a racing file", pt.name, i)
			}
			if got := readFile(t, p); got != racer {
				t.Fatalf("%s, run %d: the racing file was replaced: %q (%+v)", pt.name, i, got, r.Error)
			}
			if after := len(f.metas()); after != before {
				t.Fatalf("%s, run %d: a refused restore kept %d backups", pt.name, i, after-before)
			}
			counts[r.Error.Code]++
		}
		t.Logf("%s: %d runs, refused %v, the racing file kept every time, no backup kept", pt.name, helperWindowRuns, counts)
	}

	// A tree: entries planted before a file's commit stop the restore with
	// exists and the counts; the planted files are untouched.
	counts := map[string]int{}
	for i := range helperWindowRuns {
		f.clearStore()
		tree := filepath.Join(f.write, fmt.Sprintf("t-%d", i))
		files := delTree(t, tree)
		_, del := f.deleteBound(tree, true)
		pv := f.previewRestore(del.BackupIDs[0])
		planted := map[string]string{}
		f.opts.InjectBeforeCommit = func() {
			for _, q := range files {
				if strings.HasSuffix(q, ".txt") && !present(q) && present(filepath.Dir(q)) {
					planted[q] = "planted " + q
					writeTestFile(t, q, planted[q])
				}
			}
		}
		r := f.serve("priv_restore_backup", m{"id": del.BackupIDs[0], "expected_preview_sha256": pv.PreviewSHA256})
		f.opts.InjectBeforeCommit = nil
		if r.OK || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, "entries were restored") {
			t.Fatalf("tree run %d: %+v", i, r.Error)
		}
		for q, want := range planted {
			if readFile(t, q) != want {
				t.Fatalf("tree run %d: the planted %s was replaced", i, q)
			}
		}
		counts[fmt.Sprintf("%d planted", len(planted))]++
	}
	t.Logf("a tree with files planted before a commit: %d runs, exists with the counts every time, planted files kept: %v", helperWindowRuns, counts)
}

// TestPrivRestoreConcurrentRacer: a racer replaces the restore's target
// once, after a random delay of up to twice a restore's median duration.
// Whatever the order, its file is never lost; a restore that succeeds
// replaced the previewed version only (its backup holds it).
func TestPrivRestoreConcurrentRacer(t *testing.T) {
	t.Parallel()
	const runs = 400
	f := newFixture(t)
	prep := func(name string) (string, string, restorePreviewOut) {
		p := filepath.Join(f.write, name)
		writeTestFile(t, p, "approved old\n")
		id := f.overwrite(p, "current\n")
		return p, id, f.previewRestore(id)
	}
	var durs []time.Duration
	for i := range 9 {
		_, id, pv := prep(fmt.Sprintf("calibrate%d", i))
		start := time.Now()
		f.ok("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, nil)
		durs = append(durs, time.Since(start))
	}
	slices.Sort(durs)
	dur := durs[len(durs)/2]
	counts := map[string]int{}
	for i := range runs {
		f.clearStore()
		p, id, pv := prep(fmt.Sprintf("race-%d.conf", i))
		racer := fmt.Sprintf("racer %d\n", i)
		done := make(chan struct{})
		go func() {
			defer close(done)
			time.Sleep(time.Duration(rand.Int64N(int64(2*dur) + 1))) //nolint:gosec // G404: test timing
			writeTestFile(t, p+".racer", racer)
			_ = os.Rename(p+".racer", p)
		}()
		var r restoreOut
		resp := f.serve("priv_restore_backup", m{"id": id, "expected_preview_sha256": pv.PreviewSHA256})
		<-done
		if got := readFile(t, p); got != racer {
			t.Fatalf("run %d: the racer's file was lost: %q (%+v)", i, got, resp.Error)
		}
		switch {
		case resp.OK:
			if err := json.Unmarshal(resp.Data, &r); err != nil || len(r.BackupIDs) != 1 || f.meta(r.BackupIDs[0]).SHA256 != sum("current\n") {
				t.Fatalf("run %d: restored over something other than the previewed version: %+v %v", i, r, err)
			}
			counts["restored, then the racer replaced it"]++
		case resp.Error.Code == "exists" && strings.Contains(resp.Error.Message, "since the preview"):
			counts["refused at the recompute"]++
		case resp.Error.Code == "backup_failed" || resp.Error.Code == "exists" && strings.Contains(resp.Error.Message, "backed up"):
			counts["refused at the backup"]++
		case resp.Error.Code == "exists":
			counts["refused at the commit"]++
		case resp.Error.Code == "path_denied" && strings.Contains(resp.Error.Message, "no stable path"):
			// The racer renamed over the target between an open and the
			// check of what was opened (fsx's openTarget): refused before
			// anything was committed.
			counts["refused at an open, the file replaced meanwhile"]++
		case resp.Error.Code == "verify_failed":
			counts["the racer after the commit, reported by the read-back"]++
		default:
			t.Fatalf("run %d: %+v", i, resp.Error)
		}
		// A refusal before the commit keeps no backup of its own: only the
		// overwrite's backup that prep made is in the store.
		if !resp.OK && resp.Error.Code != "verify_failed" {
			if n := len(f.metas()); n != 1 {
				t.Fatalf("run %d: refused with %s, but %d backups are in the store", i, resp.Error.Code, n)
			}
		}
	}
	t.Logf("concurrent racer through the helper: %d runs (a restore takes ~%v); the racer's file survived every run", runs, dur)
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		t.Logf("| %-54s | %3d |", k, counts[k])
	}
}

// TestPrivMovedIn (N-6, N-7) through the helper. Another account's write
// access is a group- or world-writable directory (an unprivileged test
// cannot make another uid's directory; e2e-host covers those).
func TestPrivMovedIn(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := filepath.Join(f.write, "drop")
	gatetest.Mkdir(t, drop, 0o755)
	if err := os.Chmod(drop, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	secret := filepath.Join(drop, "secret")
	gatetest.WriteFile(t, secret, "SECRET\n", 0o600)
	public := filepath.Join(drop, "public")
	gatetest.WriteFile(t, public, "public\n", 0o644)
	// Reads: a file the movers could not read is refused, by name of the
	// directory; a world-readable one is read; metadata is unchanged.
	f.failMsg("priv_read_file", m{"path": secret}, "path_denied", drop)
	f.failMsg("priv_copy", m{"source": secret, "destination": filepath.Join(f.write, "copied")}, "path_denied", drop)
	if present(filepath.Join(f.write, "copied")) {
		t.Fatal("a refused copy created its destination")
	}
	f.ok("priv_read_file", m{"path": public}, nil)
	f.ok("priv_stat", m{"path": secret}, nil)
	f.ok("priv_list_dir", m{"path": drop}, nil)
	// Overwrites: the owner is not inherited; a write needs both, a copy is
	// refused.
	f.failMsg("priv_write_file", m{"path": public, "content_b64": b64("new\n"), "expected_sha256": sum("public\n")}, "path_denied", drop)
	f.failMsg("priv_write_file", m{"path": public, "content_b64": b64("new\n"), "owner": "tester"}, "path_denied", drop)
	src := filepath.Join(f.write, "src")
	gatetest.WriteFile(t, src, "src\n", 0o640)
	f.failMsg("priv_copy", m{"source": src, "destination": public, "overwrite": true, "expected_destination_sha256": sum("public\n")}, "path_denied", drop)
	if readFile(t, public) != "public\n" {
		t.Fatal("a refused overwrite changed the file")
	}
	// An explicit owner and group pass only where that owner could have
	// made the file itself; under a world-writable directory no owner does
	// (rule R, handoff N-8).
	f.failMsg("priv_write_file", m{"path": public, "content_b64": b64("new\n"), "owner": "tester", "group": "tester"}, "path_denied", drop)
	if readFile(t, public) != "public\n" {
		t.Fatal("a refused overwrite changed the file")
	}
	// A restore whose recorded owner would land under that directory: the
	// backup a delete (no chain rule) wrote.
	_, del := f.deleteBound(public, false)
	f.failMsg("priv_restore_preview", m{"id": del.BackupIDs[0]}, "path_denied", drop)
	// A same-parent directory swap inside a read root.
	app := filepath.Join(f.read, "app")
	gatetest.Mkdir(t, filepath.Join(app, "secrets"), 0o755)
	if err := os.Chmod(app, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(app, "secrets", "token"), "TOKEN\n", 0o600)
	if err := os.Rename(filepath.Join(app, "secrets"), filepath.Join(app, "config")); err != nil {
		t.Fatal(err)
	}
	f.failMsg("priv_read_file", m{"path": filepath.Join(app, "config", "token")}, "path_denied", app)
}
