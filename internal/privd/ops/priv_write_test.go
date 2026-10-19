//go:build linux

package ops_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
)

// S4c-2 (handoff docs/handoff/S4C-PRIVILEGED.md §5): the backup store's
// total size cap (backups.max_store_bytes, §4.1), pruning after the
// operation commits (X-8), backups bound to what was previewed (D3), the
// destination binding of copy and move with overwrite (P-9), the
// priv_backup_check op (P-11), the owner in results (P-12) and the
// replacing commits' window. Every path and value is invented.

const minStore = 64 << 20 // the smallest backups.max_store_bytes

func storeCap(n int64) opt {
	return replace("keep: 3", fmt.Sprintf("keep: 3\n  max_store_bytes: %d", n))
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// junk puts a sparse file of n bytes in the store: counted by its size,
// costing no disk.
func (f *fixture) junk(n int64) {
	f.t.Helper()
	p := filepath.Join(f.backups, "stray-file")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Truncate(p, n); err != nil {
		f.t.Fatal(err)
	}
}

// metas reads every backup metadata file in the store.
func (f *fixture) metas() []map[string]any {
	f.t.Helper()
	var out []map[string]any
	for _, n := range f.backupFiles() {
		if !strings.HasSuffix(n, ".meta.json") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(readFile(f.t, filepath.Join(f.backups, n))), &m); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

type writeOut struct {
	Created   bool     `json:"created"`
	Mode      string   `json:"mode"`
	SHA256    string   `json:"sha256"`
	OldSHA256 string   `json:"old_sha256"`
	UID       *uint32  `json:"uid"`
	GID       *uint32  `json:"gid"`
	Owner     string   `json:"owner"`
	Group     string   `json:"group"`
	Verified  bool     `json:"verified"`
	BackupIDs []string `json:"backup_ids"`
}

// TestStoreCapRefusesAndChangesNothing: a backup that would take the store
// over backups.max_store_bytes refuses the operation with backup_failed,
// saying how full it is, and nothing changes; priv_backup_check reports
// that it would not fit.
func TestStoreCapRefusesAndChangesNothing(t *testing.T) {
	f := newFixture(t, storeCap(minStore))
	conf := filepath.Join(f.write, "app.conf")
	f.junk(minStore - 8)
	before := f.backupFiles()
	r := f.serve("priv_write_file", m{"path": conf, "content_b64": b64("key: new\n")})
	if r.OK || r.Error == nil || r.Error.Code != "backup_failed" || !strings.Contains(r.Error.Message, "backup store is full") ||
		!strings.Contains(r.Error.Message, fmt.Sprint(minStore)) || !strings.Contains(r.Error.Message, "nothing was changed") {
		t.Fatalf("write into a full store: %+v", r.Error)
	}
	if readFile(t, conf) != "key: value\n" || !slices.Equal(f.backupFiles(), before) {
		t.Fatalf("a refused write changed something: %q, store %v", readFile(t, conf), f.backupFiles())
	}
	// Copy and move over a file are refused the same way.
	src := filepath.Join(f.write, "src.conf")
	writeTestFile(t, src, "source\n")
	for _, op := range []string{"priv_copy", "priv_move"} {
		r = f.serve(op, m{"source": src, "destination": conf, "overwrite": true, "expected_destination_sha256": shaHex("key: value\n")})
		if r.OK || r.Error == nil || r.Error.Code != "backup_failed" || !strings.Contains(r.Error.Message, "backup store is full") {
			t.Fatalf("%s into a full store: %+v", op, r.Error)
		}
	}
	if readFile(t, conf) != "key: value\n" || readFile(t, src) != "source\n" || !slices.Equal(f.backupFiles(), before) {
		t.Fatal("a refused copy or move changed something")
	}
	var c struct {
		Written       bool  `json:"written"`
		Bytes         int64 `json:"bytes"`
		Fits          bool  `json:"fits"`
		StoreBytes    int64 `json:"store_bytes"`
		MaxStoreBytes int64 `json:"max_store_bytes"`
	}
	f.ok("priv_backup_check", m{"path": conf}, &c)
	if !c.Written || c.Fits || c.Bytes != int64(len("key: value\n")) || c.StoreBytes < minStore-8 || c.MaxStoreBytes != minStore {
		t.Fatalf("backup check %+v", c)
	}
	// With room, the same write goes through.
	if err := os.Remove(filepath.Join(f.backups, "stray-file")); err != nil {
		t.Fatal(err)
	}
	var w writeOut
	f.ok("priv_write_file", m{"path": conf, "content_b64": b64("key: new\n")}, &w)
	if len(w.BackupIDs) != 1 {
		t.Fatalf("write with room: %+v", w)
	}
}

// TestStoreCapCountsRetention: the check counts the store as it will be
// after this backup's own retention pruning, so a file rewritten again and
// again at backups.keep versions never trips the cap.
func TestStoreCapCountsRetention(t *testing.T) {
	f := newFixture(t, storeCap(minStore), keep(2))
	p := filepath.Join(f.write, "big.conf")
	const size = 60000
	writeTestFile(t, p, strings.Repeat("a", size))
	// Room for two backups of the file (with their metadata), not three.
	f.junk(minStore - 2*(size+4096))
	for i := range 10 {
		var w writeOut
		f.ok("priv_write_file", m{"path": p, "content_b64": b64(strings.Repeat(string(rune('b'+i)), size))}, &w)
		if len(w.BackupIDs) != 1 {
			t.Fatalf("rewrite %d: %+v", i, w)
		}
	}
	if n := len(f.metas()); n != 2 {
		t.Fatalf("%d backups kept, want 2", n)
	}
}

// TestStoreFailsClosed: a store whose total cannot be computed (more names
// than the helper reads, or metadata that does not decode) refuses every
// backup, and the operation changes nothing.
func TestStoreFailsClosed(t *testing.T) {
	t.Run("unreadable metadata", func(t *testing.T) {
		f := newFixture(t)
		writeTestFile(t, filepath.Join(f.backups, "20261001T000000Z-0123456789abcdef.meta.json"), "{not json")
		f.fail("priv_write_file", m{"path": filepath.Join(f.write, "app.conf"), "content_b64": b64("x\n")}, "backup_failed")
		f.fail("priv_backup_check", m{"path": filepath.Join(f.write, "app.conf")}, "backup_failed")
		if readFile(t, filepath.Join(f.write, "app.conf")) != "key: value\n" {
			t.Fatal("changed")
		}
	})
	t.Run("too many names", func(t *testing.T) {
		f := newFixture(t)
		for i := range 20001 {
			if err := os.WriteFile(filepath.Join(f.backups, fmt.Sprintf("stray-%05d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		f.fail("priv_write_file", m{"path": filepath.Join(f.write, "app.conf"), "content_b64": b64("x\n")}, "backup_failed")
		if readFile(t, filepath.Join(f.write, "app.conf")) != "key: value\n" {
			t.Fatal("changed")
		}
	})
	t.Run("writes without a backup are not affected", func(t *testing.T) {
		f := newFixture(t)
		writeTestFile(t, filepath.Join(f.backups, "20261001T000000Z-0123456789abcdef.meta.json"), "{not json")
		f.ok("priv_write_file", m{"path": filepath.Join(f.write, "new.conf"), "content_b64": b64("x\n"), "expect_absent": true}, nil)
	})
}

// TestPruneAfterCommit: retention runs only once the operation succeeded,
// and never removes the backup the request just created.
func TestPruneAfterCommit(t *testing.T) {
	t.Run("a failed write keeps the older version", func(t *testing.T) {
		f := newFixture(t, keep(1))
		p := filepath.Join(f.write, "app.conf")
		var w writeOut
		f.ok("priv_write_file", m{"path": p, "content_b64": b64("two\n")}, &w)
		older := w.BackupIDs[0]
		// The next write backs up "two\n", then fails before its commit.
		f.opts.InjectReadBackFault = func(b []byte) []byte { return append(b, 'x') }
		f.fail("priv_write_file", m{"path": p, "content_b64": b64("three\n")}, "verify_failed")
		f.opts.InjectReadBackFault = nil
		ids := map[string]bool{}
		for _, mt := range f.metas() {
			ids[mt["id"].(string)] = true
		}
		if !ids[older] || len(ids) != 2 {
			t.Fatalf("after a failed write the store holds %v; the older backup %s must be kept", ids, older)
		}
	})
	t.Run("the backup just created is never pruned", func(t *testing.T) {
		f := newFixture(t, keep(1))
		p := filepath.Join(f.write, "app.conf")
		f.ok("priv_write_file", m{"path": p, "content_b64": b64("two\n")}, nil)
		// The next backup's clock is earlier, so it sorts as the older one.
		f.opts.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
		var w writeOut
		f.ok("priv_write_file", m{"path": p, "content_b64": b64("three\n")}, &w)
		ms := f.metas()
		if len(ms) != 1 || ms[0]["id"] != w.BackupIDs[0] {
			t.Fatalf("store %v; want only the backup just created, %v", ms, w.BackupIDs)
		}
	})
}

// TestBackupBoundToPrecondition: the backup holds exactly the content the
// request's precondition named, and its metadata records that hash
// (preview_sha256); a file changed between fsx's hash and the backup is
// refused with backup_failed and nothing changes.
func TestBackupBoundToPrecondition(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	want := shaHex("key: value\n")
	var w writeOut
	f.ok("priv_write_file", m{"path": p, "content_b64": b64("two\n"), "expected_sha256": want}, &w)
	ms := f.metas()
	if len(ms) != 1 || ms[0]["sha256"] != want || ms[0]["preview_sha256"] != want || w.OldSHA256 != want {
		t.Fatalf("metadata %v, result %+v", ms, w)
	}
	f.opts.InjectBeforeBackup = func() { writeTestFile(t, p, "changed under us\n") }
	f.fail("priv_write_file", m{"path": p, "content_b64": b64("three\n"), "expected_sha256": shaHex("two\n")}, "backup_failed")
	f.opts.InjectBeforeBackup = nil
	if readFile(t, p) != "changed under us\n" || len(f.metas()) != 1 {
		t.Fatalf("content %q, %d backups", readFile(t, p), len(f.metas()))
	}
}

// TestPrivCopyMoveExpectedDestination (P-9) through the request handling.
func TestPrivCopyMoveExpectedDestination(t *testing.T) {
	for _, op := range []string{"priv_copy", "priv_move"} {
		t.Run(op, func(t *testing.T) {
			f := newFixture(t)
			src, dst := filepath.Join(f.write, "src.conf"), filepath.Join(f.write, "app.conf")
			writeTestFile(t, src, "source\n")
			old := shaHex("key: value\n")
			f.fail(op, m{"source": src, "destination": dst, "expected_destination_sha256": old}, "bad_request")
			f.fail(op, m{"source": src, "destination": dst, "overwrite": true, "expected_destination_sha256": "XYZ"}, "bad_request")
			f.fail(op, m{"source": src, "destination": dst, "overwrite": true, "expected_destination_sha256": shaHex("other")}, "exists")
			f.fail(op, m{"source": src, "destination": filepath.Join(f.write, "gone.conf"), "overwrite": true, "expected_destination_sha256": old}, "not_found")
			if readFile(t, dst) != "key: value\n" || readFile(t, src) != "source\n" || len(f.metas()) != 0 {
				t.Fatal("a refused operation changed something")
			}
			r := f.ok(op, m{"source": src, "destination": dst, "overwrite": true, "expected_destination_sha256": old}, nil)
			var d struct {
				BackupIDs []string `json:"backup_ids"`
			}
			if err := json.Unmarshal(r.Data, &d); err != nil {
				t.Fatal(err)
			}
			ms := f.metas()
			if readFile(t, dst) != "source\n" || len(d.BackupIDs) != 1 || len(ms) != 1 || ms[0]["sha256"] != old || ms[0]["preview_sha256"] != old {
				t.Fatalf("result %s, metadata %v", r.Data, ms)
			}
			if a := f.lastAudit(); strings.Contains(a, old) || !strings.Contains(a, d.BackupIDs[0]) {
				t.Fatalf("audit line %s", a)
			}
		})
	}
}

// TestPrivBackupCheck (P-11): what an overwrite of a path would back up.
func TestPrivBackupCheck(t *testing.T) {
	f := newFixture(t)
	type check struct {
		Written       bool  `json:"written"`
		Bytes         int64 `json:"bytes"`
		Fits          bool  `json:"fits"`
		StoreBytes    int64 `json:"store_bytes"`
		MaxStoreBytes int64 `json:"max_store_bytes"`
	}
	var c check
	f.ok("priv_backup_check", m{"path": filepath.Join(f.write, "app.conf")}, &c)
	if !c.Written || !c.Fits || c.Bytes != 11 || c.MaxStoreBytes != 1<<30 {
		t.Fatalf("existing file %+v", c)
	}
	c = check{}
	f.ok("priv_backup_check", m{"path": filepath.Join(f.write, "none.conf")}, &c)
	if c.Written || !c.Fits {
		t.Fatalf("absent %+v", c)
	}
	f.fail("priv_backup_check", m{"path": filepath.Join(f.read, "hello.txt")}, "path_denied")
	f.fail("priv_backup_check", m{"path": filepath.Join(f.read, "secrets", "token")}, "path_denied")
	f.fail("priv_backup_check", m{"path": "relative"}, "bad_request")
	f.fail("priv_backup_check", m{"path": f.write, "extra": true}, "bad_request")
	if a := f.lastAudit(); !strings.Contains(a, `"op":"priv_backup_check"`) {
		t.Fatalf("audit %s", a)
	}
	// At ceiling read (a read op), and nothing is created.
	before := f.backupFiles()
	out, _ := f.serveRaw(strings.Replace(request("priv_backup_check", m{"path": filepath.Join(f.write, "app.conf")}), `"ceiling":"destructive"`, `"ceiling":"read"`, 1))
	if !strings.Contains(out, `"ok":true`) || !slices.Equal(before, f.backupFiles()) {
		t.Fatalf("at ceiling read: %s", out)
	}
	k := newFixture(t, keep(0))
	c = check{}
	k.ok("priv_backup_check", m{"path": filepath.Join(k.write, "app.conf")}, &c)
	if c.Written || !c.Fits {
		t.Fatalf("backups disabled %+v", c)
	}
}

// TestPrivResultsReportOwner (P-12): write, copy and mkdir results carry the
// new inode's uid and gid, and their names when they are on the owners
// lists; the mode is the one set.
func TestPrivResultsReportOwner(t *testing.T) {
	f := newFixture(t)
	var w writeOut
	f.ok("priv_write_file", m{"path": filepath.Join(f.write, "owned.conf"), "content_b64": b64("x\n"), "owner": "tester", "group": "tester", "mode": "0600"}, &w)
	if w.UID == nil || *w.UID != f.uid || w.GID == nil || *w.GID != f.gid || w.Owner != "tester" || w.Group != "tester" || w.Mode != "0600" {
		t.Fatalf("write %+v", w)
	}
	w = writeOut{}
	f.ok("priv_copy", m{"source": filepath.Join(f.write, "owned.conf"), "destination": filepath.Join(f.write, "owned-copy.conf")}, &w)
	if w.UID == nil || *w.UID != f.uid || w.Owner != "tester" {
		t.Fatalf("copy %+v", w)
	}
	var d struct {
		Mode  string  `json:"mode"`
		UID   *uint32 `json:"uid"`
		GID   *uint32 `json:"gid"`
		Owner string  `json:"owner"`
		Group string  `json:"group"`
	}
	f.ok("priv_mkdir", m{"path": filepath.Join(f.write, "owned.d"), "owner": "tester"}, &d)
	if d.UID == nil || *d.UID != f.uid || d.GID == nil || *d.GID != f.gid || d.Owner != "tester" || d.Mode != "0750" {
		t.Fatalf("mkdir %+v", d)
	}
}

// TestPrivReplaceCommitWindow: the destination of an overwrite bound to its
// content is replaced by another file after every check the helper makes,
// immediately before the commit; it is never lost.
func TestPrivReplaceCommitWindow(t *testing.T) {
	f := newFixture(t)
	old := "approved old\n"
	cases := []struct {
		op   string
		args func(dst string, i int) m
		pre  func(i int)
	}{
		{"priv_write_file", func(dst string, _ int) m {
			return m{"path": dst, "content_b64": b64("approved new\n"), "expected_sha256": shaHex(old)}
		}, nil},
		{"priv_copy", func(dst string, _ int) m {
			return m{"source": filepath.Join(f.write, "src.conf"), "destination": dst, "overwrite": true, "expected_destination_sha256": shaHex(old)}
		}, func(int) { writeTestFile(t, filepath.Join(f.write, "src.conf"), "approved new\n") }},
		{"priv_move", func(dst string, i int) m {
			return m{"source": fmt.Sprintf("%s/src.%d", f.write, i), "destination": dst, "overwrite": true, "expected_destination_sha256": shaHex(old)}
		}, func(i int) { writeTestFile(t, fmt.Sprintf("%s/src.%d", f.write, i), "approved new\n") }},
	}
	for _, c := range cases {
		for i := range helperWindowRuns {
			dst := filepath.Join(f.write, fmt.Sprintf("%s-win-%d", c.op, i))
			writeTestFile(t, dst, old)
			if c.pre != nil {
				c.pre(i)
			}
			racer := fmt.Sprintf("racer %d\n", i)
			f.opts.InjectBeforeCommit = func() {
				writeTestFile(t, dst+".racer", racer)
				if err := os.Rename(dst+".racer", dst); err != nil {
					t.Error(err)
				}
			}
			f.fail(c.op, c.args(dst, i), "exists")
			f.opts.InjectBeforeCommit = nil
			if got := readFile(t, dst); got != racer {
				t.Fatalf("%s run %d: the racing file was replaced: %q", c.op, i, got)
			}
		}
		t.Logf("%s: the destination replaced before the commit in %d runs: exists every time, the racing file kept", c.op, helperWindowRuns)
	}
}

// TestProductionOptionsHaveNoTestHooks: the production constructor sets no
// test-only hook.
func TestProductionOptionsHaveNoTestHooks(t *testing.T) {
	o := ops.ProductionOptions("v", "/etc/shell-mcp/privileged.yaml")
	if o.InjectReadBackFault != nil || o.InjectBeforeCommit != nil || o.InjectNoReplaceFault != nil || o.InjectMetadataReadBackFault != nil ||
		o.InjectBeforeBackup != nil || o.InjectExchangeFault != nil || o.PkgLockRetry != 0 {
		t.Fatalf("production options carry a test hook: %+v", o)
	}
}
