//go:build linux

package ops_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The helper's delete (handoff docs/handoff/S4C-PRIVILEGED.md S4c-4: P-2a,
// P-3, D10; PRIVILEGED §6): priv_delete_preview, priv_delete requiring the
// preview's hash, the backup from the plan within the store's cap, the
// fail-safe backup rule, the bounded audit of what was removed, and the
// windows between the preview, the backup and the last unlink, through the
// helper's request handling. Every layout is invented.

type delPreview struct {
	Path      string   `json:"path"`
	Type      string   `json:"type"`
	Entries   int      `json:"entries"`
	Bytes     int64    `json:"bytes"`
	First     []string `json:"first"`
	Truncated bool     `json:"truncated"`
	Backup    struct {
		Written bool   `json:"written"`
		Kind    string `json:"kind"`
		Bytes   int64  `json:"bytes"`
	} `json:"backup"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type delOut struct {
	Path      string   `json:"path"`
	Type      string   `json:"type"`
	Entries   int      `json:"entries"`
	Bytes     int64    `json:"bytes"`
	First     []string `json:"first"`
	Deleted   bool     `json:"deleted"`
	BackupIDs []string `json:"backup_ids"`
}

func (f *fixture) previewDelete(p string, recursive bool) delPreview {
	f.t.Helper()
	var pv delPreview
	f.ok("priv_delete_preview", m{"path": p, "recursive": recursive}, &pv)
	return pv
}

// deleteBound previews p and deletes it with the preview's hash.
func (f *fixture) deleteBound(p string, recursive bool) (delPreview, delOut) {
	f.t.Helper()
	pv := f.previewDelete(p, recursive)
	var out delOut
	f.ok("priv_delete", m{"path": p, "recursive": recursive, "expected_preview_sha256": pv.PreviewSHA256}, &out)
	return pv, out
}

// delTree makes dir with 7 entries (itself included) and 6 bytes:
// a.txt (0640), b/ (0750), b/c.txt (0600), b/d/ (0700), b/d/e.txt (0644),
// f/ (0755).
func delTree(t *testing.T, dir string) []string {
	t.Helper()
	gatetest.Mkdir(t, dir, 0o755)
	gatetest.Mkdir(t, filepath.Join(dir, "b", "d"), 0o700)
	if err := os.Chmod(filepath.Join(dir, "b"), 0o750); err != nil { //nolint:gosec // G302: a fixture directory mode
		t.Fatal(err)
	}
	gatetest.Mkdir(t, filepath.Join(dir, "f"), 0o755)
	gatetest.WriteFile(t, filepath.Join(dir, "a.txt"), "aaa", 0o640)
	gatetest.WriteFile(t, filepath.Join(dir, "b", "c.txt"), "cc", 0o600)
	gatetest.WriteFile(t, filepath.Join(dir, "b", "d", "e.txt"), "e", 0o644)
	return []string{dir, dir + "/a.txt", dir + "/b", dir + "/b/c.txt", dir + "/b/d", dir + "/b/d/e.txt", dir + "/f"}
}

func present(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func allPresent(t testing.TB, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if !present(p) {
			t.Fatalf("%s was removed", p)
		}
	}
}

type auditDelete struct {
	Args             map[string]any `json:"args"`
	BackupIDs        []string       `json:"backup_ids"`
	Discarded        []string       `json:"backup_ids_discarded"`
	Removed          []string       `json:"removed"`
	RemovedTotal     int            `json:"removed_total"`
	RemovedTruncated bool           `json:"removed_truncated"`
	SetAside         string         `json:"set_aside"`
	Outcome          string         `json:"outcome"`
}

func (f *fixture) lastAuditDelete() (a auditDelete, line string) {
	f.t.Helper()
	line = f.lastAudit()
	_, obj, _ := strings.Cut(line, ">")
	if err := json.Unmarshal([]byte(obj), &a); err != nil {
		f.t.Fatalf("audit line %q: %v", line, err)
	}
	return a, line
}

func TestPrivDeletePreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := filepath.Join(f.write, "tree")
	paths := delTree(t, dir)
	pv := f.previewDelete(dir, true)
	if pv.Path != dir || pv.Type != "dir" || pv.Entries != 7 || pv.Bytes != 6 || len(pv.First) != 7 || pv.First[0] != dir || pv.Truncated {
		t.Fatalf("preview %+v", pv)
	}
	if !pv.Backup.Written || pv.Backup.Kind != "tree" || pv.Backup.Bytes < 6 || pv.PolicySHA256 != f.opts.ExpectedSHA256 || !hashRE.MatchString(pv.PreviewSHA256) {
		t.Fatalf("preview backup %+v policy %q hash %q", pv.Backup, pv.PolicySHA256, pv.PreviewSHA256)
	}
	if again := f.previewDelete(dir, true); again.PreviewSHA256 != pv.PreviewSHA256 || again.Backup != pv.Backup {
		t.Fatalf("an unchanged tree previewed differently: %+v %+v", again, pv)
	}
	allPresent(t, paths...)
	if len(f.backupFiles()) != 0 {
		t.Fatalf("a preview wrote to the store: %v", f.backupFiles())
	}
	// A read-tier op: served at ceiling read.
	if r := f.serveAt("read", "priv_delete_preview", m{"path": dir, "recursive": true}); !r.OK {
		t.Fatalf("at ceiling read: %+v", r.Error)
	}
	// It takes no hash.
	f.fail("priv_delete_preview", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "bad_request")
	// A file is backed up as a file, of its size.
	fp := f.previewDelete(filepath.Join(f.write, "app.conf"), false)
	if fp.Type != "file" || fp.Entries != 1 || fp.Bytes != 11 || !fp.Backup.Written || fp.Backup.Kind != "file" || fp.Backup.Bytes != 11 {
		t.Fatalf("file preview %+v", fp)
	}
	// Without backups, none is written.
	g := newFixture(t, keep(0))
	if np := g.previewDelete(filepath.Join(g.write, "app.conf"), false); np.Backup.Written || np.Backup.Bytes != 0 {
		t.Fatalf("keep 0: %+v", np.Backup)
	}
}

// TestPrivDeleteBindsThePreview: priv_delete requires the preview's hash
// and deletes nothing unless the tree and the privileged policy are what
// the preview saw.
func TestPrivDeleteBindsThePreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := filepath.Join(f.write, "tree")
	paths := delTree(t, dir)
	pv := f.previewDelete(dir, true)
	for _, h := range []any{nil, "", "abc", strings.ToUpper(pv.PreviewSHA256), 42} {
		a := m{"path": dir, "recursive": true}
		if h != nil {
			a["expected_preview_sha256"] = h
		}
		f.fail("priv_delete", a, "bad_request")
	}
	f.fail("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": strings.Repeat("0", 64)}, "exists")
	// The hash of the other recursive flag, or another path, is another hash.
	gatetest.Mkdir(t, filepath.Join(f.write, "empty"), 0o755)
	ep := f.previewDelete(filepath.Join(f.write, "empty"), false)
	f.fail("priv_delete", m{"path": filepath.Join(f.write, "empty"), "recursive": true, "expected_preview_sha256": ep.PreviewSHA256}, "exists")
	f.fail("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": ep.PreviewSHA256}, "exists")
	allPresent(t, paths...)
	allPresent(t, filepath.Join(f.write, "empty"))
	// A newcomer after the preview: exists, nothing removed, kept.
	newcomer := filepath.Join(dir, "b", "newcomer")
	gatetest.WriteFile(t, newcomer, "new", 0o600)
	f.fail("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	allPresent(t, append(paths, newcomer)...)
	if len(f.metas()) != 0 {
		t.Fatalf("a refused delete left a backup: %v", f.metas())
	}
	if err := os.Remove(newcomer); err != nil {
		t.Fatal(err)
	}
	// A privileged policy edit changes the hash.
	pv = f.previewDelete(dir, true)
	b, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, f.policyPath, strings.Replace(string(b), "max_output_bytes: 4096", "max_output_bytes: 4097", 1), 0o600)
	f.rehash()
	f.fail("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	allPresent(t, paths...)
	if f.previewDelete(dir, true).PreviewSHA256 == pv.PreviewSHA256 {
		t.Fatal("the privileged policy is not in the preview hash")
	}
	// Bound: deleted, backed up first, recorded with the hash.
	pv, out := f.deleteBound(dir, true)
	if !out.Deleted || out.Path != dir || out.Entries != 7 || out.Bytes != 6 || len(out.BackupIDs) != 1 || present(dir) {
		t.Fatalf("delete %+v", out)
	}
	md := f.metas()
	if len(md) != 1 || md[0]["kind"] != "tree" || md[0]["entries"] != 6.0 || md[0]["preview_sha256"] != pv.PreviewSHA256 || md[0]["path"] != dir ||
		md[0]["op"] != "priv_delete" || md[0]["size"] != float64(pv.Backup.Bytes) {
		t.Fatalf("backup metadata %v (preview backup %+v)", md, pv.Backup)
	}
	a, line := f.lastAuditDelete()
	got := slices.Clone(a.Removed)
	slices.Sort(got)
	want := slices.Clone(paths)
	slices.Sort(want)
	if !slices.Equal(got, want) || a.RemovedTotal != 7 || a.RemovedTruncated || !slices.Equal(a.BackupIDs, out.BackupIDs) || a.Outcome != "ok" {
		t.Fatalf("audit %+v", a)
	}
	if strings.Contains(line, pv.PreviewSHA256) || a.Args["expected_preview_sha256"] != nil || a.Args["recursive"] != true || a.Args["path"] != dir {
		t.Fatalf("the audit line logs the hash or misses the args: %s", line)
	}
}

// denyPrivate adds <write root>/private/** to the policy's deny list.
func denyPrivate() opt {
	return func(f *fixture, s *string) {
		*s = strings.Replace(*s, `deny: ["`, `deny: ["`+f.write+`/private/**", "`, 1)
	}
}

// refusedBoth: the preview and the delete (with any well-formed hash)
// refuse p with code, and nothing changes.
func (f *fixture) refusedBoth(p string, recursive bool, code, msg string, keep ...string) {
	f.t.Helper()
	backups := len(f.metas())
	for _, op := range []string{"priv_delete_preview", "priv_delete"} {
		a := m{"path": p, "recursive": recursive}
		if op == "priv_delete" {
			a["expected_preview_sha256"] = strings.Repeat("0", 64)
		}
		r := f.serve(op, a)
		if r.OK || r.Error == nil || r.Error.Code != code || !strings.Contains(r.Error.Message, msg) {
			f.t.Fatalf("%s %s: got ok=%v %+v, want %s (%q)", op, p, r.OK, r.Error, code, msg)
		}
	}
	allPresent(f.t, keep...)
	if len(f.metas()) != backups {
		f.t.Fatalf("%s: a refusal left a backup", p)
	}
}

// refusedPreview: the preview refuses p with code (so no approval is
// requested); without a preview's hash the delete refuses too, and nothing
// changes. (fsx's tests show the delete itself refusing these.)
func (f *fixture) refusedPreview(p string, recursive bool, code, msg string, keep ...string) {
	f.t.Helper()
	backups := len(f.metas())
	r := f.serve("priv_delete_preview", m{"path": p, "recursive": recursive})
	if r.OK || r.Error == nil || r.Error.Code != code || !strings.Contains(r.Error.Message, msg) {
		f.t.Fatalf("priv_delete_preview %s: got ok=%v %+v, want %s (%q)", p, r.OK, r.Error, code, msg)
	}
	f.fail("priv_delete", m{"path": p, "recursive": recursive, "expected_preview_sha256": strings.Repeat("0", 64)}, "exists")
	allPresent(f.t, keep...)
	if len(f.metas()) != backups {
		f.t.Fatalf("%s: a refusal left a backup", p)
	}
}

// TestPrivDeleteRefusals: everything the gate's delete refuses, the
// helper's refuses, at the preview (so no approval is requested) and at the
// operation, changing nothing; plus what cannot be backed up while backups
// are on.
func TestPrivDeleteRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t, denyPrivate())
	conf := filepath.Join(f.write, "app.conf")
	f.refusedBoth(f.write, true, "path_denied", "root", conf)
	f.refusedBoth(filepath.Join(f.read, "hello.txt"), false, "path_denied", "", filepath.Join(f.read, "hello.txt"))
	gatetest.WriteFile(t, filepath.Join(f.write, "private", "key.txt"), "k", 0o600)
	f.refusedBoth(filepath.Join(f.write, "private", "key.txt"), false, "path_denied", "denied", filepath.Join(f.write, "private", "key.txt"))
	// A tree holding the deny list's entry.
	f.refusedBoth(f.write+"/private", true, "path_denied", "denied", filepath.Join(f.write, "private", "key.txt"))
	tree := filepath.Join(f.write, "holder")
	gatetest.Mkdir(t, tree, 0o755)
	if err := os.Symlink(conf, filepath.Join(tree, "final")); err != nil {
		t.Fatal(err)
	}
	f.refusedBoth(filepath.Join(tree, "final"), false, "path_denied", "symlink", conf, filepath.Join(tree, "final"))
	// A stranded set-aside entry, and a tree holding one.
	stranded := filepath.Join(f.write, "strand", ".shell-mcp-delete-0123456789abcdef0123456789abcdef")
	gatetest.WriteFile(t, stranded, "set aside", 0o600)
	f.refusedBoth(stranded, false, "path_denied", "set aside", stranded)
	f.refusedBoth(filepath.Dir(stranded), true, "path_denied", "set aside", stranded)
	// Non-empty without recursive.
	dir := filepath.Join(f.write, "tree")
	paths := delTree(t, dir)
	f.refusedBoth(dir, false, "bad_request", "recursive", paths...)
	// Above max_delete_entries (20).
	big := filepath.Join(f.write, "big")
	for i := range 25 {
		gatetest.WriteFile(t, filepath.Join(big, fmt.Sprintf("f%02d", i)), "x", 0o600)
	}
	f.refusedBoth(big, true, "too_large", "max_delete_entries", filepath.Join(big, "f00"), filepath.Join(big, "f24"))
	// With backups on, a tree holding a symlink, and a FIFO, cannot be
	// backed up, so they are not deleted.
	if err := os.Symlink(conf, filepath.Join(dir, "b", "link")); err != nil {
		t.Fatal(err)
	}
	f.refusedPreview(dir, true, "backup_failed", "symlink", append(paths, filepath.Join(dir, "b", "link"))...)
	fifo := filepath.Join(f.write, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	f.refusedPreview(fifo, false, "backup_failed", "backed up", fifo)
	if readFile(t, conf) != "key: value\n" {
		t.Fatal("the symlink's target was changed")
	}
	// Without backups, a tree holding a symlink is deleted (the link as a
	// link, never its target).
	g := newFixture(t, keep(0))
	gdir := filepath.Join(g.write, "tree")
	delTree(t, gdir)
	if err := os.Symlink(filepath.Join(g.write, "app.conf"), filepath.Join(gdir, "b", "link")); err != nil {
		t.Fatal(err)
	}
	if _, out := g.deleteBound(gdir, true); !out.Deleted || len(out.BackupIDs) != 0 || present(gdir) || readFile(t, filepath.Join(g.write, "app.conf")) != "key: value\n" {
		t.Fatalf("keep 0: %+v", out)
	}
}

// TestPrivDeleteHardLinks: a hard-linked file is deleted by its name under
// the write root, and only that name: its other name, outside the roots,
// keeps the inode and its content (maintainer decision, S4c-4: an unlink
// changes no inode, so F-2's refusal does not apply, as in the gate).
func TestPrivDeleteHardLinks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	outside := filepath.Join(f.d, "outside-link.txt")
	gatetest.WriteFile(t, outside, "outside\n", 0o600)
	in := filepath.Join(f.write, "linked.txt")
	if err := os.Link(outside, in); err != nil {
		t.Fatal(err)
	}
	if _, out := f.deleteBound(in, false); !out.Deleted || present(in) || readFile(t, outside) != "outside\n" {
		t.Fatalf("delete of a hard link %+v", out)
	}
}

// TestPrivDeleteBackupRestorable: every removed entry is in the backup, and
// the backup restores the tree (and a file) as it was.
func TestPrivDeleteBackupRestorable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := filepath.Join(f.write, "tree")
	delTree(t, dir)
	_, out := f.deleteBound(dir, true)
	if len(out.BackupIDs) != 1 || present(dir) {
		t.Fatalf("delete %+v", out)
	}
	f.restoreBound(out.BackupIDs[0])
	for p, want := range map[string]string{"a.txt": "aaa", "b/c.txt": "cc", "b/d/e.txt": "e"} {
		if got := readFile(t, filepath.Join(dir, p)); got != want {
			t.Fatalf("%s restored as %q", p, got)
		}
	}
	for p, want := range map[string]os.FileMode{"": 0o755, "a.txt": 0o640, "b": 0o750, "b/c.txt": 0o600, "b/d": 0o700, "b/d/e.txt": 0o644, "f": 0o755} {
		if got := modeOf(t, filepath.Join(dir, p)); got != want {
			t.Fatalf("%s restored with mode %04o, want %04o", p, got, want)
		}
	}
	p := filepath.Join(f.write, "app.conf")
	_, out = f.deleteBound(p, false)
	if len(out.BackupIDs) != 1 || present(p) {
		t.Fatalf("delete %+v", out)
	}
	if md := f.meta(out.BackupIDs[0]); md.Kind != "file" || md.SHA256 != sum("key: value\n") {
		t.Fatalf("file backup %+v", md)
	}
	f.restoreBound(out.BackupIDs[0])
	if readFile(t, p) != "key: value\n" {
		t.Fatal("file not restored")
	}
}

// TestPrivDeleteStoreCap: a delete whose backup would not fit the store's
// cap, or would exceed 64 MiB, is refused at the preview (no approval is
// requested) and at the operation, and changes nothing.
func TestPrivDeleteStoreCap(t *testing.T) {
	t.Parallel()
	const capacity = minStore + 1<<20
	f := newFixture(t, storeCap(capacity))
	dir := filepath.Join(f.write, "tree")
	paths := delTree(t, dir)
	pv := f.previewDelete(dir, true) // fits now
	f.junk(capacity - 2000)
	before := f.storeUse()
	r := f.serve("priv_delete_preview", m{"path": dir, "recursive": true})
	if r.OK || r.Error.Code != "backup_failed" || !strings.Contains(r.Error.Message, "full") {
		t.Fatalf("preview over the cap: %+v", r.Error)
	}
	r = f.serve("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256})
	if r.OK || r.Error.Code != "backup_failed" || !strings.Contains(r.Error.Message, "full") {
		t.Fatalf("delete over the cap: %+v", r.Error)
	}
	allPresent(t, paths...)
	if f.storeUse() != before || len(f.metas()) != 0 {
		t.Fatalf("the store changed: %d → %d, %v", before, f.storeUse(), f.metas())
	}
	// Over the 64 MiB backup limit (a sparse file costs no disk).
	g := newFixture(t)
	huge := filepath.Join(g.write, "huge", "sparse.bin")
	gatetest.WriteFile(t, huge, "", 0o600)
	if err := os.Truncate(huge, 65<<20); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p         string
		recursive bool
	}{{huge, false}, {filepath.Dir(huge), true}} {
		r := g.serve("priv_delete_preview", m{"path": c.p, "recursive": c.recursive})
		if r.OK || r.Error.Code != "backup_failed" || !strings.Contains(r.Error.Message, "64 MiB") {
			t.Fatalf("%s: %+v", c.p, r.Error)
		}
	}
	allPresent(t, huge)
}

// replaceWith puts content at p as a new inode, staged in staging.
func replaceWith(t *testing.T, staging, p, content string) {
	t.Helper()
	tmp := filepath.Join(staging, fmt.Sprintf("racer-%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
}

// TestPrivDeleteFailSafeBackups: a delete that stops before removing
// anything discards its backup (provably unchanged); one that removed
// entries keeps it, also when the removal was never reported as a commit.
func TestPrivDeleteFailSafeBackups(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name     string
		victim   string // replaced before it is checked under its name
		unreport bool
		kept     bool
	}{
		{"nothing removed", "a.txt", false, false},
		{"nothing removed (unreported)", "a.txt", true, false},
		{"partly removed", "b/c.txt", false, true},
		{"partly removed (unreported)", "b/c.txt", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			dir := filepath.Join(f.write, "tree")
			delTree(t, dir)
			staging := filepath.Join(f.write, "staging")
			gatetest.Mkdir(t, staging, 0o755)
			pv := f.previewDelete(dir, true)
			victim := filepath.Join(dir, c.victim)
			f.opts.DisableCommitReport = c.unreport
			f.opts.InjectDeleteStep = func(s fsx.DeleteStep, p string) {
				if s == fsx.DeleteStepBeforeEntry && p == victim {
					replaceWith(t, staging, victim, "racer")
				}
			}
			f.fail("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "exists")
			f.opts.InjectDeleteStep, f.opts.DisableCommitReport = nil, false
			if readFile(t, victim) != "racer" {
				t.Fatal("the racer's file was changed")
			}
			a, _ := f.lastAuditDelete()
			switch {
			case c.kept && (len(f.metas()) != 1 || len(a.BackupIDs) != 1 || len(a.Discarded) != 0 || !slices.Equal(a.Removed, []string{dir + "/a.txt"})):
				t.Fatalf("a delete that removed entries did not keep its backup: store %v audit %+v", f.metas(), a)
			case !c.kept && (len(f.metas()) != 0 || len(a.BackupIDs) != 0 || len(a.Discarded) != 1 || len(a.Removed) != 0):
				t.Fatalf("a delete that removed nothing kept its backup: store %v audit %+v", f.metas(), a)
			}
		})
	}
}

// TestPrivDeleteSetAside: an entry set aside that cannot be put back is
// named in the refusal and in the audit line's set_aside, and is never
// deleted; the backup is kept (the tree changed).
func TestPrivDeleteSetAside(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := filepath.Join(f.write, "tree")
	delTree(t, dir)
	staging := filepath.Join(f.write, "staging")
	gatetest.Mkdir(t, staging, 0o755)
	pv := f.previewDelete(dir, true)
	victim := filepath.Join(dir, "b", "c.txt")
	f.opts.InjectDeleteStep = func(s fsx.DeleteStep, p string) {
		if p != victim {
			return
		}
		switch s {
		case fsx.DeleteStepBeforeRename:
			replaceWith(t, staging, victim, "newcomer A")
		case fsx.DeleteStepAfterRename:
			replaceWith(t, staging, victim, "newcomer B")
		default:
		}
	}
	r := f.serve("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256})
	f.opts.InjectDeleteStep = nil
	a, _ := f.lastAuditDelete()
	if r.OK || r.Error.Code != "exists" || a.SetAside == "" || !strings.Contains(r.Error.Message, a.SetAside) ||
		!strings.HasPrefix(filepath.Base(a.SetAside), ".shell-mcp-delete-") || readFile(t, a.SetAside) != "newcomer A" {
		t.Fatalf("refusal %+v audit %+v", r.Error, a)
	}
	if len(f.metas()) != 1 || len(a.BackupIDs) != 1 {
		t.Fatalf("the backup of a delete that left an entry set aside was not kept: %v", f.metas())
	}
	aside := a.SetAside
	f.refusedBoth(dir, true, "path_denied", "set aside", aside, victim)
}

// TestPrivDeleteAuditBounded: the audit line lists at most 100 removed
// entries, or 32 KiB of them, with the total and removed_truncated.
func TestPrivDeleteAuditBounded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keep(0), replace("max_delete_entries: 20", "max_delete_entries: 200"))
	many := filepath.Join(f.write, "many")
	for i := range 150 {
		gatetest.WriteFile(t, filepath.Join(many, fmt.Sprintf("f%03d", i)), "x", 0o600)
	}
	f.deleteBound(many, true)
	a, _ := f.lastAuditDelete()
	if len(a.Removed) != 100 || a.RemovedTotal != 151 || !a.RemovedTruncated {
		t.Fatalf("150 files: %d listed, total %d, truncated %v", len(a.Removed), a.RemovedTotal, a.RemovedTruncated)
	}
	long := filepath.Join(f.write, "long")
	sub := filepath.Join(long, strings.Repeat("d", 200))
	name := strings.Repeat("n", 240)
	for i := range 120 {
		gatetest.WriteFile(t, filepath.Join(sub, fmt.Sprintf("%s%03d", name, i)), "x", 0o600)
	}
	f.deleteBound(long, true)
	a, _ = f.lastAuditDelete()
	b, _ := json.Marshal(a.Removed)
	if len(a.Removed) >= 100 || len(b) > 32<<10 || a.RemovedTotal != 122 || !a.RemovedTruncated {
		t.Fatalf("long names: %d listed (%d bytes), total %d, truncated %v", len(a.Removed), len(b), a.RemovedTotal, a.RemovedTruncated)
	}
}

const delWindowRuns = 200

// TestPrivDeleteWindows: through the helper, with backups on, the tree
// changes at every point between the preview and the last unlink: before
// the request (the recompute differs), after the recompute matched, before
// a file is read for the backup, after the backup was written, and at each
// step of each entry's removal. Whatever the racer put there survives, in
// every run, and the backup is kept exactly when entries were removed. Each
// run starts with an empty backup store, as in TestPrivRestoreWindows: the
// 1600 runs would otherwise leave about 1100 backups behind, which every
// later request and every count of the store reads again.
func TestPrivDeleteWindows(t *testing.T) {
	t.Parallel()
	f := newFixture(t, replace("max_delete_entries: 20", "max_delete_entries: 200"))
	staging := filepath.Join(f.write, "staging")
	gatetest.Mkdir(t, staging, 0o755)
	type point struct {
		name string
		step fsx.DeleteStep // 0: before the request
		each bool           // at the victim's path, not once
	}
	points := []point{
		{"before the request", 0, false},
		{"after the recompute", fsx.DeleteStepAfterCompare, false},
		{"before a backup read", fsx.DeleteStepBeforeBackupEntry, true},
		{"after the backup", fsx.DeleteStepAfterBackup, false},
		{"before an entry's check", fsx.DeleteStepBeforeEntry, true},
		{"before setting aside", fsx.DeleteStepBeforeRename, true},
		{"after setting aside", fsx.DeleteStepAfterRename, true},
		{"before the unlink", fsx.DeleteStepBeforeUnlink, true},
	}
	outcomes := map[string]map[string]int{}
	n := 0
	for _, pt := range points {
		outcomes[pt.name] = map[string]int{}
		for i := range delWindowRuns {
			n++
			f.clearStore()
			dir := filepath.Join(f.write, fmt.Sprintf("w%d", n))
			paths := delTree(t, dir)
			pv := f.previewDelete(dir, true)
			victim := paths[1+i%(len(paths)-1)]
			if pt.step == fsx.DeleteStepBeforeBackupEntry {
				victim = []string{dir + "/a.txt", dir + "/b/c.txt", dir + "/b/d/e.txt"}[i%3]
			}
			racer := fmt.Sprintf("racer %d", n)
			var planted string
			plant := func() {
				fi, err := os.Lstat(victim)
				switch {
				case err == nil && fi.IsDir():
					planted = victim + "/newcomer"
				case err == nil && i%2 == 0:
					planted = victim // replaced by another inode
				case err == nil:
					planted = filepath.Dir(victim) + "/newcomer"
				default: // set aside: the name is free
					planted = victim
				}
				replaceWith(t, staging, planted, racer)
			}
			if pt.step == 0 {
				plant()
			} else {
				f.opts.InjectDeleteStep = func(s fsx.DeleteStep, p string) {
					if s == pt.step && planted == "" && (!pt.each || p == victim) {
						plant()
					}
				}
			}
			before := len(f.metas())
			r := f.serve("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256})
			f.opts.InjectDeleteStep = nil
			if planted == "" {
				t.Fatalf("%s, run %d: the point was never reached for %s", pt.name, i, victim)
			}
			if got, err := os.ReadFile(planted); err != nil || string(got) != racer { //nolint:gosec // G304: test fixture
				t.Fatalf("%s, run %d: the racer's file %s was removed or changed (%q, %v)", pt.name, i, planted, got, err)
			}
			a, _ := f.lastAuditDelete()
			kept := len(f.metas()) - before
			switch {
			case r.OK:
				outcomes[pt.name]["completed (newcomer under a freed name)"]++
			case r.Error.Code != "exists":
				t.Fatalf("%s, run %d: %+v", pt.name, i, r.Error)
			case strings.Contains(r.Error.Message, "changed since the preview"):
				outcomes[pt.name]["refused at the recompute"]++
			case len(a.Removed) == 0:
				outcomes[pt.name]["stopped, nothing removed"]++
			default:
				outcomes[pt.name]["stopped part-way"]++
			}
			if (len(a.Removed) > 0) != (kept == 1) || kept > 1 {
				t.Fatalf("%s, run %d: %d removed, %d backups kept", pt.name, i, len(a.Removed), kept)
			}
		}
	}
	for _, pt := range points {
		t.Logf("%-24s %d runs: %v", pt.name, delWindowRuns, outcomes[pt.name])
	}
}

// TestPrivDeleteConcurrentRacer: no hook. A goroutine starts after a random
// delay of up to a whole request's measured duration and then, until the
// helper answers, keeps creating files in random directories of the tree
// and replacing random files of the tree by other inodes. Every file it
// managed to create survives, in every run; the outcomes are counted. Each
// run starts with an empty backup store, so that a request takes as long as
// the calibration measured.
func TestPrivDeleteConcurrentRacer(t *testing.T) {
	t.Parallel()
	const runs = 400
	f := newFixture(t, replace("max_delete_entries: 20", "max_delete_entries: 200"))
	staging := filepath.Join(f.write, "staging")
	gatetest.Mkdir(t, staging, 0o755)
	mk := func(dir string) []string {
		var files []string
		for _, s := range []string{"s1", "s2", "s3"} {
			for j := range 4 {
				p := fmt.Sprintf("%s/%s/f%d", dir, s, j)
				gatetest.WriteFile(t, p, "data", 0o600)
				files = append(files, p)
			}
		}
		return files
	}
	var durs []time.Duration
	for i := range 9 {
		cal := filepath.Join(f.write, fmt.Sprintf("calibrate%d", i))
		mk(cal)
		pv := f.previewDelete(cal, true)
		start := time.Now()
		f.ok("priv_delete", m{"path": cal, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, nil)
		durs = append(durs, time.Since(start))
	}
	slices.Sort(durs)
	dur := durs[len(durs)/2]
	counts := map[string]int{}
	planted := 0
	for i := range runs {
		f.clearStore()
		dir := filepath.Join(f.write, fmt.Sprintf("r%d", i))
		files := mk(dir)
		pv := f.previewDelete(dir, true)
		made := map[string]string{}
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			time.Sleep(time.Duration(rand.Int64N(int64(dur)))) //nolint:gosec // G404: test jitter
			for k := 0; ; k++ {
				select {
				case <-done:
					return
				default:
				}
				var p string
				if k%2 == 0 {
					p = fmt.Sprintf("%s/s%d/new-%d", dir, 1+rand.IntN(3), k) //nolint:gosec // G404: test choice
				} else {
					p = files[rand.IntN(len(files))] //nolint:gosec // G404: test choice
				}
				content := fmt.Sprintf("racer %d.%d", i, k)
				tmp := filepath.Join(staging, fmt.Sprintf("racer-%d-%d", i, k))
				if os.WriteFile(tmp, []byte(content), 0o600) != nil {
					return
				}
				if os.Rename(tmp, p) == nil {
					made[p] = content
				} else {
					_ = os.Remove(tmp)
				}
				time.Sleep(time.Duration(rand.Int64N(int64(dur/32) + 1))) //nolint:gosec // G404: test jitter
			}
		})
		before := len(f.metas())
		r := f.serve("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256})
		close(done)
		wg.Wait()
		a, _ := f.lastAuditDelete()
		switch {
		case r.OK:
			counts["completed before the racer changed anything"]++
		case r.Error.Code != "exists":
			t.Fatalf("run %d: %+v", i, r.Error)
		case strings.Contains(r.Error.Message, "changed since the preview"):
			counts["refused at the recompute"]++
		case strings.Contains(r.Error.Message, "backed up"):
			counts["stopped during the backup"]++
		case len(a.Removed) == 0:
			counts["stopped during deletion, nothing removed"]++
		default:
			counts["stopped during deletion, part removed"]++
		}
		if kept := len(f.metas()) - before; (len(a.Removed) > 0) != (kept == 1) {
			t.Fatalf("run %d: %d removed, %d backups kept", i, len(a.Removed), kept)
		}
		for p, content := range made {
			planted++
			if got, err := os.ReadFile(p); err != nil || string(got) != content { //nolint:gosec // G304: test fixture
				t.Fatalf("run %d: the racer's file %s was deleted or changed (%v)", i, p, err)
			}
		}
	}
	t.Logf("concurrent racer through the helper: %d runs (a request takes ~%v); %d racer files, every one survived", runs, dur, planted)
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		t.Logf("| %-46s | %3d |", k, counts[k])
	}
}

// TestPrivDeleteStopAfterSetAsideKeepsBackup: the operation stops right
// after setting an entry aside, without unlinking it or putting it back,
// so no commit is reported. The tree is not as the preview saw it (the
// entry is under its temporary name), so the backup is kept.
func TestPrivDeleteStopAfterSetAsideKeepsBackup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := filepath.Join(f.write, "tree")
	delTree(t, dir)
	pv := f.previewDelete(dir, true)
	victim := filepath.Join(dir, "a.txt") // the first entry the pass handles
	f.opts.InjectStopAfterSetAside = func(p string) error {
		if p == victim {
			return errors.New("stopped after the set-aside")
		}
		return nil
	}
	r := f.serve("priv_delete", m{"path": dir, "recursive": true, "expected_preview_sha256": pv.PreviewSHA256})
	f.opts.InjectStopAfterSetAside = nil
	if r.OK || present(victim) {
		t.Fatalf("result %+v, victim present %v", r.Error, present(victim))
	}
	a, _ := f.lastAuditDelete()
	if len(f.metas()) != 1 || len(a.BackupIDs) != 1 || len(a.Discarded) != 0 || len(a.Removed) != 0 {
		t.Fatalf("a delete that left an entry set aside, unrecorded, discarded its backup: store %v audit %+v", f.metas(), a)
	}
}
