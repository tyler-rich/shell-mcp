//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The helper's bound chown and chmod (handoff docs/handoff/S4C-PRIVILEGED.md
// S4c-3: P-2b, P-3, P-4, D4, N-1, Q8): priv_chown_preview and
// priv_chmod_preview, priv_chown and priv_chmod requiring the preview's
// hash, recursion, the chain rule and the bounded audit, through the
// helper's request handling. Every layout is invented.

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type metaPreview struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Entries int    `json:"entries"`
	Changes int    `json:"changes"`
	First   []struct {
		Path     string `json:"path"`
		Type     string `json:"type"`
		UID      uint32 `json:"uid"`
		GID      uint32 `json:"gid"`
		Owner    string `json:"owner"`
		Group    string `json:"group"`
		Mode     string `json:"mode"`
		NewUID   uint32 `json:"new_uid"`
		NewGID   uint32 `json:"new_gid"`
		NewOwner string `json:"new_owner"`
		NewGroup string `json:"new_group"`
		NewMode  string `json:"new_mode"`
	} `json:"first"`
	Truncated     bool   `json:"truncated"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

func clone(a m) m {
	out := m{}
	for k, v := range a {
		out[k] = v
	}
	return out
}

// bound previews op's change (op + "_preview") and sends op with the
// preview's hash.
func (f *fixture) bound(op string, args m, into any) metaPreview {
	f.t.Helper()
	var pv metaPreview
	f.ok(op+"_preview", args, &pv)
	a := clone(args)
	a["expected_preview_sha256"] = pv.PreviewSHA256
	f.ok(op, a, into)
	return pv
}

type auditMeta struct {
	Changed []struct {
		Path    string `json:"path"`
		OldMode string `json:"old_mode"`
		OldUID  uint32 `json:"old_uid"`
		OldGID  uint32 `json:"old_gid"`
	} `json:"changed"`
	ChangedTotal     int            `json:"changed_total"`
	ChangedTruncated bool           `json:"changed_truncated"`
	Args             map[string]any `json:"args"`
	Outcome          string         `json:"outcome"`
}

func (f *fixture) lastAuditMeta() (a auditMeta, obj string) {
	f.t.Helper()
	line := f.lastAudit()
	_, obj, _ = strings.Cut(line, ">")
	if err := json.Unmarshal([]byte(obj), &a); err != nil {
		f.t.Fatalf("audit line %q: %v", line, err)
	}
	return a, obj
}

// metaTree makes dir/a.conf (0640) and dir/sub/b.conf (0600); the
// directories are 0755: 4 entries.
func metaTree(t *testing.T, dir string) {
	t.Helper()
	gatetest.Mkdir(t, filepath.Join(dir, "sub"), 0o755)
	gatetest.WriteFile(t, filepath.Join(dir, "a.conf"), "a\n", 0o640)
	gatetest.WriteFile(t, filepath.Join(dir, "sub", "b.conf"), "b\n", 0o600)
}

func modeOfPath(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestPrivMetaPreviews(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tree := filepath.Join(f.write, "tree")
	metaTree(t, tree)
	var pv metaPreview
	f.ok("priv_chmod_preview", m{"path": tree, "mode": "0700", "recursive": true}, &pv)
	if pv.Path != tree || pv.Type != "dir" || pv.Entries != 4 || pv.Changes != 4 || len(pv.First) != 4 || pv.Truncated ||
		pv.PolicySHA256 != f.opts.ExpectedSHA256 || !hashRE.MatchString(pv.PreviewSHA256) {
		t.Fatalf("chmod preview %+v", pv)
	}
	e := pv.First[0]
	if e.Path != tree || e.Type != "dir" || e.Owner != "tester" || e.Group != "tester" || e.UID != f.uid || e.Mode != "0755" ||
		e.NewMode != "0700" || e.NewUID != f.uid || e.NewOwner != "tester" {
		t.Fatalf("first entry %+v", e)
	}
	f.ok("priv_chown_preview", m{"path": tree, "owner": "tester", "group": "tester", "recursive": true}, &pv)
	if pv.Entries != 4 || pv.Changes != 0 || pv.First[1].NewGroup != "tester" || pv.First[1].NewMode != pv.First[1].Mode {
		t.Fatalf("chown preview %+v", pv)
	}
	// The previews are read-tier, and refuse what the operation would.
	for _, op := range []string{
		`"op":"priv_chmod_preview","args":{"path":"` + tree + `","mode":"0700"}`,
		`"op":"priv_chown_preview","args":{"path":"` + tree + `","owner":"tester"}`,
	} {
		out, _ := f.serveRaw(`{"v":1,"id":"` + reqID + `","ceiling":"read",` + op + `,"timeout_ms":5000}` + "\n")
		if !strings.Contains(out, `"ok":true`) {
			t.Fatalf("at ceiling read: %s", out)
		}
	}
	f.fail("priv_chown_preview", m{"path": tree, "owner": "example-app"}, "policy_denied")
	f.fail("priv_chown_preview", m{"path": tree, "group": "nobody"}, "policy_denied")
	f.fail("priv_chown_preview", m{"path": tree}, "bad_request")
	f.fail("priv_chmod_preview", m{"path": tree, "mode": "0777"}, "policy_denied")
	f.fail("priv_chmod_preview", m{"path": tree}, "bad_request")
	f.fail("priv_chmod_preview", m{"path": tree, "mode": "0700", "expected_preview_sha256": strings.Repeat("0", 64)}, "bad_request")
	f.fail("priv_chmod_preview", m{"path": f.write, "mode": "0700"}, "path_denied")
	f.fail("priv_chmod_preview", m{"path": filepath.Join(f.read, "hello.txt"), "mode": "0600"}, "path_denied")
}

func TestPrivMetaBindsThePreview(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf") // 0640
	zero := strings.Repeat("0", 64)
	for _, c := range []struct {
		op   string
		args m
	}{
		{"priv_chmod", m{"path": p, "mode": "0600"}},
		{"priv_chown", m{"path": p, "group": "tester"}},
	} {
		f.fail(c.op, c.args, "bad_request") // no hash
		a := clone(c.args)
		a["expected_preview_sha256"] = "XYZ"
		f.fail(c.op, a, "bad_request")
		a["expected_preview_sha256"] = zero
		f.fail(c.op, a, "exists")
		if r := f.serve(c.op, a); !strings.Contains(r.Error.Message, "nothing was changed") {
			t.Fatalf("%s with another hash: %+v", c.op, r.Error)
		}
	}
	if modeOfPath(t, p) != 0o640 {
		t.Fatal("a refused chmod changed the file")
	}
	// Changed after the preview: exists, and the change is kept.
	var pv metaPreview
	f.ok("priv_chmod_preview", m{"path": p, "mode": "0600"}, &pv)
	if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // G302: a change made after the preview
		t.Fatal(err)
	}
	f.fail("priv_chmod", m{"path": p, "mode": "0600", "expected_preview_sha256": pv.PreviewSHA256}, "exists")
	if modeOfPath(t, p) != 0o644 {
		t.Fatal("the change made after the preview was overwritten")
	}
	var res struct {
		Path    string `json:"path"`
		OldMode string `json:"old_mode"`
		Mode    string `json:"mode"`
	}
	f.bound("priv_chmod", m{"path": p, "mode": "0600"}, &res)
	if res.Path != p || res.OldMode != "0644" || res.Mode != "0600" || modeOfPath(t, p) != 0o600 {
		t.Fatalf("result %+v, mode %04o", res, modeOfPath(t, p))
	}
	var cres struct {
		Path   string `json:"path"`
		OldUID uint32 `json:"old_uid"`
		OldGID uint32 `json:"old_gid"`
		UID    uint32 `json:"uid"`
		GID    uint32 `json:"gid"`
	}
	f.bound("priv_chown", m{"path": p, "owner": "tester"}, &cres)
	if cres.Path != p || cres.UID != f.uid || cres.OldUID != f.uid || cres.GID != f.gid {
		t.Fatalf("chown result %+v", cres)
	}
	// The privileged policy is in the hash: an edit changes it.
	f.ok("priv_chmod_preview", m{"path": p, "mode": "0640"}, &pv)
	y := readFile(t, f.policyPath)
	gatetest.WriteFile(t, f.policyPath, strings.Replace(y, "keep: 3", "keep: 4", 1), 0o600)
	f.rehash()
	var pv2 metaPreview
	f.ok("priv_chmod_preview", m{"path": p, "mode": "0640"}, &pv2)
	if pv2.PreviewSHA256 == pv.PreviewSHA256 || pv2.PolicySHA256 == pv.PolicySHA256 {
		t.Fatal("a privileged policy edit did not change the preview's hash")
	}
	f.fail("priv_chmod", m{"path": p, "mode": "0640", "expected_preview_sha256": pv.PreviewSHA256}, "exists")
}

func TestPrivMetaRecursive(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tree := filepath.Join(f.write, "tree")
	metaTree(t, tree)
	pv := f.bound("priv_chmod", m{"path": tree, "mode": "0700", "recursive": true}, nil)
	for _, p := range []string{tree, tree + "/a.conf", tree + "/sub", tree + "/sub/b.conf"} {
		if modeOfPath(t, p) != 0o700 {
			t.Fatalf("%s is %04o", p, modeOfPath(t, p))
		}
	}
	a, obj := f.lastAuditMeta()
	if len(a.Changed) != 4 || a.ChangedTotal != 4 || a.ChangedTruncated || a.Args["recursive"] != true || pv.Changes != 4 {
		t.Fatalf("audit %s", obj)
	}
	old := map[string]string{tree: "0755", tree + "/a.conf": "0640", tree + "/sub": "0755", tree + "/sub/b.conf": "0600"}
	for _, c := range a.Changed {
		if old[c.Path] != c.OldMode || c.OldUID != f.uid || c.OldGID != f.gid {
			t.Fatalf("changed entry %+v", c)
		}
	}
	if strings.Contains(obj, pv.PreviewSHA256) {
		t.Fatal("the audit line carries the preview hash")
	}
	// Non-recursive: the directory alone.
	f.bound("priv_chmod", m{"path": tree, "mode": "0750"}, nil)
	if modeOfPath(t, tree) != 0o750 || modeOfPath(t, tree+"/a.conf") != 0o700 {
		t.Fatal("a non-recursive chmod reached the tree's entries")
	}
	// Entries already as asked are not changed, and not recorded.
	f.bound("priv_chown", m{"path": tree, "group": "tester", "recursive": true}, nil)
	if a, obj := f.lastAuditMeta(); len(a.Changed) != 0 || a.ChangedTotal != 0 {
		t.Fatalf("chown to the current group recorded %s", obj)
	}
}

// otherGroup is a supplementary group of the test process (not its
// primary one): the only group an unprivileged test can give a file.
func otherGroup(t *testing.T) uint32 {
	t.Helper()
	gs, err := os.Getgroups()
	if err == nil {
		for _, g := range gs {
			if g != os.Getgid() && g >= 0 {
				return uint32(g) //nolint:gosec // G115: a gid fits
			}
		}
	}
	t.Skip("the test process has no supplementary group to chown to (root's chown is covered by e2e-host)")
	return 0
}

func TestPrivMetaChownChanges(t *testing.T) {
	t.Parallel()
	g := otherGroup(t)
	f := newFixture(t, replace("groups: [tester, root]", "groups: [tester, root, staff]"), withStaff(g))
	tree := filepath.Join(f.write, "tree")
	metaTree(t, tree)
	f.bound("priv_chown", m{"path": tree, "group": "staff", "recursive": true}, nil)
	for _, p := range []string{tree, tree + "/a.conf", tree + "/sub", tree + "/sub/b.conf"} {
		if mustStat(t, p).Gid != g {
			t.Fatalf("%s gid %d", p, mustStat(t, p).Gid)
		}
	}
	a, obj := f.lastAuditMeta()
	if len(a.Changed) != 4 || a.Changed[0].OldGID != f.gid {
		t.Fatalf("audit %s", obj)
	}
	// Read back through the descriptor: a mismatch is verify_failed.
	f.opts.InjectMetadataReadBackFault = func(mm fsx.Meta) fsx.Meta { mm.GID++; return mm }
	var pv metaPreview
	f.ok("priv_chown_preview", m{"path": tree, "group": "tester", "recursive": true}, &pv)
	f.fail("priv_chown", m{"path": tree, "group": "tester", "recursive": true, "expected_preview_sha256": pv.PreviewSHA256}, "verify_failed")
	if a, obj := f.lastAuditMeta(); len(a.Changed) != 1 || a.ChangedTotal != 1 {
		t.Fatalf("a failed read-back's entry is not recorded: %s", obj)
	}
}

// TestPrivMetaAuditBounded (Q8): the line lists at most 100 changed entries
// and at most 32 KiB of them, with the total and a truncation flag.
func TestPrivMetaAuditBounded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, replace("max_delete_entries: 20", "max_delete_entries: 1000"))
	many := filepath.Join(f.write, "many")
	for i := range 150 {
		gatetest.WriteFile(t, fmt.Sprintf("%s/f%03d", many, i), "x", 0o600)
	}
	pv := f.bound("priv_chmod", m{"path": many, "mode": "0750", "recursive": true}, nil)
	a, _ := f.lastAuditMeta()
	if pv.Changes < 150 || len(a.Changed) != 100 || a.ChangedTotal != pv.Changes || !a.ChangedTruncated {
		t.Fatalf("150 files: %d listed, total %d, truncated %v", len(a.Changed), a.ChangedTotal, a.ChangedTruncated)
	}
	long := filepath.Join(f.write, strings.Repeat("d", 200))
	for i := range 80 {
		gatetest.WriteFile(t, fmt.Sprintf("%s/%s%02d", long, strings.Repeat("n", 200), i), "x", 0o600)
	}
	pv = f.bound("priv_chmod", m{"path": long, "mode": "0750", "recursive": true}, nil)
	a, _ = f.lastAuditMeta()
	listed, _ := json.Marshal(a.Changed)
	if pv.Changes < 80 || len(a.Changed) >= pv.Changes || len(listed) > 32<<10 || a.ChangedTotal != pv.Changes || !a.ChangedTruncated {
		t.Fatalf("long names: %d listed in %d bytes, total %d, truncated %v", len(a.Changed), len(listed), a.ChangedTotal, a.ChangedTruncated)
	}
}

// TestPrivMetaMovedInRefused (N-1): a file another account moved into the
// write root (here through a world-writable directory, which an
// unprivileged test can simulate) is never changed, alone or inside a
// walk, and keeps its mode when it is moved out again.
func TestPrivMetaMovedInRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := filepath.Join(f.write, "drop")
	gatetest.Mkdir(t, drop, 0o755)
	if err := os.Chmod(drop, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	elsewhere := filepath.Join(f.d, "incoming") // in no root
	gatetest.Mkdir(t, elsewhere, 0o755)
	secret := filepath.Join(elsewhere, "secret")
	gatetest.WriteFile(t, secret, "SECRET\n", 0o600)
	moved := filepath.Join(drop, "secret")
	if err := os.Rename(secret, moved); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		op   string
		args m
	}{
		{"priv_chmod", m{"path": moved, "mode": "0644"}},
		{"priv_chmod", m{"path": drop, "mode": "0755", "recursive": true}},
		{"priv_chown", m{"path": moved, "owner": "tester"}},
		{"priv_chown", m{"path": drop, "group": "tester", "recursive": true}},
	} {
		r := f.serve(c.op+"_preview", c.args)
		if r.OK || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, drop) {
			t.Fatalf("%s preview %v: %+v", c.op, c.args, r.Error)
		}
		a := clone(c.args)
		a["expected_preview_sha256"] = strings.Repeat("0", 64)
		f.fail(c.op, a, "path_denied")
	}
	if err := os.Rename(moved, secret); err != nil {
		t.Fatal(err)
	}
	if modeOfPath(t, secret) != 0o600 {
		t.Fatalf("the moved-in file was changed: %04o", modeOfPath(t, secret))
	}
}

// TestPrivMetaHardLinkInTree (F-2 inside a walk): a tree holding a file
// with another name outside the roots is refused at the preview and at the
// operation, and that file is unchanged.
func TestPrivMetaHardLinkInTree(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tree := filepath.Join(f.write, "tree")
	metaTree(t, tree)
	outside := filepath.Join(f.d, "outside-linked.conf")
	gatetest.WriteFile(t, outside, "outside\n", 0o644)
	if err := os.Link(outside, filepath.Join(tree, "sub", "linked.conf")); err != nil {
		t.Fatal(err)
	}
	before := mustStat(t, outside)
	r := f.serve("priv_chmod_preview", m{"path": tree, "mode": "0600", "recursive": true})
	if r.OK || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, "2 links") {
		t.Fatalf("preview: %+v", r.Error)
	}
	f.fail("priv_chmod", m{"path": tree, "mode": "0600", "recursive": true, "expected_preview_sha256": strings.Repeat("0", 64)}, "path_denied")
	f.fail("priv_chown_preview", m{"path": tree, "owner": "tester", "recursive": true}, "path_denied")
	after := mustStat(t, outside)
	if modeOfPath(t, outside) != 0o644 || after.Ctim != before.Ctim || modeOfPath(t, tree+"/a.conf") != 0o640 {
		t.Fatal("something changed")
	}
}
