//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// mask0700 is a fixture policy whose modes.max is 0700.
func mask0700() opt { return replace(`max: "0755"`, `max: "0700"`) }

// Every new inode the helper creates lies within modes.max (PRIVILEGED §4,
// §6): a copy takes the source's mode, a write or a copy over a file the
// existing file's, and a restore the recorded one, each with setuid,
// setgid, sticky and world-write removed and masked by modes.max; the
// result reports the mode set.
func TestNewInodesWithinModesMax(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mask0700())
	var w struct {
		Mode string `json:"mode"`
	}
	check := func(what, p, reported string, want os.FileMode) {
		t.Helper()
		if got := modeOf(t, p); got != want || reported != fmt.Sprintf("%04o", uint32(want)) {
			t.Errorf("%s: mode on disk %04o, reported %q; want %04o", what, got, reported, want)
		}
	}

	// A copy of a 0644 source.
	src := filepath.Join(f.read, "hello.txt") // 0644
	dst := filepath.Join(f.write, "copy.txt")
	f.ok("priv_copy", m{"source": src, "destination": dst}, &w)
	check("copy", dst, w.Mode, 0o600)

	// A copy over a 0644 destination.
	over := filepath.Join(f.write, "over.txt")
	gatetest.WriteFile(t, over, "old\n", 0o644)
	f.ok("priv_copy", m{"source": src, "destination": over, "overwrite": true}, &w)
	check("copy over a file", over, w.Mode, 0o600)

	// A write over an existing 0640 file.
	conf := filepath.Join(f.write, "app.conf") // 0640
	f.ok("priv_write_file", m{"path": conf, "content_b64": b64("y\n")}, &w)
	check("write over a file", conf, w.Mode, 0o600)

	// A write over a file with bits outside the mask and group-write.
	wide := filepath.Join(f.write, "wide.conf")
	gatetest.WriteFile(t, wide, "wide\n", 0o664)
	var wb struct {
		Mode      string   `json:"mode"`
		BackupIDs []string `json:"backup_ids"`
	}
	f.ok("priv_write_file", m{"path": wide, "content_b64": b64("narrow\n")}, &wb)
	check("write over a 0664 file", wide, wb.Mode, 0o600)
	if bm := f.meta(wb.BackupIDs[0]); bm.Mode != "0664" {
		t.Fatalf("the backup records mode %s, want the replaced file's 0664", bm.Mode)
	}

	// A restore of that backup: the recorded 0664 is masked.
	f.restoreBound(wb.BackupIDs[0])
	if readFile(t, wide) != "wide\n" || modeOf(t, wide) != 0o600 {
		t.Errorf("restore: content %q mode %04o, want the old content at 0600", readFile(t, wide), modeOf(t, wide))
	}

	// A new directory, with and without parents.
	d := filepath.Join(f.write, "a", "b")
	var md struct {
		Mode string `json:"mode"`
	}
	f.ok("priv_mkdir", m{"path": d, "parents": true}, &md)
	check("mkdir", d, md.Mode, 0o700)
	check("mkdir's parent", filepath.Dir(d), md.Mode, 0o700)
}

// A restored tree's entries are masked too, including a recorded mode the
// file operations would refuse (world-write).
func TestRestoreTreeWithinModesMax(t *testing.T) {
	t.Parallel()
	f := newFixture(t, mask0700())
	tree := filepath.Join(f.write, "tree")
	gatetest.Mkdir(t, tree, 0o755)
	gatetest.Mkdir(t, filepath.Join(tree, "sub"), 0o755)
	gatetest.WriteFile(t, filepath.Join(tree, "a.txt"), "A", 0o644)
	gatetest.WriteFile(t, filepath.Join(tree, "sub", "w.txt"), "W", 0o666)
	_, del := f.deleteBound(tree, true)
	f.restoreBound(del.BackupIDs[0])
	for p, want := range map[string]os.FileMode{
		tree:                                0o700,
		filepath.Join(tree, "sub"):          0o700,
		filepath.Join(tree, "a.txt"):        0o600,
		filepath.Join(tree, "sub", "w.txt"): 0o600,
	} {
		if got := modeOf(t, p); got != want {
			t.Errorf("%s: %04o, want %04o", p, got, want)
		}
	}
	if readFile(t, filepath.Join(tree, "sub", "w.txt")) != "W" {
		t.Fatal("tree not restored")
	}
}

// priv_chmod and priv_chown refuse a non-directory with more than one link:
// its other name can lie outside the write roots. The file behind the link
// keeps its mode, owner and change time. A single-link file and a
// directory are still changed.
func TestChmodChownRefuseHardLinks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	outside := filepath.Join(f.d, "outside-linked.conf") // in no root
	gatetest.WriteFile(t, outside, "outside\n", 0o644)
	link := filepath.Join(f.write, "linked.conf")
	if err := os.Link(outside, link); err != nil {
		t.Fatal(err)
	}
	before := mustStat(t, outside)
	for _, c := range []struct {
		op   string
		args m
	}{
		{"priv_chmod", m{"path": link, "mode": "0600"}},
		{"priv_chown", m{"path": link, "group": "tester"}},
		{"priv_chown", m{"path": link, "owner": "tester"}},
	} {
		r := f.serve(c.op+"_preview", c.args)
		if r.OK || r.Error == nil || r.Error.Code != "path_denied" ||
			!strings.Contains(r.Error.Message, link) || !strings.Contains(r.Error.Message, "2 links") {
			t.Fatalf("%s through a hard link: ok=%v %+v, want path_denied naming the path and 2 links", c.op, r.OK, r.Error)
		}
		a := clone(c.args)
		a["expected_preview_sha256"] = strings.Repeat("0", 64)
		f.fail(c.op, a, "path_denied")
	}
	after := mustStat(t, outside)
	if modeOf(t, outside) != 0o644 || after.Uid != before.Uid || after.Gid != before.Gid || after.Ctim != before.Ctim {
		t.Fatalf("the outside file changed: mode %04o %d:%d ctime %v (was %v)", modeOf(t, outside), after.Uid, after.Gid, after.Ctim, before.Ctim)
	}

	// A single-link file and a directory (whose link count is 2 or more) are changed.
	one := filepath.Join(f.write, "app.conf")
	f.bound("priv_chmod", m{"path": one, "mode": "0600"}, nil)
	f.bound("priv_chown", m{"path": one, "group": "tester"}, nil)
	dir := filepath.Join(f.write, "dir")
	gatetest.Mkdir(t, filepath.Join(dir, "sub"), 0o750)
	if mustStat(t, dir).Nlink < 3 {
		t.Fatalf("directory link count %d", mustStat(t, dir).Nlink)
	}
	f.bound("priv_chmod", m{"path": dir, "mode": "0700"}, nil)
	f.bound("priv_chown", m{"path": dir, "group": "tester"}, nil)
	if modeOf(t, one) != 0o600 || modeOf(t, dir) != 0o700 {
		t.Fatalf("modes %04o %04o", modeOf(t, one), modeOf(t, dir))
	}
}

// After fchmod or fchown the helper re-reads the inode through the same
// descriptor; a mismatch is verify_failed, never a success. An entry
// already as asked is not changed, so nothing is read back for it (a chown
// to the test's own group; TestPrivMetaChownChanges reads back a real one
// where the test has a supplementary group, and e2e-host as root).
func TestChmodChownReadBack(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf")
	f.opts.InjectMetadataReadBackFault = func(m fsx.Meta) fsx.Meta { m.Mode ^= 0o040; return m }
	var pv metaPreview
	f.ok("priv_chmod_preview", m{"path": p, "mode": "0600"}, &pv)
	f.fail("priv_chmod", m{"path": p, "mode": "0600", "expected_preview_sha256": pv.PreviewSHA256}, "verify_failed")
	f.opts.InjectMetadataReadBackFault = func(m fsx.Meta) fsx.Meta { m.GID++; return m }
	f.bound("priv_chown", m{"path": p, "group": "tester"}, nil) // already the test's group: nothing changed
	f.opts.InjectMetadataReadBackFault = nil
	f.bound("priv_chmod", m{"path": p, "mode": "0640"}, nil)
}

// The helper's audit line records the old mode, owner and group of the
// entry chmod or chown changed (handoff Q8), and nothing when it changed
// nothing.
func TestChmodChownAuditOldValues(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := filepath.Join(f.write, "app.conf") // 0640, the test user's
	type change struct {
		Path    string `json:"path"`
		OldMode string `json:"old_mode"`
		OldUID  uint32 `json:"old_uid"`
		OldGID  uint32 `json:"old_gid"`
	}
	changed := func() []change {
		t.Helper()
		line := f.lastAudit()
		var l struct {
			Changed []change `json:"changed"`
		}
		_, obj, _ := strings.Cut(line, ">") // "<priority>{...}"
		if err := json.Unmarshal([]byte(obj), &l); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		return l.Changed
	}
	want := []change{{Path: p, OldMode: "0640", OldUID: f.uid, OldGID: f.gid}}
	f.bound("priv_chmod", m{"path": p, "mode": "0600"}, nil)
	if got := changed(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("chmod changed %+v, want %+v", got, want)
	}
	// A chown to the group the file already has changes nothing, and records
	// nothing (TestPrivMetaChownChanges records a real one).
	f.bound("priv_chown", m{"path": p, "group": "tester"}, nil)
	if got := changed(); len(got) != 0 {
		t.Fatalf("a chown that changed nothing recorded %+v", got)
	}
	f.fail("priv_chmod", m{"path": p, "mode": "0777"}, "policy_denied")
	if got := changed(); len(got) != 0 {
		t.Fatalf("a refused chmod recorded %+v", got)
	}
}
