//go:build linux

package ops_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// priv_copy's owner and group (handoff docs/handoff/S4C-PRIVILEGED.md N-19,
// P-15; PRIVILEGED §6): optional, names on owners.users and owners.groups
// exactly as priv_write_file takes them, set on the new inode and reported;
// an explicit owner must pass rule R. The fixture's uid stands for root and
// for tester (gatetest.Trust); another account's write access is a
// world-writable directory. Every layout is invented.

// TestPrivCopyOwner: a copy given an owner and group from the lists lands
// with them, new or over a file, and reports their names; a name on neither
// list is refused before anything is written.
func TestPrivCopyOwner(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := filepath.Join(f.write, "src.bin")
	gatetest.WriteFile(t, src, "binary\n", 0o644)
	for _, c := range []struct {
		dst       string
		overwrite bool
	}{
		{filepath.Join(f.write, "copy.bin"), false},
		{filepath.Join(f.write, "app.conf"), true},
	} {
		var w writeOut
		f.ok("priv_copy", m{"source": src, "destination": c.dst, "overwrite": c.overwrite, "owner": "tester", "group": "tester"}, &w)
		st := mustStat(t, c.dst)
		if w.UID == nil || *w.UID != f.uid || w.GID == nil || *w.GID != f.gid || w.Owner != "tester" || w.Group != "tester" || st.Uid != f.uid || st.Gid != f.gid {
			t.Fatalf("%s: %+v, on disk %d:%d", c.dst, w, st.Uid, st.Gid)
		}
	}
	never := filepath.Join(f.write, "never.bin")
	for _, a := range []m{
		{"source": src, "destination": never, "owner": "example-app"},
		{"source": src, "destination": never, "owner": "nobody"},
		{"source": src, "destination": never, "group": "svc-shell-priv"},
		{"source": src, "destination": never, "owner": "tester", "group": "nobody"},
	} {
		f.fail("priv_copy", a, "policy_denied")
	}
	if present(never) {
		t.Fatal("a refused owner made a file")
	}
}

// TestPrivCopyOwnerRuleR: under a directory another account can write, a
// copy given any owner, root's included, is refused naming the directory,
// before anything is written (no owner passes there).
func TestPrivCopyOwnerRuleR(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	drop := openDrop(t, f)
	src := filepath.Join(f.write, "src.bin")
	gatetest.WriteFile(t, src, "binary\n", 0o644)
	there := filepath.Join(drop, "there.bin")
	gatetest.WriteFile(t, there, "there\n", 0o644)
	fresh := filepath.Join(drop, "fresh.bin")
	for _, a := range []m{
		{"source": src, "destination": fresh, "owner": "tester", "group": "tester"},
		{"source": src, "destination": fresh, "owner": "root", "group": "root"},
		{"source": src, "destination": there, "overwrite": true, "owner": "tester", "group": "tester"},
	} {
		f.failMsg("priv_copy", a, "path_denied", drop)
	}
	if got, err := os.ReadFile(there); present(fresh) || err != nil || string(got) != "there\n" { //nolint:gosec // G304: test fixture
		t.Fatal("a refused copy changed something")
	}
}

// TestPrivCopySetgidGroup: in a closed setgid directory, a copy given a
// group gets it; without one it gets the helper's own. Needs a
// supplementary group (e2e-host covers it as root).
func TestPrivCopySetgidGroup(t *testing.T) {
	t.Parallel()
	g := otherGroup(t)
	f := newFixture(t, replace("groups: [tester, root]", "groups: [tester, root, staff]"), withStaff(g))
	sg := filepath.Join(f.write, "sg")
	gatetest.Mkdir(t, sg, 0o755)
	if err := os.Chown(sg, -1, int(g)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sg, 0o755|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(f.write, "src.bin")
	gatetest.WriteFile(t, src, "binary\n", 0o644)
	var w writeOut
	f.ok("priv_copy", m{"source": src, "destination": filepath.Join(sg, "staff.bin"), "group": "staff"}, &w)
	if st := mustStat(t, filepath.Join(sg, "staff.bin")); st.Gid != g || w.GID == nil || *w.GID != g || w.Group != "staff" {
		t.Fatalf("a copy given group staff (%d): on disk %d, %+v", g, st.Gid, w)
	}
	f.ok("priv_copy", m{"source": src, "destination": filepath.Join(sg, "own.bin")}, nil)
	if st := mustStat(t, filepath.Join(sg, "own.bin")); st.Gid != f.gid {
		t.Fatalf("a copy without a group took gid %d, want the helper's %d", st.Gid, f.gid)
	}
}
