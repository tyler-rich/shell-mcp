//go:build e2e && linux

package e2e

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The privileged chown and chmod tools end to end (S4c-3): the real
// shell-mcp (admin profile, web approval with a simulated human), the real
// gate and the real helper in its core unit, and the N-1 and hard-link
// cases with a real second account (example-app). Every file is invented.

const privMetaDir = "/etc/example-app/e2e-priv-meta"

// mustGateMeta previews op's change through the gate (op + "_preview") and
// sends op with the preview's hash.
func mustGateMeta(t *testing.T, op string, args map[string]any) {
	t.Helper()
	var pv struct {
		PreviewSHA256 string `json:"preview_sha256"`
	}
	mustGate(t, op+"_preview", args, &pv)
	a := map[string]any{"expected_preview_sha256": pv.PreviewSHA256}
	for k, v := range args {
		a[k] = v
	}
	mustGate(t, op, a, nil)
}

// asUser runs a fixed command as uid (its own group).
func asUser(t *testing.T, uid uint32, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: fixed test commands
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, uid)}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v as %d: %v\n%s", name, args, uid, err, out)
	}
}

func statOwner(t *testing.T, p string) (mode os.FileMode, uid, gid uint32, ctime syscall.Timespec) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fi.Mode(), st.Uid, st.Gid, st.Ctim
}

// metaTreeAt makes a root-owned tree: dir (0755), dir/a.conf (0640),
// dir/sub (0755), dir/sub/b.conf (0600).
func metaTreeAt(t *testing.T, dir string) []string {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, dir + "/sub"} {
		if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // G301: a fixture directory, as setup.sh makes them
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: a fixture directory
			t.Fatal(err)
		}
	}
	rootFile(t, dir+"/a.conf", "a\n", 0o640)
	rootFile(t, dir+"/sub/b.conf", "b\n", 0o600)
	return []string{dir, dir + "/a.conf", dir + "/sub", dir + "/sub/b.conf"}
}

func TestPrivMetaToolsApproval(t *testing.T) {
	srv, h := privWriteServer(t)
	if err := os.MkdirAll(privMetaDir, 0o755); err != nil { //nolint:gosec // G301: a fixture directory on a root-only path
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privMetaDir) })

	t.Run("chown -R: approved, run once, old values in the journal", func(t *testing.T) {
		tree := privMetaDir + "/handover"
		paths := metaTreeAt(t, tree)
		since := time.Now()
		args := map[string]any{"path": tree, "owner": "example-app", "group": "example-app", "recursive": true}
		id := pendingID(t, srv.callTool(t, "shell_priv_change_owner", args))
		if n := helperLines(t, since, "priv_chown", tree); n != 0 {
			t.Fatalf("%d helper chown lines before approval", n)
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_change_owner", withApproval(args, id)), "e2e-ssh")
		if d["entries"] != 4.0 || d["changed"] != 4.0 || d["uid"] != float64(exampleApp) || d["recursive"] != true {
			t.Fatalf("data %v", d)
		}
		for _, p := range paths {
			if _, uid, gid, _ := statOwner(t, p); uid != exampleApp || gid != exampleApp {
				t.Fatalf("%s is %d:%d", p, uid, gid)
			}
		}
		j := findJournal(t, "shell-mcp-privd", since, `"op":"priv_chown"`, `"recursive":true`, `"changed":[`, `"changed_total":4`)
		if !strings.Contains(j.Message, `"path":"`+tree+`/sub/b.conf"`) || !strings.Contains(j.Message, `"old_uid":0`) || !strings.Contains(j.Message, `"old_mode":"0600"`) {
			t.Fatalf("journal line %s", j.Message)
		}
		refusal(t, srv.callTool(t, "shell_priv_change_owner", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := helperLines(t, since, "priv_chown", tree); n != 1 {
			t.Fatalf("%d helper chown lines, want 1", n)
		}
		// The tree's directories are now example-app's, so example-app could
		// move files in: a recursive change is refused at the preview, and
		// no approval is requested (N-1). The directory itself, on a root
		// path, can still be changed.
		refusal(t, srv.callTool(t, "shell_priv_set_permissions", map[string]any{"path": tree, "mode": "0750", "recursive": true}),
			"path_denied", tree)
		refusal(t, srv.callTool(t, "shell_priv_set_permissions", map[string]any{"path": tree + "/a.conf", "mode": "0600"}), "path_denied", tree)
	})

	t.Run("chmod -R: approved, run once", func(t *testing.T) {
		tree := privMetaDir + "/modes"
		paths := metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "mode": "0750", "recursive": true}
		id := pendingID(t, srv.callTool(t, "shell_priv_set_permissions", args))
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_set_permissions", withApproval(args, id)), "e2e-ssh")
		if d["entries"] != 4.0 || d["changed"] != 4.0 || d["mode"] != "0750" {
			t.Fatalf("data %v", d)
		}
		for _, p := range paths {
			if m, _, _, _ := statOwner(t, p); m.Perm() != 0o750 {
				t.Fatalf("%s is %v", p, m)
			}
		}
		refusal(t, srv.callTool(t, "shell_priv_set_permissions", withApproval(args, id)), "approval_invalid", "")
	})

	t.Run("a tree changed after approval is approval_invalid and unchanged", func(t *testing.T) {
		tree := privMetaDir + "/changed"
		metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "mode": "0700", "recursive": true}
		id := pendingID(t, srv.callTool(t, "shell_priv_set_permissions", args))
		srv.decide(t, h, id, "approve")
		rootFile(t, tree+"/sub/new.conf", "new\n", 0o644)
		refusal(t, srv.callTool(t, "shell_priv_set_permissions", withApproval(args, id)), "approval_invalid", "changed since approval")
		if m, _, _, _ := statOwner(t, tree+"/a.conf"); m.Perm() != 0o640 {
			t.Fatalf("a.conf changed to %v", m)
		}
	})

	t.Run("a hard link to a file outside the roots refuses the whole tree", func(t *testing.T) {
		tree := privMetaDir + "/linked"
		metaTreeAt(t, tree)
		outside := "/etc/example-other/secret.txt" // root:root 0644, setup.sh
		if err := os.Link(outside, tree+"/sub/linked.conf"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(tree + "/sub/linked.conf") })
		m0, u0, g0, c0 := statOwner(t, outside)
		refusal(t, srv.callTool(t, "shell_priv_change_owner", map[string]any{"path": tree, "owner": "example-app", "recursive": true}),
			"path_denied", "2 links")
		wantGate(t, svcShell, "priv_chown", map[string]any{"path": tree, "owner": "example-app", "recursive": true,
			"expected_preview_sha256": strings.Repeat("0", 64)}, "path_denied")
		if m1, u1, g1, c1 := statOwner(t, outside); m1 != m0 || u1 != u0 || g1 != g0 || c1 != c0 {
			t.Fatal("the file outside the roots changed")
		}
	})
}

// TestPrivMetaMovedInRefused (N-1): example-app can write a directory in the
// write root and one outside every root on the same filesystem; it moves a
// root-owned 0600 file in, and the helper refuses to change it (alone or
// inside a walk), through the gate and through the tool; moved out again,
// the file is unchanged.
func TestPrivMetaMovedInRefused(t *testing.T) {
	incoming := "/etc/example-other/e2e-incoming"
	drop := "/etc/example-app/e2e-meta-drop"
	for _, d := range []string{incoming, drop} {
		_ = os.RemoveAll(d)
		if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // G301: a directory example-app writes, as on a real host
			t.Fatal(err)
		}
		if err := os.Chown(d, int(exampleApp), int(exampleApp)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
	}
	secret := incoming + "/secret.conf"
	rootFile(t, secret, "root only\n", 0o600)
	m0, u0, g0, _ := statOwner(t, secret)
	moved := drop + "/secret.conf"
	asUser(t, exampleApp, "/usr/bin/mv", secret, moved)
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		{"priv_chmod", map[string]any{"path": moved, "mode": "0644"}},
		{"priv_chmod", map[string]any{"path": drop, "mode": "0755", "recursive": true}},
		{"priv_chown", map[string]any{"path": moved, "owner": "example-app"}},
		{"priv_chown", map[string]any{"path": drop, "group": "example-app", "recursive": true}},
	} {
		r, _ := gate(t, svcShell, c.op+"_preview", c.args)
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, drop) {
			t.Fatalf("%s preview %v: %s %+v", c.op, c.args, r.code(), r.Error)
		}
		a := map[string]any{"expected_preview_sha256": strings.Repeat("0", 64)}
		for k, v := range c.args {
			a[k] = v
		}
		wantGate(t, svcShell, c.op, a, "path_denied")
	}
	srv, _ := privWriteServer(t)
	refusal(t, srv.callTool(t, "shell_priv_set_permissions", map[string]any{"path": moved, "mode": "0644"}), "path_denied", drop)
	asUser(t, exampleApp, "/usr/bin/mv", moved, secret)
	if m1, u1, g1, _ := statOwner(t, secret); m1 != m0 || u1 != u0 || g1 != g0 || m1.Perm() != 0o600 {
		t.Fatalf("the moved-in file changed: %v %d:%d", m1, u1, g1)
	}
}
