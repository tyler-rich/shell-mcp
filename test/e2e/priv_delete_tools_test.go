//go:build e2e && linux

package e2e

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The privileged delete tools end to end (S4c-4): the real shell-mcp (admin
// profile, web approval with a simulated human), the real gate and the real
// helper in its core unit, with a tmpfs mounted inside the write root
// (setup.sh) and a device node made by the test (it runs as root on the
// runner VM). Every file is invented.

const privDeleteDir = "/etc/example-app/e2e-priv-delete"

var previewHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func privDeleteFixture(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(privDeleteDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(privDeleteDir, 0o755); err != nil { //nolint:gosec // G301: a fixture directory on a root-only path
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(privDeleteDir) })
}

func TestPrivDeleteToolsPreview(t *testing.T) {
	srv, _ := privWriteServer(t)
	privDeleteFixture(t)
	t.Run("success", func(t *testing.T) {
		tree := privDeleteDir + "/tree"
		paths := metaTreeAt(t, tree)
		since := time.Now()
		args := map[string]any{"path": tree, "recursive": true}
		d := okDataAs(t, srv.callTool(t, "shell_priv_preview_delete", args), "e2e-ssh")
		b, _ := d["backup"].(map[string]any)
		sha, _ := d["preview_sha256"].(string)
		if d["entries"] != 4.0 || d["bytes"] != 4.0 || d["type"] != "dir" || b["written"] != true || b["kind"] != "tree" || !previewHashRE.MatchString(sha) {
			t.Fatalf("preview %v", d)
		}
		if again := okDataAs(t, srv.callTool(t, "shell_priv_preview_delete", args), "e2e-ssh"); again["preview_sha256"] != sha {
			t.Fatal("an unchanged tree previewed with another hash")
		}
		stillThere(t, paths...)
		findJournal(t, "shell-mcp-privd", since, `"op":"priv_delete_preview"`, `"ceiling":"read"`, `"outcome":"ok"`, `"path":"`+tree+`"`)
	})
	t.Run("refusals", func(t *testing.T) {
		devDir := privDeleteDir + "/dev"
		if err := os.Mkdir(devDir, 0o755); err != nil { //nolint:gosec // G301: a fixture directory
			t.Fatal(err)
		}
		if err := unix.Mknod(devDir+"/null", unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3))); err != nil { //nolint:gosec // G115: a small device number
			t.Fatal(err)
		}
		tree := privDeleteDir + "/nonempty"
		paths := metaTreeAt(t, tree)
		for _, c := range []struct {
			path      string
			recursive bool
			code, msg string
		}{
			{"/etc/example-app", true, "path_denied", "root"},
			{"/etc/example-other/secret.txt", false, "path_denied", "outside"},
			{"/etc/example-app/e2e-mounted/point", true, "path_denied", "mount"},
			{"/etc/example-app/e2e-mounted", true, "path_denied", "mount"},
			{devDir + "/null", false, "path_denied", "device node"},
			{devDir, true, "path_denied", "device node"},
			{tree, false, "bad_request", "recursive"},
		} {
			refusal(t, srv.callTool(t, "shell_priv_preview_delete", map[string]any{"path": c.path, "recursive": c.recursive}), c.code, c.msg)
			refusal(t, srv.callTool(t, "shell_priv_delete_path", map[string]any{"path": c.path, "recursive": c.recursive}), c.code, c.msg)
			wantGate(t, svcShell, "priv_delete", map[string]any{"path": c.path, "recursive": c.recursive,
				"expected_preview_sha256": strings.Repeat("0", 64)}, c.code)
		}
		stillThere(t, paths...)
		stillThere(t, devDir+"/null", "/etc/example-app/e2e-mounted/point/inside.txt", "/etc/example-other/secret.txt")
	})
}

func TestPrivDeleteToolsApproval(t *testing.T) {
	srv, h := privWriteServer(t)
	privDeleteFixture(t)
	t.Run("approved, backed up, deleted once, restorable", func(t *testing.T) {
		tree := privDeleteDir + "/approved"
		paths := metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "recursive": true}
		sha, _ := okDataAs(t, srv.callTool(t, "shell_priv_preview_delete", args), "e2e-ssh")["preview_sha256"].(string)
		since := time.Now()
		id := pendingID(t, srv.callTool(t, "shell_priv_delete_path", args))
		stillThere(t, paths...)
		if n := helperLines(t, since, "priv_delete", tree); n != 0 {
			t.Fatalf("%d helper delete lines before approval", n)
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_delete_path", withApproval(args, id)), "e2e-ssh")
		ids, _ := d["backup_ids"].([]any)
		if d["deleted"] != true || d["entries"] != 4.0 || len(ids) != 1 {
			t.Fatalf("data %v", d)
		}
		for _, p := range paths {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("%s still exists (%v)", p, err)
			}
		}
		bid, _ := ids[0].(string)
		if bm := backupMeta(t, bid); bm["kind"] != "tree" || bm["entries"] != 3.0 || bm["preview_sha256"] != sha || bm["op"] != "priv_delete" {
			t.Fatalf("backup metadata %v", bm)
		}
		j := findJournal(t, "shell-mcp-privd", since, `"op":"priv_delete"`, `"removed_total":4`, `"backup_ids":["`+bid+`"]`)
		if !strings.Contains(j.Message, `"`+tree+`/sub/b.conf"`) || strings.Contains(j.Message, sha) {
			t.Fatalf("journal line %s", j.Message)
		}
		refusal(t, srv.callTool(t, "shell_priv_delete_path", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := helperLines(t, since, "priv_delete", tree); n != 1 {
			t.Fatalf("%d helper delete lines, want 1", n)
		}
		// The backup restores the tree as it was.
		mustGateRestore(t, bid, nil)
		if readFile(t, tree+"/a.conf") != "a\n" || readFile(t, tree+"/sub/b.conf") != "b\n" {
			t.Fatal("the tree was not restored from its backup")
		}
		if m, _, _, _ := statOwner(t, tree+"/sub/b.conf"); m.Perm() != 0o600 {
			t.Fatalf("b.conf restored as %v", m)
		}
	})

	t.Run("a newcomer after approval is approval_invalid, nothing deleted", func(t *testing.T) {
		tree := privDeleteDir + "/newcomer"
		paths := metaTreeAt(t, tree)
		args := map[string]any{"path": tree, "recursive": true}
		since := time.Now()
		id := pendingID(t, srv.callTool(t, "shell_priv_delete_path", args))
		srv.decide(t, h, id, "approve")
		rootFile(t, tree+"/sub/new.conf", "new\n", 0o644)
		refusal(t, srv.callTool(t, "shell_priv_delete_path", withApproval(args, id)), "approval_invalid", "changed since approval")
		stillThere(t, append(paths, tree+"/sub/new.conf")...)
		time.Sleep(time.Second)
		if n := helperLines(t, since, "priv_delete", tree); n != 0 {
			t.Fatalf("%d helper delete lines after a refused re-call", n)
		}
	})

	t.Run("a refused preview requests no approval", func(t *testing.T) {
		env := srv.callTool(t, "shell_priv_delete_path", map[string]any{"path": "/etc/example-app/e2e-mounted/point", "recursive": true})
		refusal(t, env, "path_denied", "mount")
		if env["approval"] != nil {
			t.Fatalf("an approval was requested: %v", env)
		}
	})
}
