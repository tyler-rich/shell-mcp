//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The privileged write tools end to end (S4c-2): the real shell-mcp (stdio,
// admin profile, web approval with a simulated human, SHELL_MCP_APPROVAL_TIERS
// at its default), the real gate (privileged forwarding on, principal
// e2e-ssh) and the real helper in its core unit. Every file and value is
// invented.

const privWriteDir = "/etc/example-app/e2e-priv-write"

// privWriteServer starts an approval server on the privileged key, with
// operator writes not listed in SHELL_MCP_APPROVAL_TIERS: privileged tools
// are gated anyway (D-006).
func privWriteServer(t *testing.T) (*approvalServer, *human) {
	t.Helper()
	needSSHD(t)
	if err := os.RemoveAll(privWriteDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(privWriteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newHuman(t, manyApprovers)
	file := h.file(t)
	srv := startApprovalServer(t, h, file, freeLoopbackPort(t), "SHELL_MCP_PROFILE=admin", "SHELL_MCP_APPROVAL_TIERS=destructive",
		"SHELL_MCP_SSH_KEY_FILE="+filepath.Join(bin(), "e2e-client-key"))
	t.Cleanup(func() { _ = srv.cs.Close() })
	return srv, h
}

// helperLines counts the helper's journal lines of op naming p for
// requests of c's server.
func helperLines(t *testing.T, c *serverConn, op, p string) int {
	t.Helper()
	return len(c.helper(t, `"op":"`+op+`"`, `"`+p+`"`))
}

func rootFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// backupMeta reads one backup's metadata.
func backupMeta(t *testing.T, id string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(backupDir, id+".meta.json"))), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPrivWriteToolsApproval(t *testing.T) {
	srv, h := privWriteServer(t)
	conn := connOf(t, srv.cs)
	approveRun := func(t *testing.T, tool string, args map[string]any) map[string]any {
		t.Helper()
		id := pendingID(t, srv.callTool(t, tool, args))
		srv.decide(t, h, id, "approve")
		env := srv.callTool(t, tool, withApproval(args, id))
		refusal(t, srv.callTool(t, tool, withApproval(args, id)), "approval_invalid", "")
		return env
	}

	t.Run("write: approved, run once, backed up as previewed", func(t *testing.T) {
		p := privWriteDir + "/app.conf"
		rootFile(t, p, "old: value\n", 0o640)
		args := map[string]any{"path": p, "content": "new: value\n"}
		id := pendingID(t, srv.callTool(t, "shell_priv_write_file", args))
		if n := helperLines(t, conn, "priv_write_file", p); n != 0 {
			t.Fatalf("%d helper write lines before approval", n)
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_write_file", withApproval(args, id)), "e2e-ssh")
		ids, _ := d["backup_ids"].([]any)
		if readFile(t, p) != "new: value\n" || d["old_sha256"] != sha("old: value\n") || d["mode"] != "0640" || d["uid"] != 0.0 || len(ids) != 1 {
			t.Fatalf("write %v", d)
		}
		bid, _ := ids[0].(string)
		if m := backupMeta(t, bid); m["sha256"] != sha("old: value\n") || m["preview_sha256"] != sha("old: value\n") || m["path"] != p {
			t.Fatalf("backup metadata %v", m)
		}
		conn.waitHelper(t, `"op":"priv_write_file"`, `"ceiling":"operator"`, bid)
		refusal(t, srv.callTool(t, "shell_priv_write_file", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := helperLines(t, conn, "priv_write_file", p); n != 1 {
			t.Fatalf("%d helper write lines, want 1", n)
		}
	})

	t.Run("write: a file created after approval is never replaced", func(t *testing.T) {
		p := privWriteDir + "/created-after.conf"
		_ = os.Remove(p)
		args := map[string]any{"path": p, "content": "approved\n"}
		id := pendingID(t, srv.callTool(t, "shell_priv_write_file", args))
		srv.decide(t, h, id, "approve")
		rootFile(t, p, "planted\n", 0o600)
		refusal(t, srv.callTool(t, "shell_priv_write_file", withApproval(args, id)), "approval_invalid", "changed since approval")
		if readFile(t, p) != "planted\n" {
			t.Fatal("the planted file was replaced")
		}
	})

	t.Run("write: an existing file wider than modes.max is narrowed and reported", func(t *testing.T) {
		p := privWriteDir + "/wide.conf"
		rootFile(t, p, "wide\n", 0o775)
		d := okDataAs(t, approveRun(t, "shell_priv_write_file", map[string]any{"path": p, "content": "narrow\n"}), "e2e-ssh")
		if fi, _ := os.Stat(p); d["mode"] != "0755" || fi.Mode().Perm() != 0o755 {
			t.Fatalf("mode %v", d["mode"])
		}
	})

	t.Run("write: owner not allow-listed, outside the write roots, deny list, symlink", func(t *testing.T) {
		p := privWriteDir + "/owner.conf"
		rootFile(t, p, "owner\n", 0o640)
		refusal(t, approveRun(t, "shell_priv_write_file", map[string]any{"path": p, "content": "x\n", "owner": "svc-shell"}), "policy_denied", "owners")
		if readFile(t, p) != "owner\n" {
			t.Fatal("changed")
		}
		for _, c := range []struct{ path, code string }{
			{"/var/log/example-app/new.conf", "path_denied"},
			{"/etc/example-other/new.conf", "path_denied"},
			{"/etc/example-app/secrets/new", "path_denied"},
		} {
			env := srv.callTool(t, "shell_priv_write_file", map[string]any{"path": c.path, "content": "x\n"})
			refusal(t, env, c.code, "")
			if env["approval"] != nil {
				t.Fatalf("%s: an approval was requested", c.path)
			}
		}
		if err := os.Symlink("owner.conf", privWriteDir+"/link.conf"); err != nil {
			t.Fatal(err)
		}
		refusal(t, srv.callTool(t, "shell_priv_write_file", map[string]any{"path": privWriteDir + "/link.conf", "content": "x\n"}), "path_denied", "symlink")
	})

	t.Run("mkdir: approved, root's by default, the owner given", func(t *testing.T) {
		p := privWriteDir + "/made.d"
		d := okDataAs(t, approveRun(t, "shell_priv_make_directory", map[string]any{"path": p}), "e2e-ssh")
		if d["created"] != true || d["uid"] != 0.0 || d["mode"] != "0750" {
			t.Fatalf("mkdir %v", d)
		}
		q := privWriteDir + "/owned.d/sub"
		d = okDataAs(t, approveRun(t, "shell_priv_make_directory", map[string]any{"path": q, "parents": true, "owner": "example-app", "group": "example-app"}), "e2e-ssh")
		st, _ := os.Stat(q)
		if d["owner"] != "example-app" || st.Sys().(*syscall.Stat_t).Uid != 4200004 {
			t.Fatalf("mkdir with owner %v", d)
		}
	})

	t.Run("copy: overwrite bound to the destination", func(t *testing.T) {
		src, dst := privWriteDir+"/copy-src.conf", privWriteDir+"/copy-dst.conf"
		rootFile(t, src, "source\n", 0o600)
		rootFile(t, dst, "destination\n", 0o640)
		args := map[string]any{"source": src, "destination": dst, "overwrite": true}
		id := pendingID(t, srv.callTool(t, "shell_priv_copy_path", args))
		srv.decide(t, h, id, "approve")
		rootFile(t, dst, "changed after approval\n", 0o640)
		refusal(t, srv.callTool(t, "shell_priv_copy_path", withApproval(args, id)), "approval_invalid", "")
		if readFile(t, dst) != "changed after approval\n" {
			t.Fatal("the changed destination was replaced")
		}
		d := okDataAs(t, approveRun(t, "shell_priv_copy_path", args), "e2e-ssh")
		ids, _ := d["backup_ids"].([]any)
		if readFile(t, dst) != "source\n" || len(ids) != 1 || d["old_sha256"] != sha("changed after approval\n") {
			t.Fatalf("copy %v", d)
		}
		if m := backupMeta(t, ids[0].(string)); m["sha256"] != sha("changed after approval\n") || m["preview_sha256"] != m["sha256"] {
			t.Fatalf("backup metadata %v", m)
		}
		big := privWriteDir + "/big-src.conf"
		rootFile(t, big, strings.Repeat("x", 2<<20), 0o600)
		refusal(t, approveRun(t, "shell_priv_copy_path", map[string]any{"source": big, "destination": privWriteDir + "/big-dst.conf"}), "too_large", "")
		if _, err := os.Lstat(privWriteDir + "/big-dst.conf"); err == nil {
			t.Fatal("a refused copy wrote its destination")
		}
	})

	t.Run("move: approved, run once", func(t *testing.T) {
		src, dst := privWriteDir+"/move-src.conf", privWriteDir+"/move-dst.conf"
		rootFile(t, src, "moved\n", 0o600)
		_ = os.Remove(dst)
		d := okDataAs(t, approveRun(t, "shell_priv_move_path", map[string]any{"source": src, "destination": dst}), "e2e-ssh")
		if d["replaced"] != false || readFile(t, dst) != "moved\n" {
			t.Fatalf("move %v", d)
		}
		if _, err := os.Lstat(src); err == nil {
			t.Fatal("the source is still there")
		}
	})

	t.Run("a privileged policy edit after approval invalidates it", func(t *testing.T) {
		p := privWriteDir + "/policy-edit.conf"
		rootFile(t, p, "before\n", 0o640)
		args := map[string]any{"path": p, "content": "after\n"}
		id := pendingID(t, srv.callTool(t, "shell_priv_write_file", args))
		srv.decide(t, h, id, "approve")
		installPolicy(t, "privileged-cap-kill.yaml")
		refusal(t, srv.callTool(t, "shell_priv_write_file", withApproval(args, id)), "approval_invalid", "")
		if readFile(t, p) != "before\n" {
			t.Fatal("changed")
		}
	})
	conn.same(t)
}

// TestPrivWriteStoreCap: under the smallest cap, with the store nearly
// full, a write that would back up a file is refused at its preview: no
// approval is requested and nothing changes.
func TestPrivWriteStoreCap(t *testing.T) {
	srv, _ := privWriteServer(t)
	installPolicy(t, "privileged-small-store.yaml")
	junk := filepath.Join(backupDir, "e2e-stray-file")
	if err := os.WriteFile(junk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(junk) })
	if err := os.Truncate(junk, 64<<20-16); err != nil {
		t.Fatal(err)
	}
	p := privWriteDir + "/cap.conf"
	rootFile(t, p, "kept\n", 0o640)
	env := srv.callTool(t, "shell_priv_write_file", map[string]any{"path": p, "content": "x\n"})
	refusal(t, env, "backup_failed", "backup store is full")
	if env["approval"] != nil || readFile(t, p) != "kept\n" {
		t.Fatalf("store cap: %v", env)
	}
	// A new file needs no backup and is still allowed.
	pendingID(t, srv.callTool(t, "shell_priv_write_file", map[string]any{"path": privWriteDir + "/cap-new.conf", "content": "x\n"}))
}
