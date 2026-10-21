//go:build e2e && linux

package e2e

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The privileged restore tool and the moved-in rule end to end (S4c-5): the
// real shell-mcp (admin profile, web approval with a simulated human), the
// real gate and the real helper in its core unit, and example-app moving
// files and directories as itself. Every file is invented.

const privRestoreDir = "/etc/example-app/e2e-priv-restore"

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// freshDir makes dir (owner uid:uid unless 0, mode) and removes it after
// the test.
func freshDir(t *testing.T, dir string, uid uint32, mode os.FileMode) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, int(uid), int(uid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
}

// mustGateRestore previews the restore of id and restores it with the
// preview's hash, through the gate.
func mustGateRestore(t *testing.T, id string, into any) {
	t.Helper()
	var pv struct {
		PreviewSHA256 string `json:"preview_sha256"`
	}
	mustGate(t, "priv_restore_preview", map[string]any{"id": id}, &pv)
	mustGate(t, "priv_restore_backup", map[string]any{"id": id, "expected_preview_sha256": pv.PreviewSHA256}, into)
}

// gateBackupOf writes content to p through the gate and returns the id of
// the backup of what it replaced.
func gateBackupOf(t *testing.T, p, content string, extra map[string]any) string {
	t.Helper()
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	args := map[string]any{"path": p, "content_b64": b64s(content)}
	for k, v := range extra {
		args[k] = v
	}
	mustGate(t, "priv_write_file", args, &w)
	if len(w.BackupIDs) != 1 {
		t.Fatalf("write %s: backups %v", p, w.BackupIDs)
	}
	return w.BackupIDs[0]
}

// TestPrivRestoreToolsApproval: write, then restore through the tool
// (approved, restored once, a second re-call approval_invalid), then
// restore the restore's own backup; a file changed after approval and a
// backup tampered with after approval are refused, nothing restored.
func TestPrivRestoreToolsApproval(t *testing.T) {
	srv, h := privWriteServer(t)
	conn := connOf(t, srv.cs)
	freshDir(t, privRestoreDir, 0, 0o755)
	p := privRestoreDir + "/app.conf"
	rootFile(t, p, "v1\n", 0o644)

	t.Run("restore, then restore the restore's backup", func(t *testing.T) {
		b1 := gateBackupOf(t, p, "v2\n", nil)
		args := map[string]any{"backup_id": b1}
		id := pendingID(t, srv.callTool(t, "shell_priv_restore_backup", args))
		if readFile(t, p) != "v2\n" || helperLines(t, conn, "priv_restore_backup", b1) != 0 {
			t.Fatal("restored before approval")
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_restore_backup", withApproval(args, id)), "e2e-ssh")
		ids, _ := d["backup_ids"].([]any)
		if readFile(t, p) != "v1\n" || d["kind"] != "file" || d["mode"] != "0644" || d["recorded_mode"] != "0644" || len(ids) != 1 {
			t.Fatalf("data %v, content %q", d, readFile(t, p))
		}
		b2, _ := ids[0].(string)
		if bm := backupMeta(t, b2); bm["sha256"] != sha("v2\n") || bm["op"] != "priv_restore_backup" {
			t.Fatalf("the current version's backup %v", bm)
		}
		j := conn.waitHelper(t, `"op":"priv_restore_backup"`, `"backup_id":"`+b1+`"`, `"backup_ids":["`+b2+`"]`, `"outcome":"ok"`)
		if strings.Contains(j.Message, "expected_preview_sha256") {
			t.Fatalf("journal line %s", j.Message)
		}
		refusal(t, srv.callTool(t, "shell_priv_restore_backup", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := helperLines(t, conn, "priv_restore_backup", b1); n != 1 {
			t.Fatalf("%d helper restore lines, want 1", n)
		}
		// Restore again: the restore's own backup brings v2 back.
		id2 := pendingID(t, srv.callTool(t, "shell_priv_restore_backup", map[string]any{"backup_id": b2}))
		srv.decide(t, h, id2, "approve")
		okDataAs(t, srv.callTool(t, "shell_priv_restore_backup", withApproval(map[string]any{"backup_id": b2}, id2)), "e2e-ssh")
		if readFile(t, p) != "v2\n" {
			t.Fatal("the restore's backup did not restore")
		}
	})

	t.Run("a file changed after approval is approval_invalid", func(t *testing.T) {
		b := gateBackupOf(t, p, "v3\n", nil)
		args := map[string]any{"backup_id": b}
		id := pendingID(t, srv.callTool(t, "shell_priv_restore_backup", args))
		srv.decide(t, h, id, "approve")
		rootFile(t, p, "changed\n", 0o644)
		refusal(t, srv.callTool(t, "shell_priv_restore_backup", withApproval(args, id)), "approval_invalid", "changed since approval")
		if readFile(t, p) != "changed\n" {
			t.Fatal("restored over a changed file")
		}
	})

	t.Run("a backup tampered with after approval is verify_failed", func(t *testing.T) {
		b := gateBackupOf(t, p, "v4\n", nil)
		args := map[string]any{"backup_id": b}
		id := pendingID(t, srv.callTool(t, "shell_priv_restore_backup", args))
		srv.decide(t, h, id, "approve")
		rootFile(t, filepath.Join(backupDir, b+".data"), "tampered\n", 0o600)
		refusal(t, srv.callTool(t, "shell_priv_restore_backup", withApproval(args, id)), "verify_failed", "does not match its record")
		if readFile(t, p) != "v4\n" {
			t.Fatal("a tampered backup was restored")
		}
	})
	conn.same(t)
}

// TestPrivMovedInRules (N-6, N-7): example-app owns a directory under the
// privileged root and one outside every root on the same filesystem.
func TestPrivMovedInRules(t *testing.T) {
	srv, _ := privWriteServer(t)
	appDir := "/etc/example-app/e2e-app-owned"
	incoming := "/etc/example-other/e2e-moved-in"
	shared := "/etc/example-app/e2e-app-shared"
	freshDir(t, appDir, exampleApp, 0o755)
	freshDir(t, incoming, exampleApp, 0o755)
	freshDir(t, shared, exampleApp, 0o775)

	t.Run("reads", func(t *testing.T) {
		// A root-only file moved in is refused, through the gate and the tool.
		secret := incoming + "/secret.conf"
		rootFile(t, secret, "root only\n", 0o600)
		moved := appDir + "/secret.conf"
		mvAsExampleApp(t, secret, moved)
		r, _ := gate(t, svcShell, "priv_read_file", map[string]any{"path": moved})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") {
			t.Fatalf("a moved-in root-only file: %s %+v", r.code(), r.Error)
		}
		refusal(t, srv.callTool(t, "shell_priv_read_file", map[string]any{"path": moved}), "path_denied", appDir)
		wantGate(t, svcShell, "priv_copy", map[string]any{"source": moved, "destination": privWriteDir + "/copied"}, "path_denied")
		mvAsExampleApp(t, moved, secret)
		// The app's own 0600 file in its own directory is read.
		own := appDir + "/own.conf"
		rootFile(t, own, "own\n", 0o600)
		if err := os.Chown(own, exampleApp, exampleApp); err != nil {
			t.Fatal(err)
		}
		mustGate(t, "priv_read_file", map[string]any{"path": own}, nil)
		// A world-readable root file there is read.
		public := appDir + "/public.conf"
		rootFile(t, public, "public\n", 0o644)
		mustGate(t, "priv_read_file", map[string]any{"path": public}, nil)
		// A same-parent directory swap inside the root: example-app renames
		// a root-only directory within its own directory, which needs no
		// write access to the directory moved.
		secrets := appDir + "/secrets"
		if err := os.Mkdir(secrets, 0o700); err != nil {
			t.Fatal(err)
		}
		rootFile(t, secrets+"/token", "token\n", 0o600)
		mvAsExampleApp(t, secrets, appDir+"/config")
		r, _ = gate(t, svcShell, "priv_read_file", map[string]any{"path": appDir + "/config/token"})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") {
			t.Fatalf("a swapped-in directory: %s %+v", r.code(), r.Error)
		}
	})

	t.Run("overwrites and restores", func(t *testing.T) {
		// The app's own config in its own directory keeps its owner.
		own := appDir + "/app.conf"
		rootFile(t, own, "own v1\n", 0o640)
		if err := os.Chown(own, exampleApp, exampleApp); err != nil {
			t.Fatal(err)
		}
		bOwn := gateBackupOf(t, own, "own v2\n", map[string]any{"expected_sha256": sha("own v1\n")})
		if _, uid, gid, _ := statOwner(t, own); uid != exampleApp || gid != exampleApp {
			t.Fatalf("the app's own file now %d:%d", uid, gid)
		}
		// Its backup (recorded example-app) restores there.
		mustGateRestore(t, bOwn, nil)
		if readFile(t, own) != "own v1\n" {
			t.Fatal("the app's own file was not restored")
		}

		// A root-owned file moved into that directory.
		secret := incoming + "/root.conf"
		rootFile(t, secret, "root\n", 0o600)
		moved := appDir + "/root.conf"
		mvAsExampleApp(t, secret, moved)
		src := privRestoreDir + "-src.conf"
		rootFile(t, src, "src\n", 0o644)
		t.Cleanup(func() { _ = os.Remove(src) })
		wantGate(t, svcShell, "priv_copy", map[string]any{"source": src, "destination": moved, "overwrite": true,
			"expected_destination_sha256": sha("root\n")}, "path_denied")
		wantGate(t, svcShell, "priv_write_file", map[string]any{"path": moved, "content_b64": b64s("new\n"), "expected_sha256": sha("root\n")}, "path_denied")
		wantGate(t, svcShell, "priv_write_file", map[string]any{"path": moved, "content_b64": b64s("new\n"), "expected_sha256": sha("root\n"),
			"owner": "example-app"}, "path_denied")
		if readFile(t, moved) != "root\n" {
			t.Fatal("a refused overwrite changed the moved-in file")
		}
		// Through the tool, the preview cannot hash it: refused, no approval requested.
		env := srv.callTool(t, "shell_priv_write_file", map[string]any{"path": moved, "content": "new\n", "owner": "example-app", "group": "example-app"})
		refusal(t, env, "path_denied", appDir)
		if env["approval"] != nil {
			t.Fatalf("an approval was requested: %v", env)
		}
		// With both an owner and a group, the helper writes it; its backup
		// records root's ownership, which a restore will not put back there.
		bRoot := gateBackupOf(t, moved, "new\n", map[string]any{"expected_sha256": sha("root\n"), "owner": "example-app", "group": "example-app"})
		if _, uid, gid, _ := statOwner(t, moved); uid != exampleApp || gid != exampleApp {
			t.Fatalf("explicit owner: %d:%d", uid, gid)
		}
		r, _ := gate(t, svcShell, "priv_restore_preview", map[string]any{"id": bRoot})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") {
			t.Fatalf("restore of a root-owned file into the app's directory: %s %+v", r.code(), r.Error)
		}
		wantGate(t, svcShell, "priv_restore_backup", map[string]any{"id": bRoot, "expected_preview_sha256": strings.Repeat("0", 64)}, "path_denied")

		// A group-writable directory: explicit owner and group even when the
		// owners match.
		sh := shared + "/app.conf"
		rootFile(t, sh, "shared v1\n", 0o640)
		if err := os.Chown(sh, exampleApp, exampleApp); err != nil {
			t.Fatal(err)
		}
		wantGate(t, svcShell, "priv_write_file", map[string]any{"path": sh, "content_b64": b64s("shared v2\n"), "expected_sha256": sha("shared v1\n")}, "path_denied")
		gateBackupOf(t, sh, "shared v2\n", map[string]any{"expected_sha256": sha("shared v1\n"), "owner": "example-app", "group": "example-app"})
		if readFile(t, sh) != "shared v2\n" {
			t.Fatal("the explicit write did not land")
		}
	})
}
