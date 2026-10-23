//go:build e2e && linux

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/test/e2e/runner"
)

// Rule R end to end (handoff docs/handoff/S4C-PRIVILEGED.md N-8, N-9, P-14;
// PRIVILEGED §6): the real server, gate and helper (core unit). Root leaves
// a file only where the owner it will have is owner-matched on the chain
// from the privileged root; the tools' previews refuse what the helper
// would, before an approval is requested; every new inode gets its group
// set explicitly, never a setgid parent's; a delete's approval page says
// when the tools could not restore its backup. example-app is the other
// account. Every path and value is invented.

// page returns the approval page of id, as an approver would see it.
func (s *approvalServer) page(t *testing.T, id string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.origin()+"/approvals/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("approval page: %d %s", res.StatusCode, b)
	}
	return string(b)
}

// noApproval fails when env requested an approval.
func noApproval(t *testing.T, env map[string]any) {
	t.Helper()
	if env["approval"] != nil {
		t.Fatalf("an approval was requested: %v", env)
	}
}

func TestPrivOwnerRule(t *testing.T) {
	srv, h := privWriteServer(t)
	approveRun := func(t *testing.T, tool string, args map[string]any) map[string]any {
		t.Helper()
		id := pendingID(t, srv.callTool(t, tool, args))
		srv.decide(t, h, id, "approve")
		return srv.callTool(t, tool, withApproval(args, id))
	}
	appDir := "/etc/example-app/e2e-owner-app"
	shared := "/etc/example-app/e2e-owner-shared"
	freshDir(t, appDir, exampleApp, 0o755)
	freshDir(t, shared, exampleApp, 0o775)
	src := privWriteDir + "/src.conf"
	rootFile(t, src, "src\n", 0o640)

	t.Run("under the account's directory: root's file refused, the account's written", func(t *testing.T) {
		p := appDir + "/new.conf"
		// No owner (root's), and owner root given: refused at the preview,
		// naming the one owner that would pass; and by the helper itself.
		for _, args := range []map[string]any{
			{"path": p, "content": "new\n"},
			{"path": p, "content": "new\n", "owner": "root", "group": "root"},
		} {
			env := srv.callTool(t, "shell_priv_write_file", args)
			refusal(t, env, "path_denied", "example-app")
			noApproval(t, env)
		}
		r, _ := gate(t, svcShell, "priv_write_file", map[string]any{"path": p, "content_b64": b64s("new\n")})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, "the directory "+appDir+" is ") || !strings.Contains(r.Error.Message, "uid "+strconv.Itoa(exampleApp)) {
			t.Fatalf("the helper's refusal: %s %+v", r.code(), r.Error)
		}
		wantGate(t, svcShell, "priv_write_file", map[string]any{"path": p, "content_b64": b64s("new\n"), "owner": "root", "group": "root"}, "path_denied")
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("a refused write created the file")
		}
		// A new copy (no owner input) is refused at its preview.
		env := srv.callTool(t, "shell_priv_copy_path", map[string]any{"source": src, "destination": appDir + "/copy.conf"})
		refusal(t, env, "path_denied", "example-app")
		noApproval(t, env)
		// The account itself as the owner: approved and written as it.
		d := okDataAs(t, approveRun(t, "shell_priv_write_file", map[string]any{"path": p, "content": "own\n", "owner": "example-app", "group": "example-app"}), "e2e-ssh")
		if _, uid, gid, _ := statOwner(t, p); uid != exampleApp || gid != exampleApp || d["uid"] != float64(exampleApp) || readFile(t, p) != "own\n" {
			t.Fatalf("written as example-app: %d:%d %v", uid, gid, d)
		}
		// Owner-matched writes keep working: its own file, kept.
		okDataAs(t, approveRun(t, "shell_priv_write_file", map[string]any{"path": p, "content": "own v2\n"}), "e2e-ssh")
		if _, uid, _, _ := statOwner(t, p); uid != exampleApp || readFile(t, p) != "own v2\n" {
			t.Fatalf("an owner-matched overwrite: uid %d", uid)
		}
	})

	t.Run("a group-writable directory: no owner passes", func(t *testing.T) {
		p := shared + "/new.conf"
		env := srv.callTool(t, "shell_priv_write_file", map[string]any{"path": p, "content": "x\n", "owner": "example-app", "group": "example-app"})
		refusal(t, env, "path_denied", shared)
		noApproval(t, env)
		wantGate(t, svcShell, "priv_write_file", map[string]any{"path": p, "content_b64": b64s("x\n"), "owner": "example-app", "group": "example-app"}, "path_denied")
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("a refused write created the file")
		}
	})

	t.Run("a setgid directory: the group is root's unless given", func(t *testing.T) {
		sg := "/etc/example-app/e2e-owner-setgid"
		freshDir(t, sg, 0, 0o755)
		if err := os.Chown(sg, 0, exampleApp); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sg, 0o755|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		d := okDataAs(t, approveRun(t, "shell_priv_write_file", map[string]any{"path": sg + "/new.conf", "content": "new\n"}), "e2e-ssh")
		if d["gid"] != 0.0 || d["group"] != "root" {
			t.Fatalf("the write reports group %v %v", d["gid"], d["group"])
		}
		mustGate(t, "priv_copy", map[string]any{"source": src, "destination": sg + "/copy.conf"}, nil)
		mustGate(t, "priv_mkdir", map[string]any{"path": sg + "/sub"}, nil)
		for _, n := range []string{"new.conf", "copy.conf", "sub"} {
			mode, uid, gid, _ := statOwner(t, filepath.Join(sg, n))
			if uid != 0 || gid != 0 || mode&os.ModeSetgid != 0 {
				t.Fatalf("%s: %d:%d %v, want root:root without setgid", n, uid, gid, mode)
			}
		}
		// A group given is the one set.
		mustGate(t, "priv_write_file", map[string]any{"path": sg + "/app.conf", "content_b64": b64s("x\n"), "group": "example-app"}, nil)
		if _, _, gid, _ := statOwner(t, sg+"/app.conf"); gid != exampleApp {
			t.Fatalf("a given group: %d", gid)
		}
	})

	t.Run("a delete whose backup the tools could not restore says so", func(t *testing.T) {
		p := appDir + "/root.conf"
		rootFile(t, p, "root's\n", 0o640)
		args := map[string]any{"path": p}
		want := "the tools won't be able to restore 1 entry of this backup: "
		env := srv.callTool(t, "shell_priv_preview_delete", args)
		ws, _ := env["warnings"].([]any)
		if len(ws) != 1 || !strings.HasPrefix(fmt.Sprint(ws[0]), want) || !strings.Contains(fmt.Sprint(ws[0]), appDir) {
			t.Fatalf("preview warnings %v", env["warnings"])
		}
		id := pendingID(t, srv.callTool(t, "shell_priv_delete_path", args))
		if pg := srv.page(t, id); !strings.Contains(pg, "be able to restore 1 entry of this backup") {
			t.Fatalf("the approval page does not say the backup cannot be restored")
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_priv_delete_path", withApproval(args, id)), "e2e-ssh")
		ids, _ := d["backup_ids"].([]any)
		if len(ids) != 1 {
			t.Fatalf("delete %v", d)
		}
		r, _ := gate(t, svcShell, "priv_restore_preview", map[string]any{"id": ids[0]})
		if r.code() != "path_denied" || !strings.Contains(r.Error.Message, appDir) {
			t.Fatalf("the restore the warning announced: %s %+v", r.code(), r.Error)
		}
		// A backup that restores: no warning.
		q := privWriteDir + "/plain.conf"
		rootFile(t, q, "plain\n", 0o640)
		if ws, _ := srv.callTool(t, "shell_priv_preview_delete", map[string]any{"path": q})["warnings"].([]any); len(ws) != 0 {
			t.Fatalf("a restorable backup warns %v", ws)
		}
	})
}

// TestPrivOwnerRuleRace (core unit): example-app, which owns a directory
// under the write root, exchanges a directory in it with a symlink to a
// root-only directory elsewhere in the root, again and again, while the
// helper is asked to create files beneath it: without an owner, as root,
// and as example-app. Root's are always refused; example-app's either land
// in example-app's own directory, as example-app's, or are refused; nothing
// ever lands in the root-only directory.
func TestPrivOwnerRuleRace(t *testing.T) {
	race := "/etc/example-app/e2e-owner-race"
	vault := "/etc/example-app/e2e-owner-vault"
	freshDir(t, race, exampleApp, 0o755)
	freshDir(t, vault, 0, 0o700)
	d := race + "/d"
	if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // G301: example-app's directory, given to it below
		t.Fatal(err)
	}
	if err := os.Chown(d, exampleApp, exampleApp); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), self)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, exampleApp)}
	cmd.Env = append(runner.Env(), "E2E_CLIENT=swap", "E2E_SWAP_NAME="+d, "E2E_SWAP_ALT="+d+".alt", "E2E_SWAP_TO="+vault)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	written, refused := 0, 0
	for i := range 40 {
		for _, c := range []struct {
			name  string
			extra map[string]any
			own   bool
		}{
			{"root", nil, false},
			{"owner root", map[string]any{"owner": "root", "group": "root"}, false},
			{"example-app", map[string]any{"owner": "example-app", "group": "example-app"}, true},
		} {
			args := map[string]any{"path": fmt.Sprintf("%s/f%d-%d", d, i, len(c.name)), "content_b64": b64s("x\n")}
			for k, v := range c.extra {
				args[k] = v
			}
			r, _ := gate(t, svcShell, "priv_write_file", args)
			switch {
			case r.OK && c.own:
				written++
			case r.OK:
				_ = stdin.Close()
				t.Fatalf("run %d: %s created a file under example-app's directory", i, c.name)
			case r.code() == "path_denied":
				refused++
			default:
				_ = stdin.Close()
				t.Fatalf("run %d: %s: %s %+v", i, c.name, r.code(), r.Error)
			}
		}
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("racer: %v %q", err, out.String())
	}
	if f := strings.Fields(out.String()); len(f) != 2 || f[0] != "SWAPS" || f[1] == "0" {
		t.Fatalf("racer: %q", out.String())
	}
	if names, _ := os.ReadDir(vault); len(names) != 0 {
		t.Fatalf("the root-only directory holds %d entries", len(names))
	}
	// Whichever name d has now, everything in example-app's directory is its.
	for _, dir := range []string{d, d + ".alt"} {
		names, _ := os.ReadDir(dir)
		for _, n := range names {
			if _, uid, _, _ := statOwner(t, filepath.Join(dir, n.Name())); uid != exampleApp {
				t.Fatalf("%s/%s is uid %d", dir, n.Name(), uid)
			}
		}
	}
	t.Logf("%d written as example-app, %d refused; racer: %s", written, refused, strings.TrimSpace(out.String()))
}
