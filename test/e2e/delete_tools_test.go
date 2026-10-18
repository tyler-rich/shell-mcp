//go:build e2e && linux

package e2e

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
)

// The delete tools end to end: shell_preview_delete through the operator
// server, and shell_delete_path through an admin server, first without an
// approval method, then with the out-of-band approval page and a simulated
// human (docs/handoff/S4B-APPROVAL.md §9.2), against the test sshd and the
// installed gate with the operator policy (max_tier destructive). setup.sh
// mounts a tmpfs at opsWork/mounted/point. Every value is invented.

// delTree makes dir with a.txt, sub/b.txt and sub/c.txt (6 bytes), owned by
// the service account.
func delTree(t *testing.T, dir string) []string {
	t.Helper()
	_ = os.RemoveAll(dir)
	files := map[string]string{"a.txt": "aa", "sub/b.txt": "bb", "sub/c.txt": "cc"}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil { //nolint:gosec // G306: test fixture
			t.Fatal(err)
		}
	}
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "svc-shell:svc-shell", dir).CombinedOutput(); err != nil { //nolint:gosec // G204: a fixed command on the test's own path
		t.Fatalf("chown: %v: %s", err, out)
	}
	return []string{dir + "/a.txt", dir + "/sub/b.txt", dir + "/sub/c.txt"}
}

func stillThere(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s is gone: %v", p, err)
		}
	}
}

// deleteLines counts the gate's delete audit lines (not delete_preview)
// for p since start.
func deleteLines(t *testing.T, since time.Time, p string) int {
	t.Helper()
	n := 0
	for _, j := range journal(t, "shell-mcp-gate", since) {
		if strings.Contains(j.Message, `"principal":"`+opsWho+`"`) && strings.Contains(j.Message, `"op":"delete"`) && strings.Contains(j.Message, `"`+p+`"`) {
			n++
		}
	}
	return n
}

func TestDeleteToolsPreview(t *testing.T) {
	opsServer(t)
	dir := opsWork + "/del-preview"
	files := delTree(t, dir)
	start := time.Now()
	t.Run("success", func(t *testing.T) {
		d := opOK(t, "shell_preview_delete", map[string]any{"path": dir, "recursive": true})
		sha, _ := d["preview_sha256"].(string)
		first, _ := d["first"].([]any)
		if d["type"] != "dir" || d["entries"] != 5.0 || d["bytes"] != 6.0 || len(first) != 5 || first[0] != dir || len(sha) != 64 || d["truncated"] != false {
			t.Fatalf("preview %v", d)
		}
		stillThere(t, files...)
		again := opOK(t, "shell_preview_delete", map[string]any{"path": dir, "recursive": true})
		if again["preview_sha256"] != sha {
			t.Fatal("an unchanged tree previewed with another hash")
		}
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"delete_preview"`, `"ceiling":"read"`, `"outcome":"ok"`)
	})
	t.Run("refusals", func(t *testing.T) {
		// A device node (the test runs as root on the runner VM): the gate's sandbox
		// grants no right to create one, so a delete refuses it in the walk.
		devDir := opsWork + "/del-dev"
		_ = os.RemoveAll(devDir)
		if err := os.Mkdir(devDir, 0o755); err != nil { //nolint:gosec // G301: root-owned; the service account must traverse it
			t.Fatal(err)
		}
		if err := unix.Mknod(devDir+"/null", unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3))); err != nil { //nolint:gosec // G115: a small device number
			t.Fatal(err)
		}
		for _, c := range []struct {
			path      string
			recursive bool
			code, msg string
		}{
			{opsWork, true, "path_denied", "root"},
			{opsRoot + "/readonly.txt", false, "path_denied", "write roots"},
			{opsRepo + "/.git", true, "path_denied", "protected"},
			{opsRepo, true, "path_denied", "protected"},
			{opsWork + "/mounted/point", true, "path_denied", "mount"},
			{opsWork + "/mounted", true, "path_denied", "mount"},
			{dir, false, "bad_request", "not empty"},
			{devDir + "/null", false, "path_denied", "device node"},
			{devDir, true, "path_denied", "device node"},
		} {
			refusal(t, opCall(t, "shell_preview_delete", map[string]any{"path": c.path, "recursive": c.recursive}), c.code, c.msg)
		}
		stillThere(t, files...)
		stillThere(t, opsWork+"/mounted/point/inside.txt", opsRepo+"/.git/config")
		stillThere(t, devDir+"/null")
	})
}

func TestDeleteToolsApproval(t *testing.T) {
	opsServer(t)
	t.Run("no approval method: refused, nothing sent", func(t *testing.T) {
		log := &syncedBuffer{}
		cs, err := startServer(t, log, "SHELL_MCP_PROFILE=admin")
		if err != nil {
			t.Fatalf("connect: %v; server log: %s", err, log.String())
		}
		t.Cleanup(func() { _ = cs.Close() })
		dir := opsWork + "/del-none"
		files := delTree(t, dir)
		time.Sleep(1100 * time.Millisecond)
		since := time.Now()
		refusal(t, callOn(t, cs, log, "shell_delete_path", map[string]any{"path": dir, "recursive": true}), "approval_unavailable", "")
		stillThere(t, files...)
		time.Sleep(time.Second)
		for _, j := range journal(t, "shell-mcp-gate", since) {
			if strings.Contains(j.Message, `"principal":"`+opsWho+`"`) && strings.Contains(j.Message, dir) {
				t.Fatalf("a request reached the gate: %s", j.Message)
			}
		}
	})

	h := &human{seed: make([]byte, 20)}
	if _, err := rand.Read(h.seed); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "approvers")
	if err := os.WriteFile(file, []byte("alice "+approvers.EncodeSeed(h.seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startApprovalServer(t, h, file, freeLoopbackPort(t), "SHELL_MCP_PROFILE=admin")
	t.Cleanup(func() { _ = srv.cs.Close() })

	t.Run("approve, delete once, second re-call invalid", func(t *testing.T) {
		dir := opsWork + "/del-approved"
		files := delTree(t, dir)
		time.Sleep(1100 * time.Millisecond)
		start := time.Now()
		args := map[string]any{"path": dir, "recursive": true}
		id := pendingID(t, srv.callTool(t, "shell_delete_path", args))
		// Before approval: only the preview reached the gate.
		stillThere(t, files...)
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"delete_preview"`, `"ceiling":"destructive"`, dir)
		if n := deleteLines(t, start, dir); n != 0 {
			t.Fatalf("%d delete lines before approval", n)
		}

		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_delete_path", withApproval(args, id)), opsWho)
		if d["deleted"] != true || d["entries"] != 5.0 {
			t.Fatalf("delete %v", d)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("tree still there: %v", err)
		}
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"delete"`, `"ceiling":"destructive"`, `"outcome":"ok"`, dir)
		if n := deleteLines(t, start, dir); n != 1 {
			t.Fatalf("%d delete lines after the approved re-call, want 1", n)
		}

		refusal(t, srv.callTool(t, "shell_delete_path", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := deleteLines(t, start, dir); n != 1 {
			t.Fatalf("%d delete lines after the second re-call, want 1", n)
		}
		// The hash is never logged by the gate.
		for _, j := range journal(t, "shell-mcp-gate", start) {
			if strings.Contains(j.Message, "expected_preview_sha256") {
				t.Fatalf("the gate logged the precondition: %s", j.Message)
			}
		}
	})

	t.Run("a tree change after approval invalidates it and nothing is deleted", func(t *testing.T) {
		dir := opsWork + "/del-changed"
		files := delTree(t, dir)
		args := map[string]any{"path": dir, "recursive": true}
		id := pendingID(t, srv.callTool(t, "shell_delete_path", args))
		srv.decide(t, h, id, "approve")
		newcomer := dir + "/sub/newcomer.txt"
		if err := os.WriteFile(newcomer, []byte("new"), 0o644); err != nil { //nolint:gosec // G306: test fixture
			t.Fatal(err)
		}
		since := time.Now()
		refusal(t, srv.callTool(t, "shell_delete_path", withApproval(args, id)), "approval_invalid", "changed since approval")
		stillThere(t, append(files, newcomer)...)
		time.Sleep(time.Second)
		if n := deleteLines(t, since, dir); n != 0 {
			t.Fatalf("%d delete lines after the tree changed", n)
		}
	})

	t.Run("a refused preview requests no approval", func(t *testing.T) {
		env := srv.callTool(t, "shell_delete_path", map[string]any{"path": opsWork + "/mounted/point", "recursive": true})
		refusal(t, env, "path_denied", "mount")
		if env["approval"] != nil {
			t.Fatalf("an approval was requested: %v", env)
		}
		stillThere(t, opsWork+"/mounted/point/inside.txt")
	})
}
