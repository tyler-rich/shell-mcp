//go:build e2e && linux

package e2e

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// The git discard tools and the destructive shell_run_command end to end,
// against the test sshd and the installed gate with the operator policy
// (max_tier destructive; the repository opsDiscard; the destructive
// command probe-destructive): shell_preview_git_discard through the
// operator server, then shell_discard_git_changes and shell_run_command
// through an admin server, first without an approval method, then with the
// approval page and a simulated human (docs/handoff/S4B-APPROVAL.md §9.2).
// Every value is invented.

// dirtyDiscard resets opsDiscard to HEAD and makes one change of each
// kind: a tracked file edited, a staged new file, an untracked file and an
// ignored one; everything is owned by the service account.
func dirtyDiscard(t *testing.T) {
	t.Helper()
	repoGit(t, opsDiscard, "reset", "-q", "--hard")
	repoGit(t, opsDiscard, "clean", "-q", "-f", "-f", "-d", "-x")
	_ = os.Remove(opsDiscard + "/.git/index.lock")
	_ = os.Remove(opsDiscard + "/.git/MERGE_HEAD")
	opsFile(t, opsDiscard+"/.gitignore", "*.log\n", 0o644)
	repoGit(t, opsDiscard, "add", ".gitignore")
	repoGit(t, opsDiscard, "-c", "user.name=Example", "-c", "user.email=dev@example.test", "commit", "-q", "--allow-empty", "-m", "ignore logs")
	opsFile(t, opsDiscard+"/app.conf", "version: edited\n", 0o644)
	opsFile(t, opsDiscard+"/staged.txt", "staged\n", 0o644)
	repoGit(t, opsDiscard, "add", "staged.txt")
	opsFile(t, opsDiscard+"/untracked.txt", "untracked\n", 0o644)
	opsFile(t, opsDiscard+"/keep.log", "ignored\n", 0o644)
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "svc-shell:svc-shell", opsDiscard).CombinedOutput(); err != nil {
		t.Fatalf("chown: %v: %s", err, out)
	}
}

// opLines counts the audit lines of op (exactly) of c's server, for the
// operator principal, that contain every string in want.
func opLines(t *testing.T, c *serverConn, op string, want ...string) int {
	t.Helper()
	return len(c.gate(t, append([]string{`"principal":"` + opsWho + `"`, `"op":"` + op + `"`}, want...)...))
}

func TestGitDiscardPreviewTool(t *testing.T) {
	opsServer(t)
	dirtyDiscard(t)
	start := time.Now()
	t.Run("success", func(t *testing.T) {
		d := opOK(t, "shell_preview_git_discard", map[string]any{"repo": opsDiscard, "include_untracked": true})
		sha, _ := d["preview_sha256"].(string)
		if d["restore"] != 1.0 || d["remove"] != 1.0 || d["untracked"] != 1.0 || d["entries"] != 3.0 || len(sha) != 64 {
			t.Fatalf("preview %v", d)
		}
		again := opOK(t, "shell_preview_git_discard", map[string]any{"repo": opsDiscard, "include_untracked": true})
		if again["preview_sha256"] != sha {
			t.Fatal("an unchanged repository previewed with another hash")
		}
		without := opOK(t, "shell_preview_git_discard", map[string]any{"repo": opsDiscard})
		if without["untracked"] != 0.0 || without["entries"] != 2.0 || without["preview_sha256"] == sha {
			t.Fatalf("without include_untracked %v", without)
		}
		fileIs(t, opsDiscard+"/app.conf", "version: edited\n")
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"git_discard_preview"`, `"ceiling":"read"`, `"outcome":"ok"`, `"include_untracked":true`)
	})
	t.Run("refusals", func(t *testing.T) {
		refusal(t, opCall(t, "shell_preview_git_discard", map[string]any{"repo": opsWork}), "policy_denied", "git.repos")
		// An untracked symlink is never removed.
		if err := os.Symlink("app.conf", opsDiscard+"/ulink"); err != nil {
			t.Fatal(err)
		}
		refusal(t, opCall(t, "shell_preview_git_discard", map[string]any{"repo": opsDiscard, "include_untracked": true}), "path_denied", "symlink")
		_ = os.Remove(opsDiscard + "/ulink")
		// A merge in progress.
		opsFile(t, opsDiscard+"/.git/MERGE_HEAD", repoGit(t, opsDiscard, "rev-parse", "HEAD")+"\n", 0o644)
		refusal(t, opCall(t, "shell_preview_git_discard", map[string]any{"repo": opsDiscard}), "policy_denied", "in progress")
		_ = os.Remove(opsDiscard + "/.git/MERGE_HEAD")
		// A lock git holds, or left: reported and left alone.
		opsFile(t, opsDiscard+"/.git/index.lock", "", 0o644)
		refusal(t, opCall(t, "shell_preview_git_discard", map[string]any{"repo": opsDiscard}), "exists", "locked by another git process")
		if _, err := os.Lstat(opsDiscard + "/.git/index.lock"); err != nil {
			t.Fatal("the gate removed a lock it did not create")
		}
		_ = os.Remove(opsDiscard + "/.git/index.lock")
		fileIs(t, opsDiscard+"/app.conf", "version: edited\n")
	})
}

func TestDestructiveToolsApproval(t *testing.T) {
	opsServer(t)
	t.Run("no approval method: destructive refused after its preview, read and operator commands run", func(t *testing.T) {
		log := &syncedBuffer{}
		cs, err := startServer(t, log, "SHELL_MCP_PROFILE=admin")
		if err != nil {
			t.Fatalf("connect: %v; server log: %s", err, log.String())
		}
		t.Cleanup(func() { _ = cs.Close() })
		conn := connOf(t, cs)
		dirtyDiscard(t)
		refusal(t, callOn(t, cs, log, "shell_discard_git_changes", map[string]any{"repo": opsDiscard}), "approval_unavailable", "")
		refusal(t, callOn(t, cs, log, "shell_run_command", map[string]any{"command_id": "probe-destructive", "args": []string{"echo", "destructive"}}),
			"approval_unavailable", "")
		fileIs(t, opsDiscard+"/app.conf", "version: edited\n")
		// Per tier (D-006): read and operator commands need no approval under
		// the default tiers, in admin as in the operator profile; they run at
		// ceiling operator, after their preview.
		okDataAs(t, callOn(t, cs, log, "shell_run_command", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "admin-read"}}), opsWho)
		env := callOn(t, cs, log, "shell_run_command", map[string]any{"command_id": "probe-exit", "args": []string{"exit", "2"}})
		if okDataAs(t, env, opsWho) == nil || env["exec"].(map[string]any)["exit_code"] != 2.0 || env["approval"] != nil {
			t.Fatalf("operator command %v", env)
		}
		time.Sleep(time.Second)
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"exec_preview"`, `"command_id":"probe-destructive"`, `"ceiling":"destructive"`)
		for _, id := range []string{"probe-echo", "probe-exit"} {
			conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"exec"`, `"command_id":"`+id+`"`, `"ceiling":"operator"`, `"outcome":"ok"`)
		}
		if n := opLines(t, conn, "exec", `"command_id":"probe-destructive"`); n != 0 {
			t.Fatalf("%d exec lines for the destructive command", n)
		}
		if n := opLines(t, conn, "git_discard_preview") + opLines(t, conn, "git_discard"); n != 0 {
			t.Fatalf("%d discard lines without an approval method", n)
		}
		conn.same(t)
	})

	h := newHuman(t, manyApprovers)
	file := h.file(t)
	srv := startApprovalServer(t, h, file, freeLoopbackPort(t), "SHELL_MCP_PROFILE=admin")
	t.Cleanup(func() { _ = srv.cs.Close() })
	// The subtests below share this server and run one after another, each
	// waiting for every line it expects; one that counts an op an earlier
	// subtest also sent counts it at its start too (every earlier line of
	// this server for that op is in the journal by then).
	conn := connOf(t, srv.cs)

	t.Run("discard: approve, discard once, second re-call invalid", func(t *testing.T) {
		dirtyDiscard(t)
		marker := opsWork + "/discard-hook-ran"
		_ = os.Remove(marker)
		opsFile(t, opsDiscard+"/.git/hooks/post-index-change", "#!/bin/sh\necho ran >> "+marker+"\n", 0o755)
		args := map[string]any{"repo": opsDiscard, "include_untracked": true}
		id := pendingID(t, srv.callTool(t, "shell_discard_git_changes", args))
		fileIs(t, opsDiscard+"/app.conf", "version: edited\n")
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"git_discard_preview"`, `"ceiling":"destructive"`)
		if n := opLines(t, conn, "git_discard"); n != 0 {
			t.Fatalf("%d git_discard lines before approval", n)
		}

		srv.decide(t, h, id, "approve")
		d := okDataAs(t, srv.callTool(t, "shell_discard_git_changes", withApproval(args, id)), opsWho)
		if d["discarded"] != true || d["clean_after"] != true || d["restore"] != 1.0 || d["remove"] != 1.0 || d["untracked"] != 1.0 {
			t.Fatalf("discard %v", d)
		}
		fileIs(t, opsDiscard+"/app.conf", "version: 1\n")
		fileIs(t, opsDiscard+"/keep.log", "ignored\n")
		for _, p := range []string{"staged.txt", "untracked.txt", ".git/index.lock"} {
			if _, err := os.Lstat(opsDiscard + "/" + p); !os.IsNotExist(err) {
				t.Fatalf("%s still there: %v", p, err)
			}
		}
		// Before the test's own git runs: its status (as root, without the
		// gate's flags) would run the hook itself.
		if _, err := os.Lstat(marker); !os.IsNotExist(err) {
			t.Fatal("a hook ran during the discard")
		}
		_ = os.Remove(opsDiscard + "/.git/hooks/post-index-change")
		if st := repoGit(t, opsDiscard, "--no-optional-locks", "status", "--porcelain", "--untracked-files=no"); st != "" {
			t.Fatalf("status after the discard: %q", st)
		}
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"git_discard"`, `"ceiling":"destructive"`, `"outcome":"ok"`)
		if n := opLines(t, conn, "git_discard"); n != 1 {
			t.Fatalf("%d git_discard lines after the approved re-call, want 1", n)
		}
		refusal(t, srv.callTool(t, "shell_discard_git_changes", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := opLines(t, conn, "git_discard"); n != 1 {
			t.Fatalf("%d git_discard lines after the second re-call, want 1", n)
		}
		// Of any request, in this whole run.
		for _, j := range runLines(t, "shell-mcp-gate", "expected_preview_sha256") {
			t.Fatalf("the gate logged the precondition: %s", j.Message)
		}
		_ = os.Remove(opsDiscard + "/.git/hooks/post-index-change")
	})

	t.Run("discard: a change after approval invalidates it and survives", func(t *testing.T) {
		dirtyDiscard(t)
		before := opLines(t, conn, "git_discard")
		args := map[string]any{"repo": opsDiscard}
		id := pendingID(t, srv.callTool(t, "shell_discard_git_changes", args))
		srv.decide(t, h, id, "approve")
		opsFile(t, opsDiscard+"/app.conf", "version: changed after approval\n", 0o644)
		refusal(t, srv.callTool(t, "shell_discard_git_changes", withApproval(args, id)), "approval_invalid", "changed since approval")
		fileIs(t, opsDiscard+"/app.conf", "version: changed after approval\n")
		fileIs(t, opsDiscard+"/staged.txt", "staged\n")
		time.Sleep(time.Second)
		if n := opLines(t, conn, "git_discard") - before; n != 0 {
			t.Fatalf("%d git_discard lines after the change", n)
		}
	})

	t.Run("run command per tier with operator listed: read runs, operator is approved and runs at operator", func(t *testing.T) {
		// startApprovalServer sets SHELL_MCP_APPROVAL_TIERS=operator,destructive.
		env := srv.callTool(t, "shell_run_command", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "listed-read"}})
		if okDataAs(t, env, opsWho) == nil || env["approval"] != nil {
			t.Fatalf("read command %v", env)
		}
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"exec"`, `"command_id":"probe-echo"`, `"ceiling":"read"`, `"outcome":"ok"`)
		op := map[string]any{"command_id": "probe-exit", "args": []string{"exit", "1"}}
		id := pendingID(t, srv.callTool(t, "shell_run_command", op))
		if n := opLines(t, conn, "exec", `"command_id":"probe-exit"`); n != 0 {
			t.Fatalf("%d exec lines before approval", n)
		}
		srv.decide(t, h, id, "approve")
		env = srv.callTool(t, "shell_run_command", withApproval(op, id))
		if okDataAs(t, env, opsWho) == nil || env["exec"].(map[string]any)["exit_code"] != 1.0 {
			t.Fatalf("approved operator command %v", env)
		}
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"exec"`, `"command_id":"probe-exit"`, `"ceiling":"operator"`, `"outcome":"ok"`)
		if n := opLines(t, conn, "exec", `"command_id":"probe-exit"`); n != 1 {
			t.Fatalf("%d exec lines after the approved re-call, want 1", n)
		}
	})

	destructive := map[string]any{"command_id": "probe-destructive", "args": []string{"echo", "destructive"}}
	t.Run("run command: approve, run once, second re-call invalid", func(t *testing.T) {
		id := pendingID(t, srv.callTool(t, "shell_run_command", destructive))
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"exec_preview"`, `"ceiling":"destructive"`, `"command_id":"probe-destructive"`, `"outcome":"ok"`)
		if n := opLines(t, conn, "exec", `"command_id":"probe-destructive"`); n != 0 {
			t.Fatalf("%d exec lines before approval", n)
		}
		srv.decide(t, h, id, "approve")
		env := srv.callTool(t, "shell_run_command", withApproval(destructive, id))
		if d := okDataAs(t, env, opsWho); d["stdout"] != "destructive\n" {
			t.Fatalf("run %v", env)
		}
		conn.waitGate(t, `"principal":"`+opsWho+`"`, `"op":"exec"`, `"ceiling":"destructive"`, `"command_id":"probe-destructive"`, `"outcome":"ok"`)
		if n := opLines(t, conn, "exec", `"command_id":"probe-destructive"`); n != 1 {
			t.Fatalf("%d exec lines after the approved re-call, want 1", n)
		}
		refusal(t, srv.callTool(t, "shell_run_command", withApproval(destructive, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := opLines(t, conn, "exec", `"command_id":"probe-destructive"`); n != 1 {
			t.Fatalf("%d exec lines after the second re-call, want 1", n)
		}
	})

	t.Run("run command: a policy change after approval invalidates it and nothing runs", func(t *testing.T) {
		const policyFile = "/etc/shell-mcp/gate-operator.yaml"
		orig, err := os.ReadFile(policyFile)
		if err != nil {
			t.Fatal(err)
		}
		before := opLines(t, conn, "exec", `"command_id":"probe-destructive"`)
		id := pendingID(t, srv.callTool(t, "shell_run_command", destructive))
		srv.decide(t, h, id, "approve")
		if err := os.WriteFile(policyFile, append(append([]byte{}, orig...), "# changed after approval\n"...), 0o644); err != nil { //nolint:gosec // G306: the gate policy is root-owned 0644
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(policyFile, orig, 0o644); err != nil { //nolint:gosec // G306: as above
				t.Error(err)
			}
		})
		refusal(t, srv.callTool(t, "shell_run_command", withApproval(destructive, id)), "approval_invalid", "changed since approval")
		time.Sleep(time.Second)
		if n := opLines(t, conn, "exec", `"command_id":"probe-destructive"`) - before; n != 0 {
			t.Fatalf("%d exec lines after the policy changed", n)
		}
	})
	conn.same(t)
}
