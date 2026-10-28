//go:build e2e && linux

package e2e

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Replacing a private key through the gate's own tools end to end (handoff
// N-5, the gate's half; S7-3): the real server (operator profile, web
// approval with a simulated human, operator tools gated), the real gate
// with the operator policy. Each preview hashes an existing destination
// through hash_file, never reading it; the approval binds the old file's
// hash (and a write's new content); neither key appears in a tool result,
// an approval page, the server's log or the gate's journal. A copy whose
// source holds a key past its first 64 KiB is refused. The keys are
// generated for each run; every path is invented.

func TestGateKeyRotation(t *testing.T) {
	opsServer(t)
	h := newHuman(t, singleApprover)
	srv := startApprovalServer(t, h, h.file(t), freeLoopbackPort(t))
	t.Cleanup(func() { _ = srv.cs.Close() })
	start := time.Now()
	dir := opsWork + "/e2e-tls"
	_ = os.RemoveAll(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, svcShell, svcShell); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	keyA, bodyA := e2eKey(t)
	keyB, bodyB := e2eKey(t)
	keyC, bodyC := e2eKey(t)
	keyD, bodyD := e2eKey(t)
	bodies := [][]string{bodyA, bodyB, bodyC, bodyD}
	var seen []string // every result and approval page, checked at the end
	call := func(tool string, args map[string]any) map[string]any {
		env := srv.callTool(t, tool, args)
		seen = append(seen, asJSON(env))
		return env
	}
	page := func(id string) string {
		pg := srv.page(t, id)
		seen = append(seen, pg)
		return pg
	}
	// approved runs a call through a pending approval, the page (which must
	// show want), the decision and the re-call, then checks that a second
	// re-call is approval_invalid.
	approved := func(t *testing.T, tool string, args map[string]any, want ...string) map[string]any {
		t.Helper()
		id := pendingID(t, call(tool, args))
		pg := page(id)
		for _, w := range want {
			if !strings.Contains(pg, w) {
				t.Fatalf("the approval page does not show %q: %s", w, pg)
			}
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, call(tool, withApproval(args, id)), opsWho)
		refusal(t, call(tool, withApproval(args, id)), "approval_invalid", "")
		return d
	}
	cert := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"
	p := dir + "/server.key"

	t.Run("write over a key: approved with hashes only, run once", func(t *testing.T) {
		opsFile(t, p, keyA, 0o600)
		d := approved(t, "shell_write_file", map[string]any{"path": p, "content": keyB}, "private key, not shown", sha(keyA), sha(keyB))
		if readFile(t, p) != keyB || d["old_sha256"] != sha(keyA) || d["new_sha256"] != sha(keyB) {
			t.Fatalf("rotation %v", d)
		}
	})

	t.Run("write over a certificate bundle holding a key", func(t *testing.T) {
		q := dir + "/bundle.pem"
		bundle := cert + keyC
		opsFile(t, q, bundle, 0o640)
		approved(t, "shell_write_file", map[string]any{"path": q, "content": "# the key moved to its own file\n"}, sha(bundle))
		if readFile(t, q) != "# the key moved to its own file\n" {
			t.Fatal("not written")
		}
	})

	t.Run("copy over a key and over a bundle", func(t *testing.T) {
		src := dir + "/cert-only.pem"
		opsFile(t, src, cert, 0o640)
		for name, existing := range map[string]string{"copy.key": keyA, "copy-bundle.pem": cert + keyA} {
			q := dir + "/" + name
			opsFile(t, q, existing, 0o600)
			d := approved(t, "shell_copy_path", map[string]any{"source": src, "destination": q, "overwrite": true}, sha(existing))
			if readFile(t, q) != cert || d["old_sha256"] != sha(existing) {
				t.Fatalf("%s: copy %v", name, d)
			}
		}
	})

	t.Run("move a key generated on the host over the old key", func(t *testing.T) {
		for name, existing := range map[string]string{"move.key": keyA, "move-bundle.pem": cert + keyA} {
			q, staged := dir+"/"+name, dir+"/staged.key"
			opsFile(t, q, existing, 0o600)
			opsFile(t, staged, keyD, 0o600)
			d := approved(t, "shell_move_path", map[string]any{"source": staged, "destination": q, "overwrite": true}, sha(existing))
			if readFile(t, q) != keyD || d["replaced"] != true {
				t.Fatalf("%s: move %v", name, d)
			}
			if _, err := os.Lstat(staged); !os.IsNotExist(err) {
				t.Fatalf("the staged key is still there: %v", err)
			}
		}
	})

	t.Run("the destination swapped after approval is refused", func(t *testing.T) {
		q, staged := dir+"/swap.key", dir+"/staged.key"
		opsFile(t, q, keyA, 0o600)
		opsFile(t, staged, keyB, 0o600)
		for _, c := range []struct {
			tool string
			args map[string]any
		}{
			{"shell_write_file", map[string]any{"path": q, "content": keyC}},
			{"shell_move_path", map[string]any{"source": staged, "destination": q, "overwrite": true}},
		} {
			opsFile(t, q, keyA, 0o600)
			id := pendingID(t, call(c.tool, c.args))
			page(id)
			srv.decide(t, h, id, "approve")
			opsFile(t, q, keyD, 0o600)
			refusal(t, call(c.tool, withApproval(c.args, id)), "approval_invalid", "changed since approval")
			if readFile(t, q) != keyD || readFile(t, staged) != keyB {
				t.Fatalf("%s: a swapped key was replaced", c.tool)
			}
		}
	})

	t.Run("other new content than approved is refused", func(t *testing.T) {
		opsFile(t, p, keyA, 0o600)
		id := pendingID(t, call("shell_write_file", map[string]any{"path": p, "content": keyB}))
		srv.decide(t, h, id, "approve")
		refusal(t, call("shell_write_file", withApproval(map[string]any{"path": p, "content": keyC}, id)), "approval_invalid", "")
		if readFile(t, p) != keyA {
			t.Fatal("the key was replaced with unapproved content")
		}
	})

	t.Run("read_file still refuses the key", func(t *testing.T) {
		refusal(t, call("shell_read_file", map[string]any{"path": p}), "path_denied", "private key")
	})

	t.Run("a copy source holding a key past its first 64 KiB is refused", func(t *testing.T) {
		src, dst := dir+"/late.log", dir+"/late.copy"
		opsFile(t, src, strings.Repeat("log line of ordinary text\n", 4000)+keyB+"after\n", 0o640)
		_ = os.Remove(dst)
		args := map[string]any{"source": src, "destination": dst}
		id := pendingID(t, call("shell_copy_path", args))
		page(id)
		srv.decide(t, h, id, "approve")
		refusal(t, call("shell_copy_path", withApproval(args, id)), "path_denied", "private key")
		if _, err := os.Lstat(dst); !os.IsNotExist(err) {
			t.Fatalf("copied: %v", err)
		}
	})

	t.Run("no key in any result, page, log or journal line", func(t *testing.T) {
		time.Sleep(time.Second)
		for i, s := range seen {
			if l := keyLeak(s, bodies...); l != "" {
				t.Fatalf("result or page %d shows a key (%q): %s", i, l, s)
			}
		}
		if l := keyLeak(srv.log.String(), bodies...); l != "" {
			t.Fatalf("the server log shows a key (%q)", l)
		}
		for _, e := range journal(t, "shell-mcp-gate", start) {
			if l := keyLeak(e.Message, bodies...); l != "" {
				t.Fatalf("a gate journal line shows a key (%q): %s", l, e.Message)
			}
		}
		// hash_file's journal line names the path, never a hash.
		e := findJournal(t, "shell-mcp-gate", start, `"op":"hash_file"`, p)
		for _, k := range []string{keyA, keyB, keyC, keyD} {
			if strings.Contains(e.Message, sha(k)) {
				t.Fatalf("hash_file's journal line carries a hash: %s", e.Message)
			}
		}
	})
}
