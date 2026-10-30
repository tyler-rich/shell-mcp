package tools

import (
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// The gate's write, copy and move over a file holding a private key
// (handoff N-5, the gate's half; S7-3), with operator tools gated: an
// existing destination is hashed through the gate's hash_file, which
// answers its size, SHA-256, line count and private_key, never its
// content, as the privileged tools' previews use priv_hash_file. Keys are
// generated for each run; every path is invented.

// gateKeyOnDisk makes the destination hold content as the gate sees it:
// read_file refuses it (it holds a private key), hash_file hashes it.
func gateKeyOnDisk(g *recordingGate, content string) {
	g.set("read_file", gateReply{code: "path_denied", msg: "file contains a private key"})
	g.set("hash_file", gateReply{data: fakeHashSHA(content, sha(content), true)})
}

var gateWriteOp = map[string]string{"shell_write_file": "write_file", "shell_copy_path": "copy", "shell_move_path": "move"}

// TestGateWriteOverPrivateKey: a write, copy or move over a file that
// holds a private key (a key file, or a certificate bundle with its key)
// is approvable; the preview binds the file's hash and says it is a
// private key; the re-call runs once with that hash as its precondition;
// a second re-call is approval_invalid; no key reaches the client, the
// approval record or the log.
func TestGateWriteOverPrivateKey(t *testing.T) {
	oldKey, oldBody := testPrivateKey(t)
	newKey, newBody := testPrivateKey(t)
	bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + oldKey
	for kind, existing := range map[string]string{"key": oldKey, "bundle": bundle} {
		for name, op := range gateWriteOp {
			t.Run(name+"/"+kind, func(t *testing.T) {
				a := newApprovalHarness(t, approval.MethodWeb)
				gateKeyOnDisk(a.g, existing)
				args, where, want := bindArgs(true), "destination", "expected_destination_sha256"
				if name == "shell_write_file" {
					args, where, want = map[string]any{"path": bindDst, "content": newKey}, "current", "expected_sha256"
				}
				first, _ := a.call(name, args)
				if errCode(first) != "approval_pending" {
					t.Fatalf("first call: %v", first)
				}
				id, _ := approvalOf(t, first)["id"].(string)
				pv := previewMap(t, a, id)
				if pv[where+".private_key"] != "true" || pv[where+".sha256"] != sha(existing) || pv[where+".state"] != "file" {
					t.Fatalf("preview %v", pv)
				}
				if name == "shell_write_file" && (pv["new.private_key"] != "true" || pv["new.sha256"] != sha(newKey)) {
					t.Fatalf("preview of the new content %v", pv)
				}
				a.approve(id)
				env, _ := a.call(name, withID(args, id))
				if env["ok"] != true {
					t.Fatalf("approved re-call: %v", env)
				}
				if w := a.g.args(t, op); w[want] != sha(existing) {
					t.Fatalf("%s precondition %v", op, w)
				}
				again, _ := a.call(name, withID(args, id))
				if errCode(again) != "approval_invalid" || len(a.mutatingOps()) != 1 {
					t.Fatalf("second re-call: %v (sent %v)", again, a.g.ops())
				}
				for what, s := range map[string]string{
					"first call": envText(first), "re-call": envText(env), "second re-call": envText(again),
					"approval record": recordText(a, id), "log": a.logs.String(),
				} {
					noKey(t, what, s, oldBody, newBody)
				}
			})
		}
	}
}

// TestGateKeyRotationBindings: other content than approved, or a key
// destination swapped after approval, is approval_invalid and nothing is
// sent; a swap between the fresh preview and the commit is the gate's
// exists, passed through, with the approved hash as the precondition.
func TestGateKeyRotationBindings(t *testing.T) {
	oldKey, _ := testPrivateKey(t)
	newKey, _ := testPrivateKey(t)
	otherKey, _ := testPrivateKey(t)
	args := map[string]any{"path": bindDst, "content": newKey}
	t.Run("changed new content", func(t *testing.T) {
		a := newApprovalHarness(t, approval.MethodWeb)
		gateKeyOnDisk(a.g, oldKey)
		id := a.pending("shell_write_file", args)
		a.approve(id)
		env, _ := a.call("shell_write_file", withID(map[string]any{"path": bindDst, "content": otherKey}, id))
		if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 0 {
			t.Fatalf("re-call with other content: %v, sent %v", env, a.g.ops())
		}
	})
	for name, op := range gateWriteOp {
		callArgs := bindArgs(true)
		if name == "shell_write_file" {
			callArgs = args
		}
		t.Run(name+"/destination swapped after approval", func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			gateKeyOnDisk(a.g, oldKey)
			id := a.pending(name, callArgs)
			a.approve(id)
			gateKeyOnDisk(a.g, otherKey)
			env, _ := a.call(name, withID(callArgs, id))
			if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 0 {
				t.Fatalf("re-call after a swap: %v, sent %v", env, a.g.ops())
			}
		})
		t.Run(name+"/destination swapped before the commit", func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			gateKeyOnDisk(a.g, oldKey)
			a.g.set(op, gateReply{code: "exists", msg: "the file changed after it was checked; nothing was changed"})
			id := a.pending(name, callArgs)
			a.approve(id)
			env, _ := a.call(name, withID(callArgs, id))
			w := a.g.args(t, op)
			if errCode(env) != "exists" || w["expected_sha256"] != sha(oldKey) && w["expected_destination_sha256"] != sha(oldKey) {
				t.Fatalf("swap before the commit: %v, sent %v", env, w)
			}
		})
	}
}

// TestGateWritePreviewUnhashable (S7-3, decision (a)): a gated write over
// an existing file the gate gives no hash for (above 256 MiB) is refused
// at its preview with too_large, as copy and move are, and is never sent
// without expected_sha256 or expect_absent.
func TestGateWritePreviewUnhashable(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	a.g.set("stat", gateReply{data: strings.Replace(fakeFileStat, `"size":11`, `"size":300000000`, 1)})
	a.g.set("read_file", gateReply{data: `{"path":"/srv/app/config/app.yaml","size":300000000,"binary":false,"content":"head\n","offset":0,"truncated":true}`})
	a.g.set("hash_file", gateReply{code: "too_large", msg: "the file is larger than the 256 MiB that is hashed"})
	env, _ := a.call("shell_write_file", writeArgs)
	if errCode(env) != "too_large" || env["approval"] != nil || len(a.mutatingOps()) != 0 {
		t.Fatalf("a write over an unhashable file: %v, sent %v", env, a.g.ops())
	}
	if msg := envText(env); !strings.Contains(msg, "256 MiB") || !strings.Contains(msg, "gate") {
		t.Fatalf("message %s", msg)
	}
}
