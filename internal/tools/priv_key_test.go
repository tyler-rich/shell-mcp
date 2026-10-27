package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// Rotating a private key (handoff N-5, the private-key half; S6-4): an
// existing privileged destination is hashed through priv_hash_file, which
// answers its size, SHA-256, line count and private_key, never its content,
// so a write, copy or move over a file holding a private key can be
// approved. A private key in any tool's arguments is masked on the approval
// page while the arguments hash still binds it. Keys are generated for each
// run; every path is invented.

// testPrivateKey is a newly generated PEM private key (PKCS #8) and its
// base64 body lines: the sentinel that must not reach the client, the
// approval page or a log.
func testPrivateKey(t *testing.T) (pemText string, body []string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemText = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	lines := strings.Split(strings.TrimSpace(pemText), "\n")
	return pemText, lines[1 : len(lines)-1]
}

// noKey fails when s holds a line of any of the bodies, or a PEM header.
func noKey(t *testing.T, what, s string, bodies ...[]string) {
	t.Helper()
	for _, b := range bodies {
		for _, l := range b {
			if strings.Contains(s, l) {
				t.Fatalf("%s shows a private key: %s", what, s)
			}
		}
	}
	if strings.Contains(s, "-----BEGIN") {
		t.Fatalf("%s shows a PEM block: %s", what, s)
	}
}

// keyOnDisk makes privConf hold content as the helper sees it:
// priv_read_file refuses it (it holds a private key), priv_hash_file
// hashes it.
func keyOnDisk(g *recordingGate, content string) {
	g.set("priv_read_file", gateReply{code: "path_denied", msg: "file contains a private key"})
	g.set("priv_hash_file", gateReply{data: hashReply(content, true)})
}

func hashReply(content string, key bool) string {
	return fmt.Sprintf(`{"path":%q,"size":%d,"sha256":%q,"binary":false,"lines":%d,"private_key":%v}`,
		privConf, len(content), sha(content), strings.Count(content, "\n"), key)
}

// recordText is everything the approval page shows of a record.
func recordText(a *approvalHarness, id string) string {
	r, _ := a.store.Get(id)
	b, _ := json.Marshal(struct {
		D          string
		Args, Prev []approval.Field
	}{r.Description, r.Args, r.Preview})
	return string(b)
}

func envText(env map[string]any) string {
	b, _ := json.Marshal(env)
	return string(b)
}

// TestPrivWriteOverPrivateKey: a write, copy or move over a file that
// holds a private key (a key file, or a certificate bundle with its key)
// is approvable; the preview binds the file's hash and says it is a
// private key; the re-call runs once with that hash as its precondition;
// neither key reaches the client, the approval record or the log.
func TestPrivWriteOverPrivateKey(t *testing.T) {
	oldKey, oldBody := testPrivateKey(t)
	newKey, newBody := testPrivateKey(t)
	bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + oldKey
	for kind, existing := range map[string]string{"key": oldKey, "bundle": bundle} {
		for _, name := range []string{"shell_priv_write_file", "shell_priv_copy_path", "shell_priv_move_path"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				a := newPrivWriteHarness(t, approval.MethodWeb)
				keyOnDisk(a.g, existing)
				args := privWriteArgs[name]
				where, op := "destination", privWriteOp[name]
				if name == "shell_priv_write_file" {
					args, where = map[string]any{"path": privConf, "content": newKey}, "current"
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
				if name == "shell_priv_write_file" && (pv["new.private_key"] != "true" || pv["new.sha256"] != sha(newKey)) {
					t.Fatalf("preview of the new content %v", pv)
				}
				a.approve(id)
				env, _ := a.call(name, withID(args, id))
				if env["ok"] != true {
					t.Fatalf("approved re-call: %v", env)
				}
				w := a.g.args(t, op)
				want := "expected_destination_sha256"
				if name == "shell_priv_write_file" {
					want = "expected_sha256"
				}
				if w[want] != sha(existing) {
					t.Fatalf("%s precondition %v", op, w)
				}
				again, _ := a.call(name, withID(args, id))
				if errCode(again) != "approval_invalid" || len(a.privMutatingOps()) != 1 {
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

// TestPrivKeyRotationBindings: other content than approved, or an old key
// swapped after approval, is approval_invalid, and nothing is sent.
func TestPrivKeyRotationBindings(t *testing.T) {
	oldKey, _ := testPrivateKey(t)
	newKey, _ := testPrivateKey(t)
	otherKey, _ := testPrivateKey(t)
	args := map[string]any{"path": privConf, "content": newKey}
	t.Run("changed new content", func(t *testing.T) {
		a := newPrivWriteHarness(t, approval.MethodWeb)
		keyOnDisk(a.g, oldKey)
		id := a.pending("shell_priv_write_file", args)
		a.approve(id)
		env, _ := a.call("shell_priv_write_file", withID(map[string]any{"path": privConf, "content": otherKey}, id))
		if errCode(env) != "approval_invalid" || len(a.privMutatingOps()) != 0 {
			t.Fatalf("re-call with other content: %v, sent %v", env, a.g.ops())
		}
	})
	t.Run("old key swapped after approval", func(t *testing.T) {
		a := newPrivWriteHarness(t, approval.MethodWeb)
		keyOnDisk(a.g, oldKey)
		id := a.pending("shell_priv_write_file", args)
		a.approve(id)
		a.g.set("priv_hash_file", gateReply{data: hashReply(otherKey, true)})
		env, _ := a.call("shell_priv_write_file", withID(args, id))
		if errCode(env) != "approval_invalid" || len(a.privMutatingOps()) != 0 {
			t.Fatalf("re-call after a swap: %v, sent %v", env, a.g.ops())
		}
	})
}

// TestApprovalMasksPrivateKeyArgs: a private key in a write's content is
// shown on the approval page as its size and SHA-256 only, for both write
// tools; the approved re-call sends the real content, which the arguments
// hash bound.
func TestApprovalMasksPrivateKeyArgs(t *testing.T) {
	key, body := testPrivateKey(t)
	for _, name := range []string{"shell_write_file", "shell_priv_write_file"} {
		t.Run(name, func(t *testing.T) {
			var a *approvalHarness
			p := "/srv/app/config/app.yaml"
			if name == "shell_write_file" {
				a = newApprovalHarness(t, approval.MethodWeb)
			} else {
				a, p = newPrivWriteHarness(t, approval.MethodWeb), privConf
				privAbsent(a.g, p)
			}
			args := map[string]any{"path": p, "content": key}
			id := a.pending(name, args)
			r, _ := a.store.Get(id)
			var content string
			for _, f := range r.Args {
				if f.Key == "content" {
					content = f.Value
				}
			}
			if want := fmt.Sprintf("private key, not shown: %d bytes, sha256 %s", len(key), sha(key)); content != want {
				t.Fatalf("content field %q, want %q", content, want)
			}
			noKey(t, "approval record", recordText(a, id), body)
			a.approve(id)
			if env, _ := a.call(name, withID(args, id)); env["ok"] != true {
				t.Fatalf("approved re-call: %v", env)
			}
			op := map[string]string{"shell_write_file": "write_file", "shell_priv_write_file": "priv_write_file"}[name]
			w := a.g.args(t, op)
			got, _ := w["content_b64"].(string)
			b, _ := base64.StdEncoding.DecodeString(got)
			if string(b) != key {
				t.Fatalf("the write sent other content: %v", w)
			}
		})
	}
}

// TestPrivKeyOwnerRuleStillApplies: rule R refuses an overwrite of a key
// that keeps an owner root may not leave there, before an approval is
// requested, as for any file.
func TestPrivKeyOwnerRuleStillApplies(t *testing.T) {
	oldKey, _ := testPrivateKey(t)
	newKey, _ := testPrivateKey(t)
	a := newPrivWriteHarness(t, approval.MethodWeb)
	keyOnDisk(a.g, oldKey)
	a.g.set("priv_backup_check", backupCheckWith(ruleOnlyApp))
	env, _ := a.call("shell_priv_write_file", map[string]any{"path": privConf, "content": newKey})
	if errCode(env) != "path_denied" || env["approval"] != nil || !strings.Contains(envText(env), "example-app") {
		t.Fatalf("rule R over a key: %v", env)
	}
	if len(a.privMutatingOps()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestWriteDescriptionsNameTheClient: both write tools say that content
// they write came from the client, and that private keys are better
// generated on the host.
func TestWriteDescriptionsNameTheClient(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range reg.ToolsForProfile(ProfileAdmin, nil) {
		d := r.Tool.Def
		if d.Name != "shell_write_file" && d.Name != "shell_priv_write_file" {
			continue
		}
		seen++
		if !strings.Contains(d.Description, "private key") || !strings.Contains(d.Description, "on the host") {
			t.Fatalf("%s: %q", d.Name, d.Description)
		}
	}
	if seen != 2 {
		t.Fatalf("%d write tools found", seen)
	}
}
