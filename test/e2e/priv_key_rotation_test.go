//go:build e2e && linux

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Rotating a private key end to end (handoff N-5, the private-key half;
// S6-4): the real server (admin profile, web approval with a simulated
// human), the real gate and the real helper in its core unit. The preview
// hashes the old key through priv_hash_file; the approval binds both keys'
// hashes; neither key appears in a tool result, an approval page, the
// server's log, the gate's or the helper's journal, or the backup listing.
// The keys are generated for each run; every path is invented.

// e2eKey is a newly generated PEM private key (PKCS #8) and its base64
// body lines.
func e2eKey(t *testing.T) (pemText string, body []string) {
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

// keyLeak returns the first body line (or PEM header) found in s, or "".
func keyLeak(s string, bodies ...[]string) string {
	for _, b := range bodies {
		for _, l := range b {
			if strings.Contains(s, l) {
				return l
			}
		}
	}
	if strings.Contains(s, "-----BEGIN") {
		return "-----BEGIN"
	}
	return ""
}

func TestPrivKeyRotation(t *testing.T) {
	srv, h := privWriteServer(t)
	conn := connOf(t, srv.cs)
	start := time.Now()
	dir := privWriteDir + "/tls"
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
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
	p := dir + "/server.key"
	rootFile(t, p, keyA, 0o600)
	var firstBackup string

	t.Run("rotation: approved with hashes only, run once, old key backed up root-only", func(t *testing.T) {
		args := map[string]any{"path": p, "content": keyB}
		id := pendingID(t, call("shell_priv_write_file", args))
		pg := page(id)
		if !strings.Contains(pg, "private key, not shown") || !strings.Contains(pg, sha(keyA)) || !strings.Contains(pg, sha(keyB)) {
			t.Fatalf("the approval page does not show both keys' hashes, masked: %s", pg)
		}
		srv.decide(t, h, id, "approve")
		d := okDataAs(t, call("shell_priv_write_file", withApproval(args, id)), "e2e-ssh")
		ids, _ := d["backup_ids"].([]any)
		if readFile(t, p) != keyB || d["old_sha256"] != sha(keyA) || d["new_sha256"] != sha(keyB) || d["mode"] != "0600" || len(ids) != 1 {
			t.Fatalf("rotation %v", d)
		}
		firstBackup, _ = ids[0].(string)
		if m := backupMeta(t, firstBackup); m["sha256"] != sha(keyA) || m["preview_sha256"] != sha(keyA) {
			t.Fatalf("backup metadata %v", m)
		}
		fi, err := os.Stat(filepath.Join(backupDir, firstBackup+".data"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("backup data %v %v", fi, err)
		}
		refusal(t, call("shell_priv_write_file", withApproval(args, id)), "approval_invalid", "")
		time.Sleep(time.Second)
		if n := helperLines(t, conn, "priv_write_file", p); n != 1 {
			t.Fatalf("%d helper write lines, want 1", n)
		}
	})

	t.Run("the key is never read back", func(t *testing.T) {
		refusal(t, call("shell_priv_read_file", map[string]any{"path": p}), "path_denied", "private key")
		d := okDataAs(t, call("shell_priv_list_backups", map[string]any{"path": p}), "e2e-ssh")
		if bs, _ := d["backups"].([]any); len(bs) == 0 {
			t.Fatalf("backups %v", d)
		}
	})

	t.Run("the old key swapped after approval is refused", func(t *testing.T) {
		args := map[string]any{"path": p, "content": keyC}
		id := pendingID(t, call("shell_priv_write_file", args))
		page(id)
		srv.decide(t, h, id, "approve")
		rootFile(t, p, keyD, 0o600)
		refusal(t, call("shell_priv_write_file", withApproval(args, id)), "approval_invalid", "changed since approval")
		if readFile(t, p) != keyD {
			t.Fatal("the swapped key was replaced")
		}
	})

	t.Run("other new content than approved is refused", func(t *testing.T) {
		id := pendingID(t, call("shell_priv_write_file", map[string]any{"path": p, "content": keyB}))
		srv.decide(t, h, id, "approve")
		refusal(t, call("shell_priv_write_file", withApproval(map[string]any{"path": p, "content": keyC}, id)), "approval_invalid", "")
		if readFile(t, p) != keyD {
			t.Fatal("the key was replaced with unapproved content")
		}
	})

	t.Run("a certificate bundle holding a key is overwritten with hashes only", func(t *testing.T) {
		q := dir + "/bundle.pem"
		bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + keyC
		rootFile(t, q, bundle, 0o640)
		args := map[string]any{"path": q, "content": "# the key moved to its own file\n"}
		id := pendingID(t, call("shell_priv_write_file", args))
		if pg := page(id); !strings.Contains(pg, sha(bundle)) {
			t.Fatal("the approval page does not show the bundle's hash")
		}
		srv.decide(t, h, id, "approve")
		okDataAs(t, call("shell_priv_write_file", withApproval(args, id)), "e2e-ssh")
		if readFile(t, q) != "# the key moved to its own file\n" {
			t.Fatal("not written")
		}
	})

	t.Run("restore brings the old key back without showing it", func(t *testing.T) {
		args := map[string]any{"backup_id": firstBackup}
		id := pendingID(t, call("shell_priv_restore_backup", args))
		seen = append(seen, srv.page(t, id))
		srv.decide(t, h, id, "approve")
		okDataAs(t, call("shell_priv_restore_backup", withApproval(args, id)), "e2e-ssh")
		if readFile(t, p) != keyA {
			t.Fatal("the old key was not restored")
		}
	})

	t.Run("rule R still applies to a key", func(t *testing.T) {
		appDir := "/etc/example-app/e2e-key-app"
		freshDir(t, appDir, exampleApp, 0o755)
		// Root's key under the account's directory: priv_hash_file keeps the
		// moved-in read rule, so it is refused before rule R, as the read
		// was (the account could have moved it there).
		k := appDir + "/server.key"
		rootFile(t, k, keyA, 0o600)
		env := call("shell_priv_write_file", map[string]any{"path": k, "content": keyB})
		refusal(t, env, "path_denied", "is not read as root")
		noApproval(t, env)
		// The account's own key passes the read rule; giving it root's owner
		// is rule R's refusal, at the preview, with no approval requested.
		own := appDir + "/own.key"
		rootFile(t, own, keyC, 0o600)
		if err := os.Chown(own, exampleApp, exampleApp); err != nil {
			t.Fatal(err)
		}
		env = call("shell_priv_write_file", map[string]any{"path": own, "content": keyB, "owner": "root", "group": "root"})
		refusal(t, env, "path_denied", "is not left there as root")
		noApproval(t, env)
		if readFile(t, k) != keyA || readFile(t, own) != keyC {
			t.Fatal("changed")
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
		for _, ident := range []string{"shell-mcp-gate", "shell-mcp-privd"} {
			for _, e := range journal(t, ident, start) {
				if l := keyLeak(e.Message, bodies...); l != "" {
					t.Fatalf("a %s journal line shows a key (%q): %s", ident, l, e.Message)
				}
			}
		}
		// priv_hash_file's journal line names the path, never a hash.
		e := findJournal(t, "shell-mcp-privd", start, `"op":"priv_hash_file"`, p)
		for _, k := range []string{keyA, keyB, keyC, keyD} {
			if strings.Contains(e.Message, sha(k)) {
				t.Fatalf("priv_hash_file's journal line carries a hash: %s", e.Message)
			}
		}
	})
}

// TestWriteKeyMaskedOnApprovalPage: shell_write_file (the gate's write,
// operator tier gated) shows a private-key block in its content as the
// block's size and hash on the approval page, and the rest of the content
// as it is, so a key cannot hide the lines around it; it writes the
// content approved.
func TestWriteKeyMaskedOnApprovalPage(t *testing.T) {
	opsServer(t)
	h := newHuman(t, singleApprover)
	srv := startApprovalServer(t, h, h.file(t), freeLoopbackPort(t))
	t.Cleanup(func() { _ = srv.cs.Close() })
	pemKey, body := e2eKey(t)
	head, tail := "listen: 0.0.0.0:8443\ntls_key: |\n", "admin_token_file: /etc/example-app/token\n"
	content := head + pemKey + tail
	block := strings.TrimSuffix(pemKey, "\n")
	p := opsWork + "/e2e-client.conf"
	_ = os.Remove(p)
	t.Cleanup(func() { _ = os.Remove(p) })
	args := map[string]any{"path": p, "content": content}
	first := srv.callTool(t, "shell_write_file", args)
	id := pendingID(t, first)
	pg := srv.page(t, id)
	mask := "private key, not shown: " + strconv.Itoa(len(block)) + " bytes, sha256 " + sha(block)
	for _, want := range []string{mask, "listen: 0.0.0.0:8443", "tls_key: |", "admin_token_file: /etc/example-app/token"} {
		if !strings.Contains(pg, want) {
			t.Fatalf("the approval page does not show %q: %s", want, pg)
		}
	}
	srv.decide(t, h, id, "approve")
	env := srv.callTool(t, "shell_write_file", withApproval(args, id))
	okDataAs(t, env, opsWho)
	if readFile(t, p) != content {
		t.Fatal("not written as approved")
	}
	for i, s := range []string{asJSON(first), pg, asJSON(env), srv.log.String()} {
		if l := keyLeak(s, body); l != "" {
			t.Fatalf("output %d shows the key (%q)", i, l)
		}
	}
}
