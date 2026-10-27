//go:build linux

package ops_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// priv_hash_file (handoff N-5, the private-key half; S6-4): a file's size,
// SHA-256, line count and whether it holds a private key, read as root
// under priv_read_file's path rules, never its content. Keys are generated
// for each run; every path is invented.

// freshKey returns a newly generated PEM private key (PKCS #8) and its
// base64 body, the sentinel that must never leave the helper.
func freshKey(t testing.TB) (pemText, body string) {
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
	return pemText, strings.Join(lines[1:len(lines)-1], "\n")
}

// leaks reports whether s holds any line of the key's body.
func leaks(s, body string) bool {
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(s, l) {
			return true
		}
	}
	return strings.Contains(s, "-----BEGIN")
}

type hashOut struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Binary     bool   `json:"binary"`
	Lines      *int   `json:"lines"`
	PrivateKey bool   `json:"private_key"`
}

func TestPrivHashFile(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	key, body := freshKey(t)
	bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + key
	cases := []struct {
		name, content string
		key, binary   bool
		lines         int // -1: null
	}{
		{"server.key", key, true, false, strings.Count(key, "\n")},
		{"bundle.pem", bundle, true, false, strings.Count(bundle, "\n")},
		{"app.conf", "key: value\n", false, false, 1},
		{"blob.bin", "\x00\x01\x02", false, true, -1},
		{"big.txt", strings.Repeat("x\n", 40000), false, false, -1}, // above 64 KiB: not counted, as the read preview did
	}
	for _, c := range cases {
		p := filepath.Join(f.write, "tls", c.name)
		gatetest.WriteFile(t, p, c.content, 0o600)
		var h hashOut
		r := f.ok("priv_hash_file", m{"path": p}, &h)
		if h.Path != p || h.Size != int64(len(c.content)) || h.SHA256 != shaHex(c.content) || h.PrivateKey != c.key || h.Binary != c.binary {
			t.Fatalf("%s: %+v", c.name, h)
		}
		if (c.lines < 0) != (h.Lines == nil) || h.Lines != nil && *h.Lines != c.lines {
			t.Fatalf("%s: lines %v, want %d", c.name, h.Lines, c.lines)
		}
		// No content field, and nothing of the key, in the answer.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(r.Data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["content"]; ok || leaks(string(r.Data), body) || len(r.Warnings) != 0 {
			t.Fatalf("%s: answer %s %v", c.name, r.Data, r.Warnings)
		}
		// The audit line names the path, never a hash or content.
		a := f.lastAudit()
		if !strings.Contains(a, `"op":"priv_hash_file"`) || !strings.Contains(a, p) || strings.Contains(a, h.SHA256) || leaks(a, body) {
			t.Fatalf("%s: audit %s", c.name, a)
		}
	}
	// priv_read_file still refuses the key.
	f.fail("priv_read_file", m{"path": filepath.Join(f.write, "tls", "server.key")}, "path_denied")

	// priv_read_file's path rules: the policy and built-in deny lists,
	// outside the roots, unclean, a directory, a symlink, absent.
	gatetest.WriteFile(t, filepath.Join(f.read, ".ssh", "id_ed25519"), key, 0o600)
	if err := os.Symlink(filepath.Join(f.write, "tls", "server.key"), filepath.Join(f.write, "tls", "link.key")); err != nil {
		t.Fatal(err)
	}
	for p, code := range map[string]string{
		filepath.Join(f.read, "secrets", "token"):    "path_denied",
		filepath.Join(f.read, ".ssh", "id_ed25519"):  "path_denied",
		filepath.Join(f.d, "outside.txt"):            "path_denied",
		f.write + "/../example-app/app.conf":         "bad_request",
		filepath.Join(f.write, "tls"):                "is_a_directory",
		filepath.Join(f.write, "tls", "link.key"):    "path_denied",
		filepath.Join(f.write, "tls", "missing.key"): "not_found",
	} {
		f.fail("priv_hash_file", m{"path": p}, code)
	}
	f.fail("priv_hash_file", m{"path": filepath.Join(f.write, "app.conf"), "offset": 1}, "bad_request")

	// Above 256 MiB: too_large (the cap stays; the rest of N-5 is deferred).
	sparse := filepath.Join(f.write, "tls", "sparse.bin")
	gatetest.WriteFile(t, sparse, "", 0o600)
	if err := os.Truncate(sparse, 300<<20); err != nil {
		t.Fatal(err)
	}
	f.fail("priv_hash_file", m{"path": sparse}, "too_large")
}

// TestPrivKeyRotation: a key replaced through priv_write_file bound to the
// hash priv_hash_file gave; the old key is backed up root-only and listed
// as metadata only; a restore brings it back; nothing of either key is in
// an answer or an audit line.
func TestPrivKeyRotation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	oldKey, oldBody := freshKey(t)
	newKey, newBody := freshKey(t)
	p := filepath.Join(f.write, "tls", "server.key")
	gatetest.WriteFile(t, p, oldKey, 0o600)
	var answers []string
	var h hashOut
	answers = append(answers, string(f.ok("priv_hash_file", m{"path": p}, &h).Data))
	var w writeOut
	answers = append(answers, string(f.ok("priv_write_file", m{"path": p, "content_b64": b64(newKey), "expected_sha256": h.SHA256}, &w).Data))
	if readFile(t, p) != newKey || w.OldSHA256 != shaHex(oldKey) || w.SHA256 != shaHex(newKey) || len(w.BackupIDs) != 1 || w.Mode != "0600" {
		t.Fatalf("rotation %+v", w)
	}
	data := filepath.Join(f.backups, w.BackupIDs[0]+".data")
	if fi, err := os.Stat(data); err != nil || fi.Mode().Perm() != 0o600 || readFile(t, data) != oldKey {
		t.Fatalf("backup data %v %v", fi, err)
	}
	// A second write bound to the old hash is refused: the file changed.
	f.fail("priv_write_file", m{"path": p, "content_b64": b64(oldKey), "expected_sha256": h.SHA256}, "exists")
	var pv struct {
		PreviewSHA256 string `json:"preview_sha256"`
	}
	answers = append(answers, string(f.ok("priv_list_backups", m{"path": p}, nil).Data),
		string(f.ok("priv_restore_preview", m{"id": w.BackupIDs[0]}, &pv).Data))
	answers = append(answers, string(f.ok("priv_restore_backup", m{"id": w.BackupIDs[0], "expected_preview_sha256": pv.PreviewSHA256}, nil).Data))
	if readFile(t, p) != oldKey {
		t.Fatal("the restore did not bring the old key back")
	}
	for _, s := range append(answers, f.auditLines()...) {
		if leaks(s, oldBody) || leaks(s, newBody) {
			t.Fatalf("a key leaked: %s", s)
		}
	}
}
