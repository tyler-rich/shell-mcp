//go:build linux

package ops_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// hash_file (handoff N-5, the gate's half; S7-3): the gate's twin of the
// helper's priv_hash_file. A file's size, SHA-256, line count and whether
// it holds a private key, under read_file's path rules, never its content,
// so the gate's write, copy and move previews can bind a destination that
// holds a key. Keys are generated for each run; every path is invented.

// gateKey returns a newly generated PEM private key (PKCS #8) and its base64
// body, the sentinel that must never leave the gate.
func gateKey(t testing.TB) (pemText, body string) {
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

// keyLeaks reports whether s holds any line of the key's body, or a PEM
// header.
func keyLeaks(s, body string) bool {
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(s, l) {
			return true
		}
	}
	return strings.Contains(s, "-----BEGIN")
}

func hexSHA(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type gateHash struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Binary     bool   `json:"binary"`
	Lines      *int   `json:"lines"`
	PrivateKey bool   `json:"private_key"`
}

func TestHashFile(t *testing.T) {
	f := newFixture(t, "read") // a read-tier op: allowed under max_tier read
	next := f.auditTo(t)
	key, body := gateKey(t)
	bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + key
	tls := filepath.Join(f.write, "tls")
	gatetest.Mkdir(t, tls, 0o755)
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
		p := filepath.Join(tls, c.name)
		gatetest.WriteFile(t, p, c.content, 0o600)
		var h gateHash
		r := f.ok("hash_file", m{"path": p}, &h)
		if h.Path != p || h.Size != int64(len(c.content)) || h.SHA256 != hexSHA(c.content) || h.PrivateKey != c.key || h.Binary != c.binary {
			t.Fatalf("%s: %+v", c.name, h)
		}
		if (c.lines < 0) != (h.Lines == nil) || h.Lines != nil && *h.Lines != c.lines {
			t.Fatalf("%s: lines %v, want %d", c.name, h.Lines, c.lines)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(r.Data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["content"]; ok || keyLeaks(string(r.Data), body) || len(r.Warnings) != 0 {
			t.Fatalf("%s: answer %s %v", c.name, r.Data, r.Warnings)
		}
		// The audit line names the op and the path, never a hash or content.
		a := next()
		if !strings.Contains(a, `"op":"hash_file"`) || !strings.Contains(a, p) || strings.Contains(a, h.SHA256) || keyLeaks(a, body) {
			t.Fatalf("%s: audit %s", c.name, a)
		}
	}
	// read_file still refuses the key.
	f.fail("read_file", m{"path": filepath.Join(tls, "server.key")}, "path_denied")
	next()

	// read_file's path rules: the policy and built-in deny lists, outside
	// the roots, unclean, a directory, a symlink, absent, unknown fields.
	gatetest.WriteFile(t, filepath.Join(f.read, ".ssh", "id_ed25519"), key, 0o600)
	gatetest.WriteFile(t, filepath.Join(f.dir, "outside.txt"), "outside\n", 0o644)
	if err := os.Symlink(filepath.Join(tls, "server.key"), filepath.Join(tls, "link.key")); err != nil {
		t.Fatal(err)
	}
	for p, code := range map[string]string{
		filepath.Join(f.secrets, "token"):           "path_denied",
		filepath.Join(f.read, ".ssh", "id_ed25519"): "path_denied",
		filepath.Join(f.dir, "outside.txt"):         "path_denied",
		f.write + "/../config/app.conf":             "bad_request",
		tls:                                         "is_a_directory",
		filepath.Join(tls, "link.key"):              "path_denied",
		filepath.Join(tls, "missing.key"):           "not_found",
	} {
		f.fail("hash_file", m{"path": p}, code)
		next()
	}
	f.fail("hash_file", m{"path": filepath.Join(tls, "app.conf"), "max_bytes": 1}, "bad_request")
	next()

	// Above 256 MiB: too_large (the cap stays).
	sparse := filepath.Join(tls, "sparse.bin")
	gatetest.WriteFile(t, sparse, "", 0o600)
	if err := os.Truncate(sparse, 300<<20); err != nil {
		t.Fatal(err)
	}
	f.fail("hash_file", m{"path": sparse}, "too_large")
}

// TestHashFileListedAfterReadFile: hello lists hash_file right after
// read_file, at every max_tier (it is read tier).
func TestHashFileListedAfterReadFile(t *testing.T) {
	for _, tier := range []string{"read", "destructive"} {
		f := newFixture(t, tier)
		var hello struct {
			Ops []string `json:"ops"`
		}
		f.ok("hello", m{}, &hello)
		i := slices.Index(hello.Ops, "read_file")
		if i < 0 || i+1 >= len(hello.Ops) || hello.Ops[i+1] != "hash_file" {
			t.Fatalf("max_tier %s: ops %v", tier, hello.Ops)
		}
	}
}

// TestGateKeyRotation: a write, copy or move over a file holding a private
// key (a key file, or a certificate bundle with its key), bound to the hash
// hash_file gave, commits; bound to an old hash after the destination
// changed, it is exists and nothing changes; nothing of any key is in an
// answer or an audit line.
func TestGateKeyRotation(t *testing.T) {
	f := newFixture(t, "operator")
	next := f.auditTo(t)
	oldKey, oldBody := gateKey(t)
	newKey, newBody := gateKey(t)
	otherKey, otherBody := gateKey(t)
	bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + oldKey
	tls := filepath.Join(f.write, "tls")
	gatetest.Mkdir(t, tls, 0o755)
	var answers, audits []string
	call := func(op string, args m, code string) response {
		t.Helper()
		r := f.call(op, args)
		answers = append(answers, string(r.Data))
		if r.Error != nil {
			answers = append(answers, r.Error.Message)
		}
		audits = append(audits, next())
		if code == "" && !r.OK || code != "" && (r.OK || r.Error.Code != code) {
			t.Fatalf("%s(%v): %+v %s, want %q", op, args, r.Error, r.Data, code)
		}
		return r
	}
	hashOf := func(p string) string {
		t.Helper()
		var h gateHash
		if err := json.Unmarshal(call("hash_file", m{"path": p}, "").Data, &h); err != nil || !h.PrivateKey {
			t.Fatalf("hash_file %s: %+v %v", p, h, err)
		}
		return h.SHA256
	}
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	newB64 := base64.StdEncoding.EncodeToString([]byte(newKey))

	for kind, existing := range map[string]string{"key": oldKey, "bundle": bundle} {
		t.Run("write over a "+kind, func(t *testing.T) {
			p := filepath.Join(tls, "write-"+kind+".pem")
			gatetest.WriteFile(t, p, existing, 0o600)
			sum := hashOf(p)
			call("write_file", m{"path": p, "content_b64": newB64, "expected_sha256": sum}, "")
			if read(p) != newKey {
				t.Fatal("not written")
			}
			// Bound to the hash it had: the file changed since, so exists.
			call("write_file", m{"path": p, "content_b64": base64.StdEncoding.EncodeToString([]byte(otherKey)), "expected_sha256": sum}, "exists")
			if read(p) != newKey {
				t.Fatal("a stale write replaced the key")
			}
		})
		t.Run("copy over a "+kind, func(t *testing.T) {
			p := filepath.Join(tls, "copy-"+kind+".pem")
			src := filepath.Join(tls, "cert-only.pem")
			gatetest.WriteFile(t, p, existing, 0o600)
			gatetest.WriteFile(t, src, "-----BEGIN CERTIFICATE-----\nMIIBnew\n-----END CERTIFICATE-----\n", 0o600)
			sum := hashOf(p)
			call("copy", m{"source": src, "destination": p, "overwrite": true, "expected_destination_sha256": sum}, "")
			if read(p) != read(src) {
				t.Fatal("not copied")
			}
			gatetest.WriteFile(t, p, otherKey, 0o600) // swapped after the preview
			call("copy", m{"source": src, "destination": p, "overwrite": true, "expected_destination_sha256": sum}, "exists")
			if read(p) != otherKey {
				t.Fatal("a swapped destination was replaced")
			}
		})
		t.Run("move over a "+kind, func(t *testing.T) {
			p := filepath.Join(tls, "move-"+kind+".pem")
			staged := filepath.Join(tls, "staged.key")
			gatetest.WriteFile(t, p, existing, 0o600)
			gatetest.WriteFile(t, staged, newKey, 0o600)
			sum := hashOf(p)
			call("move", m{"source": staged, "destination": p, "overwrite": true, "expected_destination_sha256": sum}, "")
			if read(p) != newKey {
				t.Fatal("not moved")
			}
			gatetest.WriteFile(t, staged, otherKey, 0o600)
			call("move", m{"source": staged, "destination": p, "overwrite": true, "expected_destination_sha256": sum}, "exists")
			if read(p) != newKey || read(staged) != otherKey {
				t.Fatal("a stale move changed something")
			}
		})
	}
	for _, s := range append(answers, audits...) {
		for _, b := range []string{oldBody, newBody, otherBody} {
			if keyLeaks(s, b) {
				t.Fatalf("a key leaked: %s", s)
			}
		}
	}
	for _, a := range audits {
		for _, k := range []string{oldKey, newKey, otherKey, bundle} {
			if strings.Contains(a, hexSHA(k)) {
				t.Fatalf("an audit line carries a hash: %s", a)
			}
		}
	}
}
