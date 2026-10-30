//go:build linux

package ops_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// A root command's {path:read} that names a file holding a private key
// (handoff N-35): refused by priv_exec_preview and priv_exec alike unless
// the command declares reads_private_keys, whose output is then redacted
// with the width heuristic too. The key is generated for each run; every
// path is invented.

func keyCommands() opt {
	return func(f *fixture, s *string) {
		*s = strings.Replace(*s, "commands:\n", fmt.Sprintf(`commands:
  - id: key-cat
    path: %[1]s
    tier: read
    templates: [["cat", "{path:read}"]]
  - id: key-cat-allowed
    path: %[1]s
    tier: read
    reads_private_keys: true
    templates: [["cat", "{path:read}"]]
`, f.probe), 1)
	}
}

func helperKey(t *testing.T) []string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))), "\n")
}

func TestPrivExecKeyInput(t *testing.T) {
	f := newFixture(t, keyCommands())
	key := helperKey(t)
	keyFile := filepath.Join(f.read, "service.key")
	gatetest.WriteFile(t, keyFile, strings.Join(key, "\n")+"\n", 0o644)
	bare := filepath.Join(f.read, "bare.txt")
	// The probe prints "READ:" before the first line: an ordinary one.
	gatetest.WriteFile(t, bare, "an ordinary first line\n"+strings.Join(key[4:10], "\n")+"\n", 0o644)
	leaks := func(s string) bool {
		for _, l := range key[1 : len(key)-1] {
			if strings.Contains(s, l) {
				return true
			}
		}
		return false
	}
	req := m{"command_id": "key-cat", "args": []string{"cat", keyFile}}
	for _, op := range []string{"priv_exec_preview", "priv_exec"} {
		r := f.serveAt("read", op, req)
		if r.OK || r.Error == nil || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, "reads_private_keys") || leaks(string(r.Data)) {
			t.Fatalf("%s: %+v %s, want path_denied naming reads_private_keys", op, r.Error, r.Data)
		}
	}
	for _, p := range []string{keyFile, bare} {
		var d struct {
			Stdout string `json:"stdout"`
		}
		r := f.serveAt("read", "priv_exec", m{"command_id": "key-cat-allowed", "args": []string{"cat", p}})
		if !r.OK {
			t.Fatalf("%s: %+v", p, r.Error)
		}
		if err := json.Unmarshal(r.Data, &d); err != nil {
			t.Fatal(err)
		}
		if leaks(d.Stdout) || !strings.Contains(d.Stdout, "[REDACTED]") {
			t.Fatalf("%s: body shown:\n%s", p, d.Stdout)
		}
	}
	var s struct {
		Commands []struct {
			ID               string `json:"id"`
			ReadsPrivateKeys bool   `json:"reads_private_keys"`
		} `json:"commands"`
	}
	f.ok("priv_policy", m{}, &s)
	got := map[string]bool{}
	for _, c := range s.Commands {
		got[c.ID] = c.ReadsPrivateKeys
	}
	if !got["key-cat-allowed"] || got["key-cat"] {
		t.Fatalf("priv_policy reads_private_keys: %v", got)
	}
}
