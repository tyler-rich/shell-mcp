//go:build linux

package ops_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// selfSigned returns an invented certificate and its key as PEM, generated
// at test time.
func selfSigned(t *testing.T, cn string, days int) (certPEM, keyPEM string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE" + " KEY", Bytes: kd}))
}

func TestCertInspect(t *testing.T) {
	f := newFixture(t, "read")
	cert, key := selfSigned(t, "app.example.test", 20)
	gatetest.WriteFile(t, filepath.Join(f.read, "tls", "cert.pem"), cert, 0o644)
	gatetest.WriteFile(t, filepath.Join(f.read, "tls", "combined.pem"), cert+key, 0o644)
	gatetest.WriteFile(t, filepath.Join(f.read, "tls", "notes.txt"), "no certificates here\n", 0o644)

	var d struct {
		Path         string `json:"path"`
		Format       string `json:"format"`
		Certificates []struct {
			Subject       string   `json:"subject"`
			DNSNames      []string `json:"dns_names"`
			DaysRemaining int      `json:"days_remaining"`
			KeyType       string   `json:"key_type"`
			SHA256        string   `json:"sha256"`
		} `json:"certificates"`
	}
	f.ok("cert_inspect", m{"path": filepath.Join(f.read, "tls", "cert.pem")}, &d)
	if d.Format != "pem" || len(d.Certificates) != 1 || d.Certificates[0].Subject != "CN=app.example.test" ||
		d.Certificates[0].DaysRemaining != 20 || d.Certificates[0].KeyType != "ECDSA" || len(d.Certificates[0].SHA256) != 64 {
		t.Fatalf("cert %+v", d)
	}
	// A file holding a private key is refused, and nothing of it is echoed.
	r := f.call("cert_inspect", m{"path": filepath.Join(f.read, "tls", "combined.pem")})
	if r.OK || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, "private key") || len(r.Data) != 0 {
		t.Fatalf("combined: %+v %s", r.Error, r.Data)
	}
	body := strings.Split(strings.TrimSpace(key), "\n")[1]
	if strings.Contains(r.Error.Message, body[:16]) || strings.Contains(r.Error.Message, "BEGIN") {
		t.Fatalf("message echoes the file: %q", r.Error.Message)
	}
	f.fail("cert_inspect", m{"path": filepath.Join(f.read, "tls", "notes.txt")}, "bad_request")
	f.fail("cert_inspect", m{"path": filepath.Join(f.secrets, "token")}, "path_denied")
	f.fail("cert_inspect", m{"path": filepath.Join(f.read, "tls")}, "is_a_directory")
	f.fail("cert_inspect", m{"path": filepath.Join(f.read, "tls", "missing.pem")}, "not_found")
	f.fail("cert_inspect", m{}, "bad_request")
}
