package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// Every certificate and key here is generated at test time for invented
// names; nothing secret-shaped is committed.

var now = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

type issued struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

func issue(t testing.TB, key crypto.Signer, tpl *x509.Certificate, parent *issued) issued {
	t.Helper()
	signerCert, signerKey := tpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{der, c, key}
}

func template(cn string, serial int64, from, to time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{"Example Org"}},
		NotBefore: from, NotAfter: to}
}

type chain struct {
	ca, rsaLeaf, ecLeaf, edLeaf issued
}

func newChain(t testing.TB) chain {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTpl := template("Example Test CA", 1, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	caTpl.IsCA, caTpl.BasicConstraintsValid, caTpl.KeyUsage = true, true, x509.KeyUsageCertSign
	ca := issue(t, caKey, caTpl, nil)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := template("app.example.test", 2, now.Add(-time.Hour), now.Add(30*24*time.Hour+time.Hour))
	leafTpl.DNSNames = []string{"app.example.test", "api.example.test"}
	leafTpl.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
	leafTpl.EmailAddresses = []string{"ops@example.test"}
	u, _ := url.Parse("spiffe://example.test/app")
	leafTpl.URIs = []*url.URL{u}
	rsaLeaf := issue(t, rsaKey, leafTpl, &ca)

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecLeaf := issue(t, ecKey, template("expired.example.test", 3, now.Add(-100*24*time.Hour), now.Add(-10*24*time.Hour-time.Hour)), &ca)

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edLeaf := issue(t, edKey, template("ed.example.test", 4, now.Add(24*time.Hour), now.Add(48*time.Hour)), &ca)
	return chain{ca, rsaLeaf, ecLeaf, edLeaf}
}

func pemOf(certs ...issued) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.der})
	}
	return b.Bytes()
}

func keyPEM(t testing.TB, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE" + " KEY", Bytes: der})
}

func TestInspectPEMChain(t *testing.T) {
	c := newChain(t)
	res, err := Inspect(pemOf(c.rsaLeaf, c.ecLeaf, c.edLeaf, c.ca), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "pem" || len(res.Certificates) != 4 {
		t.Fatalf("result %+v", res)
	}
	leaf := res.Certificates[0]
	sum := sha256.Sum256(c.rsaLeaf.der)
	if leaf.Subject != "CN=app.example.test,O=Example Org" || leaf.Issuer != "CN=Example Test CA,O=Example Org" ||
		leaf.KeyType != "RSA" || leaf.KeyBits != 2048 || leaf.DaysRemaining != 30 || leaf.Expired || leaf.IsCA ||
		leaf.SHA256 != hex.EncodeToString(sum[:]) || leaf.SerialHex != "02" || leaf.Index != 0 {
		t.Fatalf("leaf %+v", leaf)
	}
	if strings.Join(leaf.DNSNames, ",") != "app.example.test,api.example.test" || strings.Join(leaf.IPAddresses, ",") != "192.0.2.10" ||
		strings.Join(leaf.EmailAddresses, ",") != "ops@example.test" || strings.Join(leaf.URIs, ",") != "spiffe://example.test/app" {
		t.Fatalf("SANs %+v", leaf)
	}
	if leaf.NotAfter != c.rsaLeaf.cert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("not_after %q", leaf.NotAfter)
	}
	ec := res.Certificates[1]
	if ec.KeyType != "ECDSA" || ec.KeyBits != 256 || !ec.Expired || ec.DaysRemaining != -11 {
		t.Fatalf("expired ec %+v", ec)
	}
	ed := res.Certificates[2]
	if ed.KeyType != "Ed25519" || ed.KeyBits != 256 || !ed.NotYetValid {
		t.Fatalf("ed25519 %+v", ed)
	}
	ca := res.Certificates[3]
	if !ca.IsCA || !ca.SelfSigned || ca.KeyBits != 384 {
		t.Fatalf("ca %+v", ca)
	}
}

func TestInspectDER(t *testing.T) {
	c := newChain(t)
	res, err := Inspect(c.rsaLeaf.der, now)
	if err != nil || res.Format != "der" || len(res.Certificates) != 1 {
		t.Fatalf("single DER: %+v %v", res, err)
	}
	res, err = Inspect(append(append([]byte(nil), c.rsaLeaf.der...), c.ca.der...), now)
	if err != nil || len(res.Certificates) != 2 {
		t.Fatalf("concatenated DER: %+v %v", res, err)
	}
}

func TestInspectRefusesPrivateKeys(t *testing.T) {
	c := newChain(t)
	combined := append(pemOf(c.rsaLeaf), keyPEM(t, c.rsaLeaf.key)...)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(c.ecLeaf.key)
	ecDER, _ := x509.MarshalECPrivateKey(c.ecLeaf.key.(*ecdsa.PrivateKey))
	pkcs1 := x509.MarshalPKCS1PrivateKey(c.rsaLeaf.key.(*rsa.PrivateKey))
	oddType := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE" + " KEY", Bytes: ecDER})
	for name, in := range map[string][]byte{
		"cert then key PEM": combined, "key only PEM": keyPEM(t, c.edLeaf.key), "EC PEM": oddType,
		"PKCS8 DER": pkcs8, "SEC1 DER": ecDER, "PKCS1 DER": pkcs1,
		// A key hidden after a megabyte of certificates is still found.
		"key after padding": append(bytes.Repeat(pemOf(c.ca), 1<<20/len(pemOf(c.ca))+1), keyPEM(t, c.edLeaf.key)...),
	} {
		res, err := Inspect(in, now)
		if !errors.Is(err, ErrPrivateKey) {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		if len(res.Certificates) != 0 {
			t.Fatalf("%s: certificates returned alongside a private key", name)
		}
	}
}

func TestInspectNoCertificates(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("not a certificate\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1}})} {
		if _, err := Inspect(in, now); !errors.Is(err, ErrNoCertificates) {
			t.Fatalf("%q: %v", in, err)
		}
	}
	// A PEM "CERTIFICATE" block with garbage inside is counted, not echoed.
	c := newChain(t)
	in := append(pemOf(c.ca), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})...)
	res, err := Inspect(in, now)
	if err != nil || len(res.Certificates) != 1 || res.Unparsable != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	// Too many certificates.
	if _, err := Inspect(bytes.Repeat(pemOf(c.ca), MaxCertificates+1), now); !errors.Is(err, ErrTooMany) {
		t.Fatalf("limit: %v", err)
	}
}

func FuzzInspect(f *testing.F) {
	c := newChain(f)
	f.Add(pemOf(c.rsaLeaf, c.ca))
	f.Add(c.edLeaf.der)
	f.Add(append(pemOf(c.ca), keyPEM(f, c.edLeaf.key)...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := Inspect(b, now)
		if err != nil {
			if len(res.Certificates) != 0 {
				t.Fatal("certificates returned with an error")
			}
			return
		}
		if len(res.Certificates) == 0 || len(res.Certificates) > MaxCertificates {
			t.Fatalf("%d certificates without an error", len(res.Certificates))
		}
		if redact.ContainsPrivateKey(b) {
			t.Fatal("a file with a private-key header was inspected")
		}
	})
}
