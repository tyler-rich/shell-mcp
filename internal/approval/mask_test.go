package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"
)

// freshKey is a private key generated for this test run only, PEM-encoded
// (PKCS #8), and its base64 body: the sentinel that must not appear in what
// an approver sees.
func freshKey(t *testing.T) (pemText, body string) {
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
	return pemText, strings.Join(lines[1:len(lines)-1], "")
}

// TestFieldsMaskPrivateKey (handoff N-5, S6-4): a value holding a PEM
// private key is never shown as a field: the field says it is a private
// key with its size and SHA-256. The hash of the arguments still covers
// the real value, so the approval binds it.
func TestFieldsMaskPrivateKey(t *testing.T) {
	key, body := freshKey(t)
	bundle := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n" + key
	for name, v := range map[string]string{"key": key, "bundle": bundle, "after text": "# rotated\n" + key} {
		t.Run(name, func(t *testing.T) {
			args := map[string]any{"path": "/etc/example-app/tls/server.key", "content": v, "nested": map[string]any{"list": []any{v}}}
			fs, err := Fields(args, MaxArgsBytes)
			if err != nil {
				t.Fatal(err)
			}
			want := "private key, not shown: " + strconv.Itoa(len(v)) + " bytes, sha256 " + SHA256Hex([]byte(v))
			got := map[string]string{}
			for _, f := range fs {
				got[f.Key] = f.Value
				if strings.Contains(f.Value, body[:32]) || strings.Contains(f.Value, "-----BEGIN") {
					t.Fatalf("field %s shows the key: %q", f.Key, f.Value)
				}
			}
			if got["content"] != want || got["nested.list[0]"] != want || got["path"] != "/etc/example-app/tls/server.key" {
				t.Fatalf("fields %v, want content %q", got, want)
			}
			// The binding is to the real content: another key hashes
			// differently although both fields read alike in shape.
			other, _ := freshKey(t)
			h1, _ := HashOf(args)
			h2, _ := HashOf(map[string]any{"path": args["path"], "content": other, "nested": args["nested"]})
			if h1 == h2 {
				t.Fatal("the arguments hash does not bind the content")
			}
		})
	}
	// Text without a key is shown as it is.
	fs, _ := Fields(map[string]any{"content": "PRIVATE KEY is mentioned here\n"}, MaxArgsBytes)
	if fs[0].Value != "PRIVATE KEY is mentioned here\n" {
		t.Fatalf("plain text masked: %q", fs[0].Value)
	}
}
