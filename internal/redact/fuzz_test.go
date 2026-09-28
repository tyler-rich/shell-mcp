package redact

import (
	"bytes"
	"regexp"
	"testing"
)

// FuzzRedact: redaction never panics; no private-key header survives
// Bytes or Truncate; Truncate never exceeds its limit; with no secrets
// present, Bytes is the identity.
func FuzzRedact(f *testing.F) {
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n"), 20)
	f.Add([]byte("Authorization: Bearer abc.def\r\nHost: x\r\n"), 10)
	f.Add([]byte("x -----BEGIN OPENSSH PRIVATE KEY----- y"), 5)
	f.Add([]byte("api_key=1234567890"), 8)
	f.Add([]byte("plain text only"), 100)
	r := New([]*regexp.Regexp{regexp.MustCompile(`api_key=\S+`)})
	f.Fuzz(func(t *testing.T, in []byte, limit int) {
		if limit < 0 {
			limit = -limit
		}
		limit %= 1 << 16
		out := r.Bytes(in)
		if ContainsPrivateKey(out) {
			t.Fatalf("a private-key header survived: %q", out)
		}
		cut, _ := r.Truncate(in, limit)
		if len(cut) > limit {
			t.Fatalf("Truncate(%d) returned %d bytes", limit, len(cut))
		}
		if ContainsPrivateKey(cut) {
			t.Fatalf("a private-key header survived truncation: %q", cut)
		}
		if !pemHead.Match(in) && !authHeader.Match(in) && !bearer.Match(in) && !r.extra[0].Match(in) && !bytes.Equal(out, in) {
			t.Fatalf("input without secrets was changed: %q -> %q", in, out)
		}
	})
}
