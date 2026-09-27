package redact

import (
	"regexp"
	"strings"
	"testing"
)

// Fixture keys below are invented, truncated and not valid key material.
const pemKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDinventedinventedinvented\n-----END OPENSSH PRIVATE KEY-----"

func mustNotContain(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("output still contains %q:\n%s", s, out)
		}
	}
	if !strings.Contains(out, Mask) {
		t.Fatalf("output has no mask:\n%s", out)
	}
}

func TestPEMBlocks(t *testing.T) {
	r := New(nil)
	for _, hdr := range []string{"OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		in := "before\n-----BEGIN " + hdr + "-----\nSECRETLINE1\nSECRETLINE2\n-----END " + hdr + "-----\nafter\n"
		out := r.String(in)
		mustNotContain(t, out, "SECRETLINE1", "SECRETLINE2")
		if !strings.Contains(out, "before") || !strings.Contains(out, "after") {
			t.Fatalf("%s: surrounding text lost: %q", hdr, out)
		}
	}
	// Two blocks: the text between them survives.
	out := r.String(pemKey + "\nmiddle\n" + pemKey)
	if !strings.Contains(out, "middle") {
		t.Fatalf("non-greedy match expected: %q", out)
	}
	mustNotContain(t, out, "inventedinvented")
}

func TestPEMWithoutEnd(t *testing.T) {
	r := New(nil)
	in := "log line\n-----BEGIN RSA PRIVATE KEY-----\nMIIEinventedSECRET\nMORESECRET"
	out := r.String(in)
	mustNotContain(t, out, "MIIEinventedSECRET", "MORESECRET")
	if !strings.HasPrefix(out, "log line\n") {
		t.Fatalf("prefix lost: %q", out)
	}
}

func TestPEMCRLF(t *testing.T) {
	in := strings.ReplaceAll(pemKey, "\n", "\r\n") + "\r\nafter"
	out := New(nil).String(in)
	mustNotContain(t, out, "inventedinvented")
	if !strings.Contains(out, "after") {
		t.Fatalf("after lost: %q", out)
	}
}

func TestPublicMaterialUntouched(t *testing.T) {
	in := "-----BEGIN CERTIFICATE-----\nMIIBinvented\n-----END CERTIFICATE-----\n-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----\n"
	if out := New(nil).String(in); out != in {
		t.Fatalf("public material changed: %q", out)
	}
}

func TestAuthorizationAndBearer(t *testing.T) {
	r := New(nil)
	cases := map[string][]string{
		"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\nHost: x\r\n":  {"dXNlcjpwYXNzd29yZA"},
		"authorization:Token abc123secret\n":                         {"abc123secret"},
		"Proxy-Authorization: Negotiate YIIsecret\n":                 {"YIIsecret"},
		"curl -H 'Authorization: Bearer eyJhbGciOi.payload.sig' x\n": {"eyJhbGciOi", "payload.sig"},
		"token is bearer abc.DEF_ghi-123~+/=\n":                      {"abc.DEF_ghi-123"},
		"BEARER    tok3n\n":                                          {"tok3n"},
	}
	for in, secrets := range cases {
		out := r.String(in)
		mustNotContain(t, out, secrets...)
	}
	// CRLF: the value ends at \r, the next header is kept.
	out := r.String("Authorization: Basic abc\r\nHost: target-a.example.test\r\n")
	if !strings.Contains(out, "Host: target-a.example.test") {
		t.Fatalf("next header lost: %q", out)
	}
}

func TestExtraPatterns(t *testing.T) {
	r := New([]*regexp.Regexp{regexp.MustCompile(`(?i)(api[_-]?key|password)\s*[:=]\s*\S+`)})
	out := r.String("user=svc-shell\nPASSWORD = hunter2\napi_key: k-123\n")
	mustNotContain(t, out, "hunter2", "k-123")
	if !strings.Contains(out, "user=svc-shell") {
		t.Fatalf("unrelated line changed: %q", out)
	}
}

func TestTruncateCannotSplitSecret(t *testing.T) {
	r := New([]*regexp.Regexp{regexp.MustCompile(`secret=[A-Za-z0-9]{12}`)})
	// The cut falls inside the secret: redacting before the cut is what
	// removes it (the 5-character remainder would no longer match).
	in := []byte("xxxxxxxx secret=ABCDEFGHIJKL tail")
	out, cut := r.Truncate(in, 21)
	if !cut {
		t.Fatal("not reported as cut")
	}
	if strings.Contains(string(out), "ABCD") || len(out) > 21 {
		t.Fatalf("leaked or over limit: %q (%d bytes)", out, len(out))
	}
	// The cut removes the END line of a key: redacting after the cut is what
	// removes the body.
	key := []byte("ok\n" + pemKey)
	out, _ = r.Truncate(key, 60)
	if strings.Contains(string(out), "b3BlbnNz") {
		t.Fatalf("key body leaked after cut: %q", out)
	}
	// Under the limit: redacted, not cut.
	out, cut = r.Truncate([]byte("secret=ABCDEFGHIJKL"), 1000)
	if cut || strings.Contains(string(out), "ABCD") {
		t.Fatalf("under limit: %q cut=%v", out, cut)
	}
}

func TestContainsPrivateKey(t *testing.T) {
	if !ContainsPrivateKey([]byte("x\n" + pemKey)) {
		t.Fatal("key not detected")
	}
	if !ContainsPrivateKey([]byte("-----BEGIN EC PRIVATE KEY-----\n")) {
		t.Fatal("header alone not detected")
	}
	if ContainsPrivateKey([]byte("-----BEGIN CERTIFICATE-----\n")) || ContainsPrivateKey([]byte("PRIVATE KEY")) {
		t.Fatal("false positive")
	}
}
