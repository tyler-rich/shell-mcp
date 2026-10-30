package redact

import (
	"regexp"
	"strings"
	"testing"
)

// Fixture keys are invented, truncated and not valid key material. They are
// assembled at runtime so that no contiguous key-shaped literal appears in
// the source (secret scanners flag those).
func keyBegin(kind string) string { return "-----BEGIN " + kind + "PRIVATE " + "KEY-----" }

func keyEnd(kind string) string { return "-----END " + kind + "PRIVATE " + "KEY-----" }

var pemKey = keyBegin("OPENSSH ") + "\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\nAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDinventedinventedinvented\n" + keyEnd("OPENSSH ")

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
	in := "log line\n" + keyBegin("RSA ") + "\nMIIEinventedSECRET\nMORESECRET"
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
		"Authorization: Basic aW52ZW50ZWQ6aW52ZW50ZWQ=\r\nHost: x\r\n":   {"aW52ZW50ZWQ6aW52ZW50ZWQ"},
		"authorization:Token abc123secret\n":                             {"abc123secret"},
		"Proxy-Authorization: Negotiate YIIsecret\n":                     {"YIIsecret"},
		"sent 'Authorization: Bearer eyJhbGciOi.payload.sig' upstream\n": {"eyJhbGciOi", "payload.sig"},
		"token is bearer abc.DEF_ghi-123~+/=\n":                          {"abc.DEF_ghi-123"},
		"BEARER    tok3n\n":                                              {"tok3n"},
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
	if !ContainsPrivateKey([]byte(keyBegin("EC ") + "\n")) {
		t.Fatal("header alone not detected")
	}
	if ContainsPrivateKey([]byte("-----BEGIN CERTIFICATE-----\n")) || ContainsPrivateKey([]byte("PRIVATE KEY")) {
		t.Fatal("false positive")
	}
}

// N-34: a block ends only at the first END line of the BEGIN line's own
// label, as in PrivateKeyBlocks (the approval page's masking), and runs to the
// end of the output when there is none. The bodies are invented.
func TestPEMMismatchedLabel(t *testing.T) {
	r := New(nil)
	// The END line of another label does not close the block.
	in := "before\n" + keyBegin("RSA ") + "\nBODYONE\n" + keyEnd("EC ") + "\nBODYTWO\n" + keyEnd("RSA ") + "\nafter\n"
	if got, want := r.String(in), "before\n"+Mask+"\nafter\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// With no END of its own label, the block runs to the end of the output.
	in = "before\n" + keyBegin("RSA ") + "\nBODYONE\n" + keyEnd("EC ") + "\nBODYTWO\nmore text"
	if got, want := r.String(in), "before\n"+Mask; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A BEGIN line of another label inside the block is part of the block.
	in = "x\n" + keyBegin("RSA ") + "\nBODYONE\n" + keyBegin("EC ") + "\nBODYTWO\n" + keyEnd("EC ") + "\nBODYTHREE\n" + keyEnd("RSA ") + "\ny"
	if got, want := r.String(in), "x\n"+Mask+"\ny"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPEMBeginWithoutEndRunsToEnd(t *testing.T) {
	in := "head\n" + keyBegin("") + "\nBODYONE\nBODYTWO\n"
	if got, want := New(nil).String(in), "head\n"+Mask; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPEMConsecutiveKeysOfDifferentLabels(t *testing.T) {
	in := "a\n" + keyBegin("RSA ") + "\nBODYONE\n" + keyEnd("RSA ") + "\nb\n" + keyBegin("EC ") + "\nBODYTWO\n" + keyEnd("EC ") + "\nc\n" +
		keyBegin("RSA ") + "\nBODYTHREE\n" + keyEnd("RSA ") + keyBegin("EC ") + "\nBODYFOUR\n" + keyEnd("EC ") + "\nd"
	want := "a\n" + Mask + "\nb\n" + Mask + "\nc\n" + Mask + Mask + "\nd"
	if got := New(nil).String(in); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPEMTextAroundWellFormedKeysUnchanged(t *testing.T) {
	in := "line one\r\nkey: " + pemKey + " trailing\n\tindented " + keyBegin("RSA ") + "\nBODY\n" + keyEnd("RSA ") + "\nlast\n"
	want := "line one\r\nkey: " + Mask + " trailing\n\tindented " + Mask + "\nlast\n"
	if got := New(nil).String(in); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Output is redacted as a whole buffer (the gate and the helper capture a
// command's output, then redact and cut it; nothing redacts a stream in
// chunks), so a block "split across chunks" is a block the byte cap cuts.
// Truncate redacts before the cut and again after it, so wherever the cut
// falls no key body survives, with a mismatched END line included.
func TestTruncateMismatchedKeyAtEveryCut(t *testing.T) {
	r := New(nil)
	in := []byte("head\n" + keyBegin("RSA ") + "\nBODYONE\n" + keyEnd("EC ") + "\nBODYTWO\n" + keyEnd("RSA ") + "\ntail\n")
	for limit := 0; limit <= len(in); limit++ {
		out, _ := r.Truncate(in, limit)
		mustNotContainAny(t, string(out), "BODYONE", "BODYTWO", "-----END EC")
		if len(out) > limit {
			t.Fatalf("limit %d: %d bytes", limit, len(out))
		}
	}
	// Whole-buffer redaction of output that arrives in pieces: the pieces are
	// joined first, so a block split between them is still one block.
	var joined []byte
	for _, piece := range []string{"head\n" + keyBegin("RSA ") + "\nBODY", "ONE\n" + keyEnd("EC ") + "\nBOD", "YTWO\n" + keyEnd("RSA ") + "\nta", "il\n"} {
		joined = append(joined, piece...)
	}
	if got, want := string(r.Bytes(joined)), "head\n"+Mask+"\ntail\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func mustNotContainAny(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("output still contains %q:\n%s", s, out)
		}
	}
}
