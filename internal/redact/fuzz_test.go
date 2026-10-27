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
	f.Add([]byte(keyBegin("RSA ")+"\nabc\n"+keyEnd("RSA ")+"\n"), 20)
	f.Add([]byte("Authorization: Bearer abc.def\r\nHost: x\r\n"), 10)
	f.Add([]byte("x "+keyBegin("OPENSSH ")+" y"), 5)
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

// FuzzPrivateKeyBlocks: the blocks are in order and never overlap; each
// starts at a private-key header and ends just after "-----END <its
// label>-----" or at the end of the input; no text outside the blocks
// holds a private-key header; and there are none exactly when
// ContainsPrivateKey is false.
func FuzzPrivateKeyBlocks(f *testing.F) {
	begin, end := "-----BEGIN ", "-----END "
	for _, s := range []string{"", "x", begin + "PRIVATE " + "KEY-----\nQQ==\n" + end + "PRIVATE " + "KEY-----\ny",
		begin + "EC PRIVATE " + "KEY-----\nQQ==\n" + end + "PRIVATE " + "KEY-----\n", begin + "PGP PRIVATE " + "KEY BLOCK-----\n",
		"a" + begin + "RSA PRIVATE " + "KEY-----" + end + "RSA PRIVATE " + "KEY-----b" + begin + "PRIVATE " + "KEY-----c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		blocks := PrivateKeyBlocks(s)
		if (len(blocks) > 0) != ContainsPrivateKey([]byte(s)) {
			t.Fatalf("%q: %d blocks, ContainsPrivateKey %v", s, len(blocks), ContainsPrivateKey([]byte(s)))
		}
		last := 0
		for _, r := range blocks {
			if r[0] < last || r[1] <= r[0] || r[1] > len(s) {
				t.Fatalf("%q: block %v after %d", s, r, last)
			}
			m := pemLabeled.FindStringSubmatchIndex(s[r[0]:])
			if len(m) < 4 || m[0] != 0 {
				t.Fatalf("%q: block %v does not start at a header", s, r)
			}
			closing := "-----END " + s[r[0]+m[2]:r[0]+m[3]] + "-----"
			body := s[r[0]+m[1] : r[1]]
			if r[1] != len(s) && !bytes.HasSuffix([]byte(body), []byte(closing)) {
				t.Fatalf("%q: block %v ends early", s, r)
			}
			if i := bytes.Index([]byte(body), []byte(closing)); i >= 0 && i != len(body)-len(closing) {
				t.Fatalf("%q: block %v runs past its first END", s, r)
			}
			if ContainsPrivateKey([]byte(s[last:r[0]])) {
				t.Fatalf("%q: a header outside the blocks", s)
			}
			last = r[1]
		}
		if ContainsPrivateKey([]byte(s[last:])) {
			t.Fatalf("%q: a header after the blocks", s)
		}
	})
}
