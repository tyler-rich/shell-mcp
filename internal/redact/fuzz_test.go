package redact

import (
	"bytes"
	"regexp"
	"strings"
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
		if !pemHead.Match(in) && len(refOrphanEnds(string(in), 0, len(in))) == 0 && !authHeader.Match(in) && !bearer.Match(in) && !r.extra[0].Match(in) && !bytes.Equal(out, in) {
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

// refKeyBlocks is an independent reference for the key-block rule (a header
// "-----BEGIN <label>-----" whose label ends in PRIVATE KEY or PRIVATE KEY
// BLOCK; the block runs through the first "-----END <label>-----" after it, or
// to the end of s), written without the package's regexps.
func refKeyBlocks(s string) [][2]int {
	var out [][2]int
	for off := 0; off < len(s); {
		start, head, label := -1, 0, ""
		for i := off; i+len("-----BEGIN ") <= len(s); i++ {
			if !strings.HasPrefix(s[i:], "-----BEGIN ") {
				continue
			}
			j := i + len("-----BEGIN ")
			k := j
			for k < len(s) && (s[k] == ' ' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= '0' && s[k] <= '9') {
				k++
			}
			l := s[j:k]
			if strings.HasPrefix(s[k:], "-----") && (strings.HasSuffix(l, "PRIVATE KEY") || strings.HasSuffix(l, "PRIVATE KEY BLOCK")) {
				start, head, label = i, k+len("-----"), l
				break
			}
		}
		if start < 0 {
			break
		}
		end := len(s)
		if i := strings.Index(s[head:], "-----END "+label+"-----"); i >= 0 {
			end = head + i + len("-----END "+label+"-----")
		}
		out = append(out, [2]int{start, end})
		off = end
	}
	return out
}

// refOrphanEnds is the reference for the orphan-END rule (handoff N-35) in
// s[from:to], text outside every block: each "-----END <label>-----" of a
// private-key label masks from from, or from the end of the previous one,
// through itself.
func refOrphanEnds(s string, from, to int) [][2]int {
	var out [][2]int
	for i := from; i+len("-----END ") <= to; i++ {
		if !strings.HasPrefix(s[i:], "-----END ") {
			continue
		}
		k := i + len("-----END ")
		j := k
		for j < to && (s[j] == ' ' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		l := s[k:j]
		if j+len("-----") <= to && strings.HasPrefix(s[j:], "-----") && (strings.HasSuffix(l, "PRIVATE KEY") || strings.HasSuffix(l, "PRIVATE KEY BLOCK")) {
			out = append(out, [2]int{from, j + len("-----")})
			from = j + len("-----")
			i = from - 1
		}
	}
	return out
}

// refMasked is every range Bytes masks: the key blocks and, in the text
// between them, the orphan END ranges.
func refMasked(s string) [][2]int {
	var out [][2]int
	last := 0
	for _, b := range refKeyBlocks(s) {
		out = append(out, refOrphanEnds(s, last, b[0])...)
		out = append(out, b)
		last = b[1]
	}
	return append(out, refOrphanEnds(s, last, len(s))...)
}

// FuzzRedactKeyBlocks: for input with no Authorization or Bearer text, the
// output is the input with each key block, and each orphan END range
// (handoff N-35), replaced by Mask and everything else unchanged, so no key
// body survives and no text outside those ranges is touched; Bytes agrees
// with the reference on where they are.
func FuzzRedactKeyBlocks(f *testing.F) {
	begin, end := "-----BEGIN ", "-----END "
	pk := "PRIVATE " + "KEY-----"
	for _, s := range []string{"", "plain", "a" + begin + "RSA " + pk + "BODY1" + end + "RSA " + pk + "z",
		begin + "RSA " + pk + "BODY1" + end + "EC " + pk + "BODY2" + end + "RSA " + pk + "tail",
		begin + "RSA " + pk + "BODY1" + end + "EC " + pk + "BODY2",
		begin + "RSA " + pk + "B" + end + "RSA " + pk + "m" + begin + "EC " + pk + "C" + end + "EC " + pk,
		begin + pk + "A" + begin + "EC " + pk + "B" + end + pk,
		"BODY1\nBODY2\n" + end + pk + "\nafter", "a" + begin + "RSA " + pk + "B" + end + "RSA " + pk + "m" + end + "EC " + pk + "n",
		"x" + end + pk + "y" + end + "OPENSSH " + pk + "z", "BODY" + end + "RSA PUBLIC " + "KEY-----"} {
		f.Add(s)
	}
	r := New(nil)
	f.Fuzz(func(t *testing.T, s string) {
		if authHeader.MatchString(s) || bearer.MatchString(s) {
			t.Skip()
		}
		var want strings.Builder
		last := 0
		for _, b := range refMasked(s) {
			want.WriteString(s[last:b[0]])
			want.WriteString(Mask)
			last = b[1]
		}
		want.WriteString(s[last:])
		if got := r.String(s); got != want.String() {
			t.Fatalf("%q: got %q, want %q", s, got, want.String())
		}
	})
}
