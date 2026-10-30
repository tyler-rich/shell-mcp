package redact

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// Headerless key text (handoff N-35): a slice the source cut before
// redaction (journalctl -n, a command that prints a range of a file, a diff
// hunk) can begin inside a key's body, without its BEGIN line. Key bodies
// here are invented: base64 of hashed bytes, wrapped as PEM wraps it,
// assembled at run time, never a literal key.

// inventedBody returns n full lines of width w and a shorter last line,
// derived from seed.
func inventedBody(seed string, n, w int) []string {
	var raw []byte
	for i := 0; len(raw)*4/3 < n*w+w/2; i++ {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], uint64(i))
		h := sha256.Sum256(append([]byte(seed), c[:]...))
		raw = append(raw, h[:]...)
	}
	enc := base64.StdEncoding.EncodeToString(raw)[:n*w+w/2]
	var out []string
	for len(enc) > w {
		out = append(out, enc[:w])
		enc = enc[w:]
	}
	return append(out, enc+"==")
}

// keyLines is a whole invented key: BEGIN, body, END.
func keyLines(label, seed string, n, w int) []string {
	return append(append([]string{keyBegin(label)}, inventedBody(seed, n, w)...), keyEnd(label))
}

// b1: an END line of a private-key label with no BEGIN of its label before
// it masks back to the start of the text, or to the end of the previous
// masked block, so a window that starts inside a body and reaches its END
// shows none of it.
func TestOrphanEndMasksBack(t *testing.T) {
	r := New(nil)
	key := keyLines("", "orphan", 26, 64)
	for start := 1; start < len(key); start++ {
		in := strings.Join(key[start:], "\n") + "\nlistening on :8080\n"
		got := r.String(in)
		if want := Mask + "\nlistening on :8080\n"; got != want {
			t.Fatalf("window from line %d: got %q, want %q", start, got, want)
		}
	}
	// After a whole block, an orphan END masks back to that block's end only.
	rsa := keyLines("RSA ", "first", 3, 64)
	ec := keyLines("EC ", "second", 3, 64)
	in := "a\n" + strings.Join(rsa, "\n") + "\nb\n" + strings.Join(ec[2:], "\n") + "\nc\n"
	if got, want := r.String(in), "a\n"+Mask+Mask+"\nc\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Two orphan ENDs: each masks back to the previous one.
	in = "x\n" + keyEnd("") + "\ny\n" + keyEnd("OPENSSH ") + "\nz"
	if got, want := r.String(in), Mask+Mask+"\nz"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// With a journal prefix on every line, as journalctl prints it.
	var j []string
	for i, l := range append([]string{"starting"}, key[10:]...) {
		j = append(j, fmt.Sprintf("2026-10-30T10:00:%02d+00:00 target-a example-app[4242]: %s", i, l))
	}
	got := r.String(strings.Join(j, "\n") + "\n")
	mustNotContainAny(t, got, key[10:]...)
	if !strings.HasSuffix(got, Mask+"\n") {
		t.Fatalf("got %q", got)
	}
}

// b1 leaves ordinary text alone: END lines of other labels, the words END
// and PRIVATE KEY apart, and a public key's END.
func TestOrphanEndOrdinaryTextUnchanged(t *testing.T) {
	for _, in := range []string{
		"-----END CERTIFICATE-----\nnext\n",
		"END PRIVATE KEY section\n",
		"-----END PUBLIC KEY-----\n-----END RSA PUBLIC KEY-----\n",
		"the END of the PRIVATE KEY rotation\n",
	} {
		if got := New(nil).String(in); got != in {
			t.Fatalf("%q changed to %q", in, got)
		}
	}
}

// b2: MaskKeyBodies masks runs of PEM-width base64 lines (64 or 70
// characters, not all hex, a shorter last line included) outside any PEM
// block whose BEGIN is shown: a window wholly inside a key's body.
func TestMaskKeyBodiesWindowInsideBody(t *testing.T) {
	for _, w := range []int{64, 70} {
		body := inventedBody(fmt.Sprintf("inside-%d", w), 26, w)
		for start := 0; start < len(body)-1; start++ {
			for end := start + 1; end <= len(body); end++ {
				in := "before\n" + strings.Join(body[start:end], "\n") + "\nafter\n"
				got := string(MaskKeyBodies([]byte(in), PlainLines))
				mustNotContainAny(t, got, body[start:end]...)
				if !strings.HasPrefix(got, "before\n") || !strings.HasSuffix(got, "\nafter\n") {
					t.Fatalf("w=%d [%d:%d]: surrounding text changed: %q", w, start, end, got)
				}
			}
		}
	}
}

// b2 on journal lines: the short-iso prefix is kept and the message masked,
// continuation lines (indented) included.
func TestMaskKeyBodiesJournal(t *testing.T) {
	body := inventedBody("journal", 26, 64)
	var lines []string
	for i, l := range body[3:9] {
		lines = append(lines, fmt.Sprintf("2026-10-30T10:00:%02d+00:00 target-a example-app[4242]: %s", i, l))
	}
	lines = append(lines, "                                                      "+body[9])
	in := strings.Join(lines, "\n") + "\n"
	got := string(MaskKeyBodies([]byte(in), JournalLines))
	mustNotContainAny(t, got, body[3:10]...)
	if !strings.HasPrefix(got, "2026-10-30T10:00:00+00:00 target-a example-app[4242]: "+Mask+"\n") {
		t.Fatalf("prefix not kept: %q", got)
	}
	if strings.Count(got, "\n") != strings.Count(in, "\n") {
		t.Fatalf("line count changed: %q", got)
	}
}

// b2 leaves ordinary output alone: a whole certificate, public key or PGP
// block (its BEGIN shown), SHA-256 hex lines, base64 wrapped at 76, short
// base64, ordinary log lines.
func TestMaskKeyBodiesOrdinaryOutputUnchanged(t *testing.T) {
	cert := append(append([]string{"-----BEGIN CERTIFICATE-----"}, inventedBody("cert", 12, 64)...), "-----END CERTIFICATE-----")
	pub := append(append([]string{"-----BEGIN PUBLIC KEY-----"}, inventedBody("pub", 4, 64)...), "-----END PUBLIC KEY-----")
	pgp := append(append([]string{"-----BEGIN PGP SIGNATURE-----", ""}, inventedBody("pgp", 5, 64)...), "-----END PGP SIGNATURE-----")
	h := sha256.Sum256([]byte("x"))
	hexLine := fmt.Sprintf("%x", h)
	mime := strings.Join(inventedBody("mime", 4, 76), "\n")
	for name, in := range map[string]string{
		"certificate": strings.Join(cert, "\n") + "\n",
		"public key":  strings.Join(pub, "\n") + "\n",
		"pgp":         strings.Join(pgp, "\n") + "\n",
		"hex":         hexLine + "\n" + hexLine + "\n" + hexLine + "  /srv/app/file\n",
		"mime 76":     mime + "\n",
		"short":       "aGVsbG8gd29ybGQ=\nQUJDREVGRw==\n",
		"log":         "2026-10-30T10:00:00+00:00 target-a example-app[4242]: listening on :8080\nok\n",
	} {
		for _, f := range []LineFormat{PlainLines, JournalLines} {
			if got := string(MaskKeyBodies([]byte(in), f)); got != in {
				t.Fatalf("%s (format %d) changed: %q", name, f, got)
			}
		}
	}
}

// FuzzHeaderlessKeyBody: for an invented key (any width PEM uses, any body
// length) in surrounding log text, any window of its lines, with or without
// journal prefixes, redacted as the journal and strict command output are
// (Bytes, then MaskKeyBodies): no full body line survives, and when the
// window reaches the key's END line no body line survives at all.
func FuzzHeaderlessKeyBody(f *testing.F) {
	f.Add("seed", uint8(26), false, uint8(10), uint8(40), false)
	f.Add("x", uint8(1), true, uint8(1), uint8(3), true)
	f.Add("y", uint8(60), false, uint8(30), uint8(31), true)
	f.Fuzz(func(t *testing.T, seed string, n uint8, wide bool, start, end uint8, journal bool) {
		w := 64
		if wide {
			w = 70
		}
		key := keyLines("", seed, int(n%80)+1, w)
		lines := append(append([]string{"starting up"}, key...), "listening on :8080")
		s, e := int(start)%len(lines), int(end)%(len(lines)+1)
		if e <= s {
			s, e = e, s
		}
		if e == s {
			e = s + 1
		}
		window := lines[s:e]
		format := PlainLines
		if journal {
			format = JournalLines
			for i := range window {
				window[i] = fmt.Sprintf("2026-10-30T10:00:%02d+00:00 target-a example-app[4242]: %s", i%60, window[i])
			}
		}
		got := string(MaskKeyBodies(New(nil).Bytes([]byte(strings.Join(window, "\n")+"\n")), format))
		body := key[1 : len(key)-1]
		reachesEnd := s <= len(key) && e > len(key)
		for i, l := range body {
			if (len(l) == w || reachesEnd) && strings.Contains(got, l) {
				t.Fatalf("window [%d:%d] of %d lines: body line %d survived:\n%s", s, e, len(lines), i, got)
			}
		}
	})
}
