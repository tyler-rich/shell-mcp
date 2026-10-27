package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// The approval page masks each PEM private-key block in a value, and only
// the block (handoff N-5, S6-4): the text around it is shown as it is, so a
// key cannot hide the rest of a file from the approver. Keys are generated
// for each run; every path and value is invented.

// freshKey is a private key generated for this test run only, PEM-encoded
// (PKCS #8), and its base64 body lines: the sentinel that must not appear
// in what an approver sees.
func freshKey(t *testing.T) (pemText string, body []string) {
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
	return pemText, lines[1 : len(lines)-1]
}

// masked is how the page shows one private-key block.
func masked(block string) string {
	return "private key, not shown: " + strconv.Itoa(len(block)) + " bytes, sha256 " + SHA256Hex([]byte(block))
}

// fieldsOf returns the fields of {"content": v} by key.
func fieldsOf(t *testing.T, v string) map[string]string {
	t.Helper()
	fs, err := Fields(map[string]any{"path": "/etc/example-app/app.conf", "content": v, "nested": map[string]any{"list": []any{v}}}, MaxArgsBytes)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Key] = f.Value
	}
	return got
}

// noBody fails when s holds a line of a key's body or a PEM header.
func noBody(t *testing.T, s string, bodies ...[]string) {
	t.Helper()
	for _, b := range bodies {
		for _, l := range b {
			if strings.Contains(s, l) {
				t.Fatalf("a key's body is shown: %q", s)
			}
		}
	}
	if redact.ContainsPrivateKey([]byte(s)) {
		t.Fatalf("a PEM header is shown: %q", s)
	}
}

// TestFieldsMaskPrivateKey: each private-key block in a value is shown as
// its size and SHA-256, and everything around it as it is; the hash of the
// arguments still covers the real value, so the approval binds it.
func TestFieldsMaskPrivateKey(t *testing.T) {
	key, body := freshKey(t)
	block := strings.TrimSuffix(key, "\n") // BEGIN line to END line
	cert := "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"
	for name, c := range map[string]struct{ v, want string }{
		"key":        {key, masked(block) + "\n"},
		"bundle":     {cert + key, cert + masked(block) + "\n"},
		"after text": {"# rotated\n" + key, "# rotated\n" + masked(block) + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			got := fieldsOf(t, c.v)
			if got["content"] != c.want || got["nested.list[0]"] != c.want || got["path"] != "/etc/example-app/app.conf" {
				t.Fatalf("fields %q, want content %q", got, c.want)
			}
			for _, v := range got {
				noBody(t, v, body)
			}
			// The binding is to the real content.
			other, _ := freshKey(t)
			h1, _ := HashOf(map[string]any{"content": c.v})
			h2, _ := HashOf(map[string]any{"content": strings.Replace(c.v, key, other, 1)})
			if h1 == h2 {
				t.Fatal("the arguments hash does not bind the content")
			}
		})
	}
	// Text without a key is shown as it is.
	if got := fieldsOf(t, "PRIVATE KEY is mentioned here\n"); got["content"] != "PRIVATE KEY is mentioned here\n" {
		t.Fatalf("plain text masked: %q", got["content"])
	}
}

// TestFieldsMaskKeyBlocksOnly: a key cannot hide the rest of a value from
// the approver. A config file with an embedded key shows its other lines;
// two blocks are both masked; a BEGIN line without its END line (of the
// same label) is masked to the end of the value, never shown.
func TestFieldsMaskKeyBlocksOnly(t *testing.T) {
	keyA, bodyA := freshKey(t)
	keyB, bodyB := freshKey(t)
	blockA, blockB := strings.TrimSuffix(keyA, "\n"), strings.TrimSuffix(keyB, "\n")
	head := "listen: 0.0.0.0:8443\nallow_from: any\ntls_key: |\n"
	tail := "admin_token_file: /etc/example-app/token\nmode: permissive\n"
	// A BEGIN line whose END line is cut off, or names another label.
	cut := strings.Join(strings.Split(keyB, "\n")[:3], "\n") + "\n"
	otherEnd := strings.Replace(keyB, "-----END PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", 1)
	for name, c := range map[string]struct {
		v, want string
		bodies  [][]string
	}{
		"a config with an embedded key": {head + keyA + tail, head + masked(blockA) + "\n" + tail, [][]string{bodyA}},
		"two blocks":                    {head + keyA + "between: kept\n" + keyB + tail, head + masked(blockA) + "\nbetween: kept\n" + masked(blockB) + "\n" + tail, [][]string{bodyA, bodyB}},
		"a BEGIN without its END":       {head + cut + tail, head + masked(cut+tail), [][]string{bodyB[:2]}},
		"an END of another label":       {head + otherEnd + tail, head + masked(otherEnd+tail), [][]string{bodyB}},
		"a key, then one cut off":       {keyA + tail + cut, masked(blockA) + "\n" + tail + masked(cut), [][]string{bodyA, bodyB[:2]}},
	} {
		t.Run(name, func(t *testing.T) {
			got := fieldsOf(t, c.v)
			if got["content"] != c.want || got["nested.list[0]"] != c.want {
				t.Fatalf("content field\n%q\nwant\n%q", got["content"], c.want)
			}
			for _, v := range got {
				noBody(t, v, c.bodies...)
			}
		})
	}
}

// labelRE is the label of a private-key PEM header, as POLICY §3's
// detection reads it; reference below is written without redact's
// regular expression, as an independent model.
var labelRE = regexp.MustCompile(`^[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?$`)

// reference masks s block by block: each "-----BEGIN <label>-----" whose
// label is a private key's, through the first "-----END <label>-----"
// after it, or to the end of s when there is none. It returns the shown
// text, the text outside every block, and each block's body.
func reference(s string) (shown, outside string, bodies []string) {
	var b, o strings.Builder
	last, pos := 0, 0
	for {
		k := strings.Index(s[pos:], "-----BEGIN ")
		if k < 0 {
			break
		}
		h := pos + k
		rest := s[h+len("-----BEGIN "):]
		e := strings.Index(rest, "-----")
		if e < 0 || !labelRE.MatchString(rest[:e]) {
			pos = h + 1
			continue
		}
		label := rest[:e]
		hdrEnd := h + len("-----BEGIN ") + e + len("-----")
		endTok := "-----END " + label + "-----"
		stop, bodyEnd := len(s), len(s)
		if x := strings.Index(s[hdrEnd:], endTok); x >= 0 {
			bodyEnd = hdrEnd + x
			stop = bodyEnd + len(endTok)
		}
		b.WriteString(s[last:h])
		o.WriteString(s[last:h])
		o.WriteByte(0)
		b.WriteString(masked(s[h:stop]))
		bodies = append(bodies, s[hdrEnd:bodyEnd])
		last, pos = stop, stop
	}
	b.WriteString(s[last:])
	o.WriteString(s[last:])
	return b.String(), o.String(), bodies
}

// FuzzFieldsMaskPrivateKey: for any string argument, the field shows
// exactly the reference masking: the text outside every private-key block
// unchanged and each block as its size and SHA-256; no field holds a
// private-key header, and no block's body survives on the page.
func FuzzFieldsMaskPrivateKey(f *testing.F) {
	// The headers are assembled at run time, so no PEM block is a literal
	// here (gitleaks; .gitleaksignore).
	begin, end := "-----BEGIN ", "-----END "
	for _, s := range []string{"", "plain\n", begin + "PRIVATE " + "KEY-----\nAAAA\n" + end + "PRIVATE " + "KEY-----\n",
		"x " + begin + "RSA PRIVATE " + "KEY----- y", begin + "PGP PRIVATE " + "KEY BLOCK-----", begin + "private KEY-----", "PRIVATE KEY",
		"a: 1\n" + begin + "PRIVATE " + "KEY-----\nQUFB\n" + end + "PRIVATE " + "KEY-----\nb: 2\n" + begin + "EC PRIVATE " + "KEY-----\nQkJC\n",
		begin + "EC PRIVATE " + "KEY-----\nQ0ND\n" + end + "PRIVATE " + "KEY-----\nc: 3\n", begin + "X-----" + begin + "PRIVATE " + "KEY-----\nREQ=\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		fs, err := Fields(map[string]any{"content": s, "list": []any{s}}, MaxArgsBytes)
		if err != nil {
			return // not representable as JSON text
		}
		for _, x := range fs {
			if redact.ContainsPrivateKey([]byte(x.Value)) {
				t.Fatalf("field %s shows a private key: %q", x.Key, x.Value)
			}
		}
		if !utf8.ValidString(s) {
			return // shown as JSON decodes it, which the loop checked
		}
		want, outside, bodies := reference(s)
		got := fs[0].Value
		if len(want) <= MaxFieldBytes && got != want {
			t.Fatalf("field\n%q\nwant\n%q", got, want)
		}
		for _, b := range bodies {
			if len(b) >= 8 && strings.Contains(got, b) && !strings.Contains(outside, b) {
				t.Fatalf("a block's body %q survives in %q", b, got)
			}
		}
	})
}
