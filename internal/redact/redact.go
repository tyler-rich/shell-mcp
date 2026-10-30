// Package redact is the shared output redaction used by the server, gate and
// helper: PEM private-key blocks (to the first END line of the BEGIN line's
// label, or to the end of the input when there is none, as after truncation),
// an END line of a private-key label with no BEGIN before it (back to the
// start of the input or the previous mask), Authorization header values,
// Bearer tokens, and configured RE2 patterns. MaskKeyBodies is a separate,
// opt-in heuristic for output a source cut before redaction (handoff N-35).
package redact

import (
	"bytes"
	"regexp"
	"strings"
)

// Mask replaces every redacted value.
const Mask = "[REDACTED]"

var (
	pemHead = regexp.MustCompile(`-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-{5}`)
	// pemHead with the label captured (the same matches): the END line that
	// closes a block names the same label.
	pemLabeled = regexp.MustCompile(`-{5}BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-{5}`)
	// The END line of a private-key label, for the orphan-END rule.
	pemEnd = regexp.MustCompile(`-{5}END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-{5}`)
	// The value of an Authorization or Proxy-Authorization header, to the end
	// of the line (a CR ends it too).
	authHeader = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization[ \t]*:[ \t]*)[^\r\n]*`)
	// A bearer token anywhere.
	bearer = regexp.MustCompile(`(?i)\b(bearer[ \t]+)[A-Za-z0-9\-._~+/]+=*`)
)

var (
	pemRepl  = []byte(Mask)
	keepRepl = []byte("${1}" + Mask)
)

// Redactor applies the built-in rules and any extra patterns.
type Redactor struct {
	extra []*regexp.Regexp
}

// New returns a Redactor with the built-in rules plus extra patterns (each
// full match is replaced by Mask).
func New(extra []*regexp.Regexp) *Redactor {
	return &Redactor{extra: extra}
}

// Bytes returns b with every secret replaced by Mask. b is not modified.
func (r *Redactor) Bytes(b []byte) []byte {
	out := maskKeyBlocks(b)
	out = authHeader.ReplaceAll(out, keepRepl)
	out = bearer.ReplaceAll(out, keepRepl)
	if r != nil {
		for _, re := range r.extra {
			out = re.ReplaceAllLiteral(out, pemRepl)
		}
	}
	return out
}

// maskKeyBlocks returns b with each private-key block (PrivateKeyBlocks, the
// finder the approval page's masking uses too) replaced by Mask, and, in the
// text between the blocks, each orphan END range (orphanEnds). b is not
// modified; without a key header or END line it is returned as it is.
func maskKeyBlocks(b []byte) []byte {
	if !bytes.Contains(b, []byte("PRIVATE KEY")) || !pemHead.Match(b) && !pemEnd.Match(b) {
		return b
	}
	s := string(b)
	out := make([]byte, 0, len(b))
	last := 0
	mask := func(rs [][2]int) {
		for _, r := range rs {
			out = append(out, s[last:r[0]]...)
			out = append(out, pemRepl...)
			last = r[1]
		}
	}
	for _, r := range PrivateKeyBlocks(s) {
		mask(orphanEnds(s, last, r[0]))
		mask([][2]int{r})
	}
	mask(orphanEnds(s, last, len(s)))
	return append(out, s[last:]...)
}

// orphanEnds returns the ranges of s[from:to], text outside every key
// block, that an END line of a private-key label masks (handoff N-35): from
// from, or from the end of the previous such line, through this line's
// closing dashes. Its BEGIN line is not in the text, so what comes before
// it, back to the start or to the previous mask, is the body of a key whose
// header a source cut away (journalctl -n, a command printing a range, a
// diff hunk).
func orphanEnds(s string, from, to int) [][2]int {
	var out [][2]int
	for from < to {
		m := pemEnd.FindStringIndex(s[from:to])
		if m == nil {
			break
		}
		out = append(out, [2]int{from, from + m[1]})
		from += m[1]
	}
	return out
}

// String is Bytes for strings.
func (r *Redactor) String(s string) string { return string(r.Bytes([]byte(s))) }

// Truncate redacts b, cuts it to at most limit bytes, and redacts the result
// again, so that neither a secret straddling the cut nor a key header whose
// END line fell beyond it can survive. It reports whether b was cut.
func (r *Redactor) Truncate(b []byte, limit int) ([]byte, bool) {
	if limit < 0 {
		limit = 0
	}
	out := r.Bytes(b)
	cut := false
	// A mask can be longer than the short secret it replaced, so redacting
	// the cut text can overflow again. Output that has already been redacted
	// only holds masks and non-matching text, so the loop settles at once in
	// practice; it is bounded anyway, and the final plain cut can only split
	// a mask or harmless text.
	for i := 0; i < 3 && len(out) > limit; i++ {
		cut = true
		out = r.Bytes(out[:limit])
	}
	if len(out) > limit {
		cut = true
		out = out[:limit]
	}
	return out, cut
}

// ContainsPrivateKey reports whether b contains a PEM private-key header.
func ContainsPrivateKey(b []byte) bool {
	if !bytes.Contains(b, []byte("PRIVATE KEY")) {
		return false
	}
	return pemHead.Match(b)
}

// PrivateKeyBlocks returns the byte ranges [start, end) of the PEM
// private-key blocks in s, in order: each from its BEGIN header (the one
// ContainsPrivateKey detects) through the first END line of the same label
// after it, or, when there is none, to the end of s, so that a block whose
// END is missing or names another label is never taken to end early.
func PrivateKeyBlocks(s string) [][2]int {
	var out [][2]int
	for off := 0; off < len(s); {
		m := pemLabeled.FindStringSubmatchIndex(s[off:])
		if m == nil {
			break
		}
		start, head := off+m[0], off+m[1]
		end := len(s)
		closing := "-----END " + s[off+m[2]:off+m[3]] + "-----"
		if i := strings.Index(s[head:], closing); i >= 0 {
			end = head + i + len(closing)
		}
		out = append(out, [2]int{start, end})
		off = end
	}
	return out
}
