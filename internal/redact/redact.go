// Package redact is the shared output redaction used by the server, gate and
// helper: PEM private-key blocks (including a header whose END line was cut
// off by truncation), Authorization header values, Bearer tokens, and
// configured RE2 patterns.
package redact

import (
	"bytes"
	"regexp"
)

// Mask replaces every redacted value.
const Mask = "[REDACTED]"

var (
	// A private-key block, up to its END line or, when the END line is
	// missing (for example after truncation), to the end of the input.
	// (?s) lets . cross line breaks, so LF and CRLF input behave alike.
	pemBlock = regexp.MustCompile(`(?s)-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-{5}.*?(?:-{5}END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-{5}|\z)`)
	pemHead  = regexp.MustCompile(`-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-{5}`)
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
	out := pemBlock.ReplaceAll(b, pemRepl)
	out = authHeader.ReplaceAll(out, keepRepl)
	out = bearer.ReplaceAll(out, keepRepl)
	if r != nil {
		for _, re := range r.extra {
			out = re.ReplaceAllLiteral(out, pemRepl)
		}
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
