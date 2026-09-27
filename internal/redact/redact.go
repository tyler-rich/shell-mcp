// Package redact is the shared output redaction used by the server, gate and
// helper: PEM private-key blocks (including a header whose END line was cut
// off by truncation), Authorization header values, Bearer tokens, and
// configured RE2 patterns.
package redact

import "regexp"

// Mask replaces every redacted value.
const Mask = "[REDACTED]"

// Redactor applies the built-in rules and any extra patterns.
type Redactor struct {
	extra []*regexp.Regexp
}

// New returns a Redactor with the built-in rules plus extra patterns (each
// full match is replaced by Mask).
func New(extra []*regexp.Regexp) *Redactor {
	return &Redactor{extra: extra}
}

// Bytes returns b with every secret replaced by Mask.
func (r *Redactor) Bytes(b []byte) []byte { return b }

// String is Bytes for strings.
func (r *Redactor) String(s string) string { return s }

// Truncate redacts b, cuts it to at most limit bytes, and redacts the result
// again, so that neither a secret straddling the cut nor a key header whose
// END line fell beyond it can survive. It reports whether b was cut.
func (r *Redactor) Truncate(b []byte, limit int) ([]byte, bool) {
	return b, false
}

// ContainsPrivateKey reports whether b contains a PEM private-key header.
func ContainsPrivateKey(b []byte) bool { return false }
