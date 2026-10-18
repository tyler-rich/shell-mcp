package approval

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Visible returns s with every control, format (bidi controls included),
// separator and other non-printing character shown as an escape \u{XXXX},
// and backslashes doubled so that an escape cannot be faked. Ordinary
// spaces are kept. Invalid UTF-8 bytes are shown as \x{XX}.
func Visible(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02X}`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case hidden(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// hidden reports whether r would not show as itself: controls, format
// characters (bidi controls, zero-width characters, the byte-order mark),
// line and paragraph separators, spaces other than U+0020, and anything not
// graphic (unassigned, private use).
func hidden(r rune) bool {
	if r == ' ' {
		return false
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs) || !unicode.IsGraphic(r)
}
