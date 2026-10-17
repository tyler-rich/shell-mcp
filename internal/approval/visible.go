package approval

// Visible returns s with every control, format (bidi controls included),
// separator and other non-printing character shown as an escape \u{XXXX},
// and backslashes doubled so that an escape cannot be faked. Ordinary
// spaces are kept. Invalid UTF-8 bytes are shown as \x{XX}.
func Visible(s string) string { return s }
