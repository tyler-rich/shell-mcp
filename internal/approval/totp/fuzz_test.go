package totp

import (
	"strings"
	"testing"
)

// FuzzParseCode: whatever is accepted is exactly six ASCII digits, and is the
// input with its spaces removed; nothing longer than the bound is accepted.
func FuzzParseCode(f *testing.F) {
	for _, s := range []string{"123456", "123 456", " 000000 ", "12345", "1234567", "12345a", "１２３４５６", "", "\x00123456"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := ParseCode(s)
		if !ok {
			if got != "" {
				t.Fatalf("refused %q but returned %q", s, got)
			}
			return
		}
		if len(got) != Digits || strings.Trim(got, "0123456789") != "" {
			t.Fatalf("accepted %q as %q", s, got)
		}
		if got != strings.ReplaceAll(s, " ", "") || len(s) > maxCodeInput {
			t.Fatalf("accepted %q as %q", s, got)
		}
	})
}
