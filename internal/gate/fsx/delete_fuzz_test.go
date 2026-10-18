//go:build linux

package fsx

import (
	"regexp"
	"testing"
)

var previewSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FuzzValidPreviewSHA256: delete's expected_preview_sha256 is accepted
// exactly when it is 64 lowercase hex digits.
func FuzzValidPreviewSHA256(f *testing.F) {
	for _, s := range []string{"", "0", zeroHash, zeroHash + "0", "ABCDEF" + zeroHash[6:], zeroHash[:63] + "\n", zeroHash[:63] + "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := ValidPreviewSHA256(s), previewSHA256RE.MatchString(s); got != want {
			t.Fatalf("ValidPreviewSHA256(%q) = %v, want %v", s, got, want)
		}
	})
}
