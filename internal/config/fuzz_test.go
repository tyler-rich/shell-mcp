package config

import (
	"slices"
	"strings"
	"testing"
)

// FuzzParseHostKeyPin: whatever is accepted is exactly "<type> <fingerprint>"
// with a known type and a valid fingerprint, and prints back unchanged.
func FuzzParseHostKeyPin(f *testing.F) {
	for _, s := range []string{testPin, testFingerprint, "ssh-rsa " + testFingerprint, "ssh-ed25519  " + testFingerprint, "ssh-ed25519\t" + testFingerprint, ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, ok := ParseHostKeyPin(s)
		if !ok {
			return
		}
		if p.String() != s || !slices.Contains(HostKeyTypes, p.Type) || !ValidFingerprint(p.Fingerprint) || strings.ContainsAny(p.Fingerprint, " \t\n") {
			t.Fatalf("accepted %q as %+v", s, p)
		}
	})
}
