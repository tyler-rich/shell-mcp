//go:build linux

package serverinit

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzCheckToken: an accepted token is, after one trailing newline (and a
// carriage return before it) is removed, as the server removes it, at least
// 43 characters with no line break.
func FuzzCheckToken(f *testing.F) {
	for _, s := range []string{strings.Repeat("a", 43), strings.Repeat("a", 43) + "\n", strings.Repeat("a", 42), "a\nb" + strings.Repeat("c", 43), strings.Repeat("a", 43) + "\r\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if checkToken(b) != nil {
			return
		}
		s := strings.TrimSuffix(string(b), "\n")
		if len(s) < len(b) {
			s = strings.TrimSuffix(s, "\r")
		}
		if len(s) < 43 || strings.ContainsAny(s, "\r\n") {
			t.Fatalf("accepted %q", b)
		}
	})
}

// FuzzCheckPublicKey: an accepted .pub file holds exactly the wanted key.
func FuzzCheckPublicKey(f *testing.F) {
	pub := ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		f.Fatal(err)
	}
	want := sp.Marshal()
	line := ssh.MarshalAuthorizedKey(sp)
	f.Add(line)
	f.Add(append(bytes.TrimSuffix(line, []byte("\n")), []byte(" shell-mcp\n")...))
	f.Add([]byte("ssh-ed25519 AAAA\n"))
	f.Add([]byte(`restrict ` + string(line)))
	f.Fuzz(func(t *testing.T, b []byte) {
		if checkPublicKey(b, want) != nil {
			return
		}
		k, _, opts, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil || !bytes.Equal(k.Marshal(), want) || len(opts) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("accepted %q", b)
		}
	})
}
