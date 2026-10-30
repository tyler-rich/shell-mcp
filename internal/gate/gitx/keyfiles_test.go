package gitx

import (
	"bytes"
	"slices"
	"testing"
)

func TestParseNames(t *testing.T) {
	got, err := ParseNames([]byte("a.key\x00dir/odd [1] *.pem\x00"), "")
	if err != nil || !slices.Equal(got, []string{"a.key", "dir/odd [1] *.pem"}) {
		t.Fatalf("%q %v", got, err)
	}
	got, err = ParseNames([]byte("HEAD:tls/x.key\x00"), "HEAD:")
	if err != nil || !slices.Equal(got, []string{"tls/x.key"}) {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := ParseNames(nil, ""); err != nil || got != nil {
		t.Fatalf("empty: %q %v", got, err)
	}
	for _, bad := range []struct{ out, prefix string }{{"a", ""}, {"a\x00\x00", ""}, {"\x00", ""}, {"x:a\x00", "HEAD:"}, {"HEAD:\x00", "HEAD:"}} {
		if _, err := ParseNames([]byte(bad.out), bad.prefix); err == nil {
			t.Errorf("%q (prefix %q) accepted", bad.out, bad.prefix)
		}
	}
}

// FuzzParseNames: a list parses exactly when it is NUL-terminated names
// that each carry the prefix and are not empty; each name is its bytes
// without the prefix, and joining them back gives the input.
func FuzzParseNames(f *testing.F) {
	f.Add([]byte("a\x00b c\x00"), "")
	f.Add([]byte("HEAD:a\x00HEAD:\x00"), "HEAD:")
	f.Add([]byte("x"), "")
	f.Fuzz(func(t *testing.T, out []byte, prefix string) {
		names, err := ParseNames(out, prefix)
		if err != nil {
			return
		}
		var back []byte
		for _, n := range names {
			if n == "" {
				t.Fatalf("%q: empty name", out)
			}
			back = append(append(append(back, prefix...), n...), 0)
		}
		if !bytes.Equal(back, out) {
			t.Fatalf("%q (prefix %q): parsed %q, which joins to %q", out, prefix, names, back)
		}
	})
}
