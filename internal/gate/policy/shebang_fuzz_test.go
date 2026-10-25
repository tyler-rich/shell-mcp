package policy

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzShebang: parseShebang never panics, reads at most the kernel's 256
// bytes, and returns an interpreter only for a #! file, without blanks,
// NUL or newline, and an argument without NUL, newline or surrounding
// blanks.
func FuzzShebang(f *testing.F) {
	for _, s := range []string{"#!/bin/sh\n", "#! /usr/bin/env -S x y\n", "#!\n", "#!/x", "\x7fELF", "#!/a\x00b\n", "#!" + strings.Repeat("a", 300), "#!/x \t arg \t\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		interp, arg, ok, err := parseShebang(b)
		if !ok {
			if interp != "" || arg != "" || err != nil {
				t.Fatalf("not a script, but %q %q %v", interp, arg, err)
			}
			return
		}
		if len(b) < 2 || b[0] != '#' || b[1] != '!' {
			t.Fatalf("%q taken for a script", b)
		}
		if err != nil {
			return
		}
		if interp == "" || strings.ContainsAny(interp, " \t\n\x00") || strings.ContainsAny(arg, "\n\x00") ||
			strings.TrimLeft(arg, " \t") != arg || strings.TrimRight(arg, " \t") != arg {
			t.Fatalf("%q: interpreter %q, argument %q", b, interp, arg)
		}
		if n := bytes.IndexByte(b, '\n'); n < 0 || n >= 256 {
			t.Fatalf("%q: parsed past the kernel's 256 bytes", b)
		}
	})
}
