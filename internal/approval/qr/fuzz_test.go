package qr

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzEncode: any input either is refused as too long (and only then) or
// encodes, without panicking, into the smallest version that holds it, and
// the independent test decoder reads back exactly the input.
func FuzzEncode(f *testing.F) {
	for _, s := range []string{"", "A", "otpauth://totp/shell-mcp:alice?issuer=shell-mcp", "\x00\xff\x80", string(make([]byte, MaxBytes)), string(make([]byte, MaxBytes+1))} {
		f.Add([]byte(s))
	}
	caps := []int{14, 26, 42, 62, 84, 106, 122, 152, 180, 213}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Encode(data)
		if len(data) > MaxBytes {
			if !errors.Is(err, ErrTooLong) || c != nil {
				t.Fatalf("%d bytes: %v, %v", len(data), c, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("%d bytes: %v", len(data), err)
		}
		v := c.Version()
		if v < 1 || v > 10 || c.Size() != 17+4*v || c.Mask() < 0 || c.Mask() > 7 {
			t.Fatalf("version %d size %d mask %d", v, c.Size(), c.Mask())
		}
		if len(data) > caps[v-1] || (v > 1 && len(data) <= caps[v-2]) {
			t.Fatalf("%d bytes in version %d", len(data), v)
		}
		// Out-of-range reads are light, never a panic.
		for _, p := range [][2]int{{-1, 0}, {0, -1}, {c.Size(), 0}, {0, c.Size()}, {1 << 30, 1 << 30}} {
			if c.Dark(p[0], p[1]) {
				t.Fatalf("module %v outside the symbol is dark", p)
			}
		}
		got, err := decode(c)
		if err != nil {
			t.Fatalf("%d bytes: decode: %v", len(data), err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("decoded %q, want %q", got, data)
		}
	})
}
