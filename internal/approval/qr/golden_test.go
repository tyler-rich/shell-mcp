package qr

import (
	"bufio"
	"encoding/base32"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// golden is one case of testdata/golden.txt (see its header).
type golden struct {
	id      string
	payload []byte
	mask    int // -1 for automatic
	version int
	chosen  int
	rows    []string
}

// rfcSeed is the RFC 6238 Appendix B SHA-1 test seed, a published test value.
var rfcSeed = []byte("12345678901234567890")

func otpauthURI(name string) string {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rfcSeed)
	return "otpauth://totp/shell-mcp:" + name + "?secret=" + secret + "&issuer=shell-mcp&algorithm=SHA1&digits=6&period=30"
}

func loadGolden(t testing.TB) []golden {
	t.Helper()
	f, err := os.Open("testdata/golden.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var cases []golden
	var cur *golden
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, val, _ := strings.Cut(line, " ")
		switch {
		case cur == nil && key != "case":
			// header
		case cur == nil:
			cases = append(cases, golden{id: val})
			cur = &cases[len(cases)-1]
		case key == "payload" && strings.HasPrefix(val, "hex:"):
			if cur.payload, err = hex.DecodeString(val[4:]); err != nil {
				t.Fatal(err)
			}
		case key == "payload" && strings.HasPrefix(val, "uri:"):
			cur.payload = []byte(otpauthURI(val[4:]))
		case key == "mask" && val == "auto":
			cur.mask = -1
		case key == "mask":
			cur.mask = atoi(t, val)
		case key == "version":
			cur.version = atoi(t, val)
		case key == "chosen":
			cur.chosen = atoi(t, val)
		case line == "end":
			cur = nil
		default:
			cur.rows = append(cur.rows, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 30 {
		t.Fatalf("only %d golden cases", len(cases))
	}
	return cases
}

func atoi(t testing.TB, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// matrix renders a code as golden rows.
func matrix(c *Code) []string {
	rows := make([]string, c.Size())
	for y := range rows {
		var b strings.Builder
		for x := range c.Size() {
			if c.Dark(x, y) {
				b.WriteByte('#')
			} else {
				b.WriteByte('.')
			}
		}
		rows[y] = b.String()
	}
	return rows
}

func compare(t *testing.T, g golden, c *Code) {
	t.Helper()
	if c.Version() != g.version || c.Mask() != g.chosen {
		t.Fatalf("version %d mask %d, want version %d mask %d", c.Version(), c.Mask(), g.version, g.chosen)
	}
	got := matrix(c)
	if len(got) != len(g.rows) {
		t.Fatalf("size %d, want %d", len(got), len(g.rows))
	}
	diff := 0
	for y := range got {
		for x := range got[y] {
			if got[y][x] != g.rows[y][x] {
				if diff < 5 {
					t.Errorf("module (%d,%d) = %c, want %c", x, y, got[y][x], g.rows[y][x])
				}
				diff++
			}
		}
	}
	if diff > 0 {
		t.Fatalf("%d modules differ from the golden matrix", diff)
	}
}

// TestGolden: every case matches the reference encoder module for module,
// with the mask it chose (automatic cases) or the one it was given.
func TestGolden(t *testing.T) {
	for _, g := range loadGolden(t) {
		t.Run(g.id, func(t *testing.T) {
			var c *Code
			var err error
			if g.mask < 0 {
				c, err = Encode(g.payload)
			} else {
				c, err = encode(g.payload, g.mask)
			}
			if err != nil {
				t.Fatalf("encode %d bytes: %v", len(g.payload), err)
			}
			compare(t, g, c)
		})
	}
}

func TestGoldenCovers(t *testing.T) {
	versions, masks, uris := map[int]bool{}, map[int]bool{}, 0
	for _, g := range loadGolden(t) {
		versions[g.version] = true
		masks[g.chosen] = true
		if strings.HasPrefix(string(g.payload), "otpauth://") {
			uris++
		}
	}
	for v := 1; v <= 10; v++ {
		if !versions[v] {
			t.Errorf("no golden case of version %d", v)
		}
	}
	for m := range 8 {
		if !masks[m] {
			t.Errorf("no golden case with mask %d", m)
		}
	}
	if uris < 2 {
		t.Errorf("%d otpauth URI cases", uris)
	}
}

func TestCapacity(t *testing.T) {
	// The most each version holds in byte mode at level M.
	caps := []int{14, 26, 42, 62, 84, 106, 122, 152, 180, 213}
	for v, n := range caps {
		for _, l := range []int{n, n + 1} {
			c, err := Encode([]byte(strings.Repeat("x", l)))
			switch {
			case l > MaxBytes:
				if err != ErrTooLong || c != nil {
					t.Fatalf("%d bytes: %v, %v; want ErrTooLong", l, c, err)
				}
			case err != nil:
				t.Fatalf("%d bytes: %v", l, err)
			case l == n && c.Version() != v+1, l == n+1 && c.Version() != v+2:
				t.Fatalf("%d bytes: version %d", l, c.Version())
			}
		}
	}
	if _, err := Encode(make([]byte, 10_000)); err != ErrTooLong {
		t.Fatalf("10000 bytes: %v", err)
	}
}

func TestEncodeRefusesBadMask(t *testing.T) {
	for _, m := range []int{-2, 8, 100} {
		if _, err := encode([]byte("x"), m); err == nil {
			t.Fatalf("mask %d accepted", m)
		}
	}
}

func TestRoundTripGolden(t *testing.T) {
	for _, g := range loadGolden(t) {
		c, err := Encode(g.payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decode(c)
		if err != nil {
			t.Fatalf("%s: decode: %v", g.id, err)
		}
		if string(got) != string(g.payload) {
			t.Fatalf("%s: decoded %q, want %q", g.id, got, g.payload)
		}
	}
}

// TestTerminal: the rendering, read back, is the matrix inside a light quiet
// zone of QuietZone modules, two rows per line, with fixed colours.
func TestTerminal(t *testing.T) {
	for _, g := range loadGolden(t) {
		if g.mask >= 0 {
			continue
		}
		c, err := Encode(g.payload)
		if err != nil {
			t.Fatal(err)
		}
		out := c.Terminal()
		got, err := readTerminal(out)
		if err != nil {
			t.Fatalf("%s: %v", g.id, err)
		}
		// The size is odd, so the last line's lower half lies outside the
		// symbol and is drawn dark.
		n := c.Size() + 2*QuietZone
		if len(got) != n+1 {
			t.Fatalf("%s: %d rows read back, want %d", g.id, len(got), n+1)
		}
		for x, d := range got[n] {
			if d {
				t.Fatalf("%s: module %d below the symbol is light", g.id, x)
			}
		}
		for y := range n {
			for x := range n {
				in := x >= QuietZone && x < n-QuietZone && y >= QuietZone && y < n-QuietZone
				want := in && c.Dark(x-QuietZone, y-QuietZone)
				if got[y][x] != want {
					t.Fatalf("%s: rendered module (%d,%d) = %v, want %v", g.id, x, y, got[y][x], want)
				}
			}
		}
		if lines := strings.Count(out, "\n"); lines != (n+1)/2 {
			t.Fatalf("%s: %d lines, want %d", g.id, lines, (n+1)/2)
		}
	}
}
