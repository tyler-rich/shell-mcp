package qr

import (
	"errors"
	"fmt"
	"strings"
)

// A minimal QR decoder for tests, written from ISO/IEC 18004 independently of
// the encoder: its own tables, function-pattern map, mask formulas and
// GF(256) arithmetic. It reads only what the encoder writes (byte mode,
// level M, versions 1-10) and checks everything strictly: both format
// copies, the version information, every Reed-Solomon block, the
// terminator and the padding.

var (
	// Level M: error-correction codewords per block, and the data
	// codewords of each block, for versions 1-10.
	tEC     = [11]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26}
	tBlocks = [11][]int{
		nil, {16}, {28}, {44}, {32, 32}, {43, 43}, {27, 27, 27, 27},
		{31, 31, 31, 31}, {38, 38, 39, 39}, {36, 36, 36, 37, 37}, {43, 43, 43, 43, 44},
	}
	tAlign = [11][]int{nil, nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}}
)

func tFunction(v int) [][]bool {
	n := 17 + 4*v
	f := make([][]bool, n)
	for y := range f {
		f[y] = make([]bool, n)
		for x := range f[y] {
			f[y][x] = x == 6 || y == 6 || // timing
				(x <= 8 && y <= 8) || (x >= n-8 && y <= 8) || (x <= 8 && y >= n-8) || // finders, separators, format, dark module
				(v >= 7 && ((x >= n-11 && x < n-8 && y < 6) || (y >= n-11 && y < n-8 && x < 6))) // version information
		}
	}
	a := tAlign[v]
	for _, cy := range a {
		for _, cx := range a {
			if (cx == 6 && cy == 6) || (cx == 6 && cy == a[len(a)-1]) || (cx == a[len(a)-1] && cy == 6) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					f[cy+dy][cx+dx] = true
				}
			}
		}
	}
	return f
}

func tMask(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	}
	return ((x+y)%2+x*y%3)%2 == 0
}

func tGFMul(a, b byte) byte {
	var p byte
	for b > 0 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return p
}

// tBCH returns data (bits wide) with its BCH remainder appended.
func tBCH(data, gen uint32, genDegree, bits int) uint32 {
	r := data << genDegree
	for i := bits + genDegree - 1; i >= genDegree; i-- {
		if r&(1<<i) != 0 {
			r ^= gen << (i - genDegree)
		}
	}
	return data<<genDegree | r
}

func decode(c *Code) ([]byte, error) {
	n := c.Size()
	v := (n - 17) / 4
	if v < 1 || v > 10 || 17+4*v != n {
		return nil, fmt.Errorf("size %d", n)
	}
	dark := func(x, y int) bool { return c.Dark(x, y) }

	// Fixed patterns.
	for _, o := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		for dy := range 7 {
			for dx := range 7 {
				ring := max(abs(dx-3), abs(dy-3))
				if dark(o[0]+dx, o[1]+dy) != (ring != 2) {
					return nil, errors.New("finder pattern")
				}
			}
		}
	}
	for i := 8; i < n-8; i++ {
		if dark(i, 6) != (i%2 == 0) || dark(6, i) != (i%2 == 0) {
			return nil, errors.New("timing pattern")
		}
	}
	if !dark(8, n-8) {
		return nil, errors.New("dark module")
	}

	// Format information, both copies.
	var f1, f2 uint32
	for i := range 15 {
		var a, b bool
		switch {
		case i < 6:
			a = dark(8, i)
		case i < 8:
			a = dark(8, i+1)
		case i == 8:
			a = dark(7, 8)
		default:
			a = dark(14-i, 8)
		}
		if i < 8 {
			b = dark(n-1-i, 8)
		} else {
			b = dark(8, n-15+i)
		}
		if a {
			f1 |= 1 << i
		}
		if b {
			f2 |= 1 << i
		}
	}
	if f1 != f2 {
		return nil, errors.New("format copies differ")
	}
	f1 ^= 0x5412
	if tBCH(f1>>10, 0x537, 10, 5) != f1 {
		return nil, errors.New("format BCH")
	}
	if f1>>13 != 0 { // level M
		return nil, fmt.Errorf("error-correction level bits %02b", f1>>13)
	}
	mask := int(f1>>10) & 7
	if mask != c.Mask() {
		return nil, errors.New("format mask differs from Mask()")
	}

	// Version information.
	if v >= 7 {
		want := tBCH(uint32(v), 0x1f25, 12, 6)
		for i := range 18 {
			bit := want&(1<<i) != 0
			a, b := n-11+i%3, i/3
			if dark(a, b) != bit || dark(b, a) != bit {
				return nil, errors.New("version information")
			}
		}
	}

	// Codewords, in placement order.
	fn := tFunction(v)
	var bits []bool
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range n {
			for j := range 2 {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if !fn[y][x] {
					bits = append(bits, dark(x, y) != tMask(mask, x, y))
				}
			}
		}
	}
	blocks := tBlocks[v]
	ec := tEC[v]
	total := 0
	for _, d := range blocks {
		total += d + ec
	}
	if len(bits) < total*8 || len(bits)-total*8 > 7 {
		return nil, fmt.Errorf("%d data modules for %d codewords", len(bits), total)
	}
	for _, b := range bits[total*8:] {
		if b {
			return nil, errors.New("remainder bit set")
		}
	}
	words := make([]byte, total)
	for i := range words {
		for j := range 8 {
			if bits[i*8+j] {
				words[i] |= 0x80 >> j
			}
		}
	}

	// De-interleave and check each block's syndromes.
	data := make([][]byte, len(blocks))
	ecw := make([][]byte, len(blocks))
	k := 0
	for i := range blocks[len(blocks)-1] {
		for b, d := range blocks {
			if i < d {
				data[b] = append(data[b], words[k])
				k++
			}
		}
	}
	for range ec {
		for b := range blocks {
			ecw[b] = append(ecw[b], words[k])
			k++
		}
	}
	var stream []byte
	for b := range blocks {
		cw := append(append([]byte(nil), data[b]...), ecw[b]...)
		alpha := byte(1)
		for range ec {
			var s byte
			for _, w := range cw {
				s = tGFMul(s, alpha) ^ w
			}
			if s != 0 {
				return nil, fmt.Errorf("block %d: Reed-Solomon syndrome", b)
			}
			alpha = tGFMul(alpha, 2)
		}
		stream = append(stream, data[b]...)
	}

	// The bit stream: byte mode, count, data, terminator, padding.
	r := bitReader{b: stream}
	if r.read(4) != 0b0100 {
		return nil, errors.New("not byte mode")
	}
	countBits := 8
	if v >= 10 {
		countBits = 16
	}
	cnt := r.read(countBits)
	out := make([]byte, 0, cnt)
	for range cnt {
		if r.left() < 8 {
			return nil, errors.New("count exceeds the data")
		}
		out = append(out, byte(r.read(8)))
	}
	if t := min(4, r.left()); r.read(t) != 0 {
		return nil, errors.New("terminator")
	}
	if r.read((8-r.pos%8)%8) != 0 {
		return nil, errors.New("padding bits")
	}
	for i := 0; r.left() > 0; i++ {
		if want := [2]uint32{0xec, 0x11}[i%2]; r.read(8) != want {
			return nil, errors.New("pad codewords")
		}
	}
	return out, nil
}

type bitReader struct {
	b   []byte
	pos int
}

func (r *bitReader) left() int { return len(r.b)*8 - r.pos }

func (r *bitReader) read(n int) uint32 {
	var v uint32
	for range n {
		if r.pos >= len(r.b)*8 {
			return 0xffffffff
		}
		v = v<<1 | uint32(r.b[r.pos/8]>>(7-r.pos%8)&1)
		r.pos++
	}
	return v
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// readTerminal reads Terminal's output back into modules (true for dark).
func readTerminal(out string) ([][]bool, error) {
	const pre, post = "\x1b[97;40m", "\x1b[0m"
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	var rows [][]bool
	for i, l := range lines {
		if !strings.HasPrefix(l, pre) || !strings.HasSuffix(l, post) {
			return nil, fmt.Errorf("line %d: colours", i+1)
		}
		var top, bottom []bool
		for _, g := range strings.TrimSuffix(strings.TrimPrefix(l, pre), post) {
			// Light modules are drawn in the foreground colour.
			switch g {
			case '█':
				top, bottom = append(top, false), append(bottom, false)
			case '▀':
				top, bottom = append(top, false), append(bottom, true)
			case '▄':
				top, bottom = append(top, true), append(bottom, false)
			case ' ':
				top, bottom = append(top, true), append(bottom, true)
			default:
				return nil, fmt.Errorf("line %d: glyph %q", i+1, g)
			}
		}
		if len(rows) > 0 && len(top) != len(rows[0]) {
			return nil, fmt.Errorf("line %d: width", i+1)
		}
		rows = append(rows, top, bottom)
	}
	return rows, nil
}
