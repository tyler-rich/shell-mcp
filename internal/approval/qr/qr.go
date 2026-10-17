// Package qr encodes a QR Code (ISO/IEC 18004) for the enrolment command:
// byte mode, error-correction level M, versions 1-10, the smallest version
// that holds the data, and the mask chosen from all eight by the standard
// penalty scoring. It exists because the standard library has none and the
// otpauth URI is the only thing it encodes (docs/handoff/S4B-APPROVAL.md
// §6.4); it decodes nothing.
package qr

import (
	"errors"
	"strings"
)

// MaxBytes is the most a version 10-M symbol holds in byte mode.
const MaxBytes = 213

// QuietZone is the light border, in modules, that Terminal adds.
const QuietZone = 4

const maxVersion = 10

// ErrTooLong is returned for data longer than MaxBytes.
var ErrTooLong = errors.New("qr: data longer than a version 10-M symbol holds")

// Level M, versions 1-10 (ISO/IEC 18004 table 9): error-correction
// codewords per block and the number of blocks.
var (
	ecPerBlock = [maxVersion + 1]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26}
	numBlocks  = [maxVersion + 1]int{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5}
	// Alignment pattern centre coordinates (annex E).
	alignment = [maxVersion + 1][]int{
		nil, nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
		{6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
	}
)

// rawCodewords is the number of codewords (data and error correction) a
// version holds: its modules minus every function pattern, in bytes.
func rawCodewords(v int) int {
	n := (16*v+128)*v + 64
	if v >= 2 {
		a := v/7 + 2
		n -= (25*a-10)*a - 55
		if v >= 7 {
			n -= 36
		}
	}
	return n / 8
}

func dataCodewords(v int) int { return rawCodewords(v) - ecPerBlock[v]*numBlocks[v] }

func countBits(v int) int {
	if v >= 10 {
		return 16
	}
	return 8
}

// capacity is the most bytes version v holds in byte mode.
func capacity(v int) int { return (dataCodewords(v)*8 - 4 - countBits(v)) / 8 }

// Code is an encoded symbol.
type Code struct {
	version, mask, size int
	modules             []bool
}

// Encode encodes data in the smallest version that holds it, with the
// lowest-penalty mask.
func Encode(data []byte) (*Code, error) { return encode(data, -1) }

// encode encodes data with the given mask, or the best one for -1.
func encode(data []byte, mask int) (*Code, error) {
	if mask < -1 || mask > 7 {
		return nil, errors.New("qr: mask must be 0 to 7")
	}
	if len(data) > MaxBytes {
		return nil, ErrTooLong
	}
	v := 1
	for len(data) > capacity(v) {
		v++
	}
	m := newMatrix(v)
	m.drawCodewords(interleave(v, dataStream(v, data)))
	if mask < 0 {
		best := -1
		for i := range 8 {
			m.applyMask(i)
			m.drawFormat(i)
			if p := m.penalty(); best < 0 || p < best {
				mask, best = i, p
			}
			m.applyMask(i) // XOR again undoes it
		}
	}
	m.applyMask(mask)
	m.drawFormat(mask)
	return &Code{version: v, mask: mask, size: m.size, modules: m.dark}, nil
}

// Version returns the symbol's version, 1 to 10.
func (c *Code) Version() int { return c.version }

// Mask returns the mask pattern used, 0 to 7.
func (c *Code) Mask() int { return c.mask }

// Size returns the width and height in modules, 17+4×version.
func (c *Code) Size() int { return c.size }

// Dark reports whether the module at column x, row y is dark. Coordinates
// outside the symbol are light.
func (c *Code) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= c.size || y >= c.size {
		return false
	}
	return c.modules[y*c.size+x]
}

// Terminal renders the symbol inside a light quiet zone of QuietZone
// modules, two rows per line with Unicode half blocks. Light modules are the
// foreground and dark ones the background, and both colours are set
// explicitly (bright white on black), so it scans on light and dark terminal
// themes alike. The size is odd, so the last line's lower half, outside the
// quiet zone, is dark.
func (c *Code) Terminal() string {
	n := c.size + 2*QuietZone
	light := func(x, y int) bool { return y < n && !c.Dark(x-QuietZone, y-QuietZone) }
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString("\x1b[97;40m")
		for x := range n {
			switch top, bottom := light(x, y), light(x, y+1); {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String()
}

// dataStream is the data codewords: mode indicator, character count, the
// bytes, a terminator of up to four zero bits, zero bits to the codeword
// boundary, then the pad codewords 0xEC and 0x11 alternately (§7.4).
func dataStream(v int, data []byte) []byte {
	var w bitWriter
	w.put(0b0100, 4)
	w.put(len(data), countBits(v))
	for _, b := range data {
		w.put(int(b), 8)
	}
	total := dataCodewords(v) * 8
	w.put(0, min(4, total-w.n))
	w.put(0, (8-w.n%8)%8)
	for pad := 0xec; w.n < total; pad ^= 0xec ^ 0x11 {
		w.put(pad, 8)
	}
	return w.b
}

type bitWriter struct {
	b []byte
	n int
}

func (w *bitWriter) put(v, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.b = append(w.b, 0)
		}
		if v>>i&1 != 0 {
			w.b[len(w.b)-1] |= 0x80 >> (w.n % 8)
		}
		w.n++
	}
}

// interleave splits the data codewords into blocks (the short ones first),
// appends each block's Reed-Solomon codewords and interleaves them (§7.6).
func interleave(v int, data []byte) []byte {
	nb, ec, raw := numBlocks[v], ecPerBlock[v], rawCodewords(v)
	short := nb - raw%nb
	shortData := raw/nb - ec
	gen := rsGenerator(ec)
	blocks := make([][]byte, nb)
	ecc := make([][]byte, nb)
	k := 0
	for i := range nb {
		l := shortData
		if i >= short {
			l++
		}
		blocks[i] = data[k : k+l]
		ecc[i] = rsRemainder(blocks[i], gen)
		k += l
	}
	out := make([]byte, 0, raw)
	for i := range shortData + 1 {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := range ec {
		for _, e := range ecc {
			out = append(out, e[i])
		}
	}
	return out
}

// gfMul multiplies in GF(2^8) modulo x^8+x^4+x^3+x^2+1 (0x11D).
func gfMul(a, b byte) byte {
	var p byte
	for ; b != 0; b >>= 1 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a&0x80 != 0
		a <<= 1
		if carry {
			a ^= 0x1d
		}
	}
	return p
}

// rsGenerator returns the coefficients of (x-α^0)…(x-α^(degree-1)), highest
// degree first, without the leading 1.
func rsGenerator(degree int) []byte {
	g := make([]byte, degree)
	g[degree-1] = 1
	root := byte(1)
	for range degree {
		for j := range g {
			g[j] = gfMul(g[j], root)
			if j+1 < len(g) {
				g[j] ^= g[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return g
}

// rsRemainder is data·x^degree modulo the generator: the block's error
// correction codewords.
func rsRemainder(data, gen []byte) []byte {
	r := make([]byte, len(gen))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i, g := range gen {
			r[i] ^= gfMul(g, f)
		}
	}
	return r
}

// matrix is a symbol under construction.
type matrix struct {
	size     int
	version  int
	dark     []bool
	function []bool
}

func newMatrix(v int) *matrix {
	n := 17 + 4*v
	m := &matrix{size: n, version: v, dark: make([]bool, n*n), function: make([]bool, n*n)}
	for i := range n { // timing patterns
		m.set(6, i, i%2 == 0)
		m.set(i, 6, i%2 == 0)
	}
	m.finder(3, 3)
	m.finder(n-4, 3)
	m.finder(3, n-4)
	a := alignment[v]
	for i, cy := range a {
		for j, cx := range a {
			if (i == 0 && j == 0) || (i == 0 && j == len(a)-1) || (i == len(a)-1 && j == 0) {
				continue // overlaps a finder
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					m.set(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	m.drawFormat(0) // reserves the format areas and the dark module
	if v >= 7 {
		bits := bch(v, 0x1f25, 12)
		for i := range 18 {
			a, b := n-11+i%3, i/3
			m.set(a, b, bits>>i&1 != 0)
			m.set(b, a, bits>>i&1 != 0)
		}
	}
	return m
}

// set draws a function module.
func (m *matrix) set(x, y int, dark bool) {
	m.dark[y*m.size+x] = dark
	m.function[y*m.size+x] = true
}

// finder draws a finder pattern centred at (cx, cy) with its separator.
func (m *matrix) finder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			x, y := cx+dx, cy+dy
			if x >= 0 && y >= 0 && x < m.size && y < m.size {
				d := max(abs(dx), abs(dy))
				m.set(x, y, d != 2 && d != 4)
			}
		}
	}
}

// bch appends the BCH remainder of data by gen (of degree deg) to data.
func bch(data, gen, deg int) int {
	r := data
	for range deg {
		r = r<<1 ^ (r>>(deg-1))*gen
	}
	return data<<deg | r
}

// drawFormat draws both copies of the format information for level M and
// mask (§7.9), and the dark module.
func (m *matrix) drawFormat(mask int) {
	const levelM = 0b00
	bits := bch(levelM<<3|mask, 0x537, 10) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 != 0 }
	n := m.size
	for i := range 6 {
		m.set(8, i, bit(i))
	}
	m.set(8, 7, bit(6))
	m.set(8, 8, bit(7))
	m.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		m.set(14-i, 8, bit(i))
	}
	for i := range 8 {
		m.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		m.set(8, n-15+i, bit(i))
	}
	m.set(8, n-8, true)
}

// drawCodewords places the codewords' bits in the two-column zigzag from
// the bottom right (§7.7.3); remainder bits stay light.
func (m *matrix) drawCodewords(words []byte) {
	n, i := m.size, 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 { // skip the vertical timing pattern
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := range n {
			y := vert
			if upward {
				y = n - 1 - vert
			}
			for x := right; x >= right-1; x-- {
				if m.function[y*n+x] || i >= len(words)*8 {
					continue
				}
				m.dark[y*n+x] = words[i/8]>>(7-i%8)&1 != 0
				i++
			}
		}
	}
}

// applyMask XORs mask pattern k over every non-function module (§7.8.2).
func (m *matrix) applyMask(k int) {
	n := m.size
	for y := range n {
		for x := range n {
			if !m.function[y*n+x] && maskBit(k, x, y) {
				m.dark[y*n+x] = !m.dark[y*n+x]
			}
		}
	}
}

func maskBit(k, x, y int) bool {
	switch k {
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

// Penalty weights (§7.8.3).
const (
	penaltyN1 = 3
	penaltyN2 = 3
	penaltyN3 = 40
	penaltyN4 = 10
)

// penalty scores the masked symbol (§7.8.3): runs of five or more of one
// colour in a row or column (N1), 2×2 blocks of one colour (N2), finder-like
// 1:1:3:1:1 patterns with four light modules on one side (N3), and the
// dark/light balance (N4). N3 counts the area outside the symbol as light;
// this reading matches the encoder the golden fixtures come from
// (testdata/golden.txt), so the mask choice does too.
func (m *matrix) penalty() int {
	n := m.size
	at := func(x, y int) bool { return m.dark[y*n+x] }
	score := 0
	for _, column := range []bool{false, true} {
		for i := range n {
			line := func(j int) bool {
				if column {
					return at(i, j)
				}
				return at(j, i)
			}
			score += m.linePenalty(line)
		}
	}
	dark := 0
	for y := range n - 1 {
		for x := range n - 1 {
			c := at(x, y)
			if c == at(x+1, y) && c == at(x, y+1) && c == at(x+1, y+1) {
				score += penaltyN2
			}
		}
	}
	for _, d := range m.dark {
		if d {
			dark++
		}
	}
	total := n * n
	// The smallest k with (45-5k)% <= dark/total <= (55+5k)%.
	k := (abs(dark*20-total*10)+total-1)/total - 1
	return score + k*penaltyN4
}

// linePenalty is N1 and N3 for one row or column.
func (m *matrix) linePenalty(at func(int) bool) int {
	n := m.size
	score := 0
	var h runHistory
	color, run := false, 0
	for i := range n {
		if at(i) == color {
			run++
			switch {
			case run == 5:
				score += penaltyN1
			case run > 5:
				score++
			}
			continue
		}
		h.add(run, n)
		if !color {
			score += h.finderLike() * penaltyN3
		}
		color, run = at(i), 1
	}
	// End of the line: close a dark run, then add the light border.
	if color {
		h.add(run, n)
		run = 0
	}
	h.add(run+n, n)
	return score + h.finderLike()*penaltyN3
}

// runHistory holds the last seven run lengths, newest first; the first run
// of a line has the light area before the symbol added to it.
type runHistory struct {
	r    [7]int
	used bool
}

func (h *runHistory) add(run, size int) {
	if !h.used {
		run += size
		h.used = true
	}
	copy(h.r[1:], h.r[:6])
	h.r[0] = run
}

// finderLike counts 1:1:3:1:1 patterns (dark, light, dark×3, light, dark)
// ending at the light run just added, with four light modules before or
// after: 0, 1 or 2.
func (h *runHistory) finderLike() int {
	n := h.r[1]
	core := n > 0 && h.r[2] == n && h.r[3] == 3*n && h.r[4] == n && h.r[5] == n
	c := 0
	if core && h.r[0] >= 4*n && h.r[6] >= n {
		c++
	}
	if core && h.r[6] >= 4*n && h.r[0] >= n {
		c++
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
