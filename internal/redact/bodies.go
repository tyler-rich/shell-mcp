package redact

import (
	"bytes"
	"regexp"
)

// LineFormat says how MaskKeyBodies finds a line's content.
type LineFormat int

// Line formats.
const (
	// PlainLines: a line's content is the line without its surrounding
	// blanks.
	PlainLines LineFormat = iota
	// JournalLines: journalctl -o short-iso output. A line's content
	// follows "<time> <host> <identifier>[<pid>]: ", and an indented line
	// (a later line of a multi-line message) is its content after the
	// blanks.
	JournalLines
)

var (
	journalPrefix = regexp.MustCompile(`^\S+ \S+ [^ :]+: `)
	// A BEGIN or END line of any PEM label: the content between them is
	// shown with its header, so it is not a headerless body.
	pemBegin = regexp.MustCompile(`-{5}BEGIN ([A-Z0-9 ]+)-{5}`)
)

// MaskKeyBodies masks what may be a private key's body shown without its
// BEGIN line (handoff N-35): each run of lines whose content is exactly 64
// or 70 base64 characters (PEM's widths: OpenSSL and Go wrap at 64,
// OpenSSH at 70), all of one width and not all hexadecimal, with the
// shorter base64 line that may follow (lastLineLength), outside every PEM
// block whose BEGIN line is shown. Each such line's content is replaced by
// Mask; its prefix, its line ending and every other line are kept. It is a
// heuristic for output that a source cut before redaction (a journal
// window, a range of a command's input), applied after Bytes; it also masks
// a headerless window into a certificate or other PEM block, and base64
// wrapped at those widths. Measured on 12.3 million lines of ordinary text,
// it matched outside a PEM block 11 times (ARCHIVE §14, S7-6). b is not
// modified.
func MaskKeyBodies(b []byte, f LineFormat) []byte {
	lines := bytes.SplitAfter(b, []byte("\n"))
	type span struct{ line, from, to int }
	var (
		masked []span
		run    []span
		width  int
		open   string
	)
	flush := func() {
		masked = append(masked, run...)
		run, width = nil, 0
	}
	for i, l := range lines {
		from, to := content(l, f)
		c := l[from:to]
		if m := pemBegin.FindSubmatch(l); m != nil {
			flush()
			if open == "" {
				open = string(m[1])
			}
			continue
		}
		if open != "" {
			if bytes.Contains(l, []byte("-----END "+open+"-----")) {
				open = ""
			}
			continue
		}
		switch w := len(c); {
		case (w == 64 || w == 70) && fullLine(c):
			if width != 0 && w != width {
				flush()
			}
			run, width = append(run, span{i, from, to}), w
		case width != 0 && w > 0 && w < width && lastLineLength(w, width) && base64Line(c):
			run = append(run, span{i, from, to})
			flush()
		default:
			flush()
		}
	}
	flush()
	if len(masked) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	next := 0
	for i, l := range lines {
		if next < len(masked) && masked[next].line == i {
			s := masked[next]
			out = append(append(append(out, l[:s.from]...), Mask...), l[s.to:]...)
			next++
			continue
		}
		out = append(out, l...)
	}
	return out
}

// content returns the bounds of line l's content under f.
func content(l []byte, f LineFormat) (from, to int) {
	to = len(l)
	for to > 0 && (l[to-1] == '\n' || l[to-1] == '\r' || l[to-1] == ' ' || l[to-1] == '\t') {
		to--
	}
	if f == JournalLines {
		if m := journalPrefix.FindIndex(l[:to]); m != nil {
			from = m[1]
		}
	}
	for from < to && (l[from] == ' ' || l[from] == '\t') {
		from++
	}
	return from, to
}

// base64Line reports whether c is base64 characters with at most two '='
// at its end.
func base64Line(c []byte) bool {
	end := len(c)
	for i := 0; i < 2 && end > 0 && c[end-1] == '='; i++ {
		end--
	}
	if end == 0 {
		return false
	}
	for _, x := range c[:end] {
		if !(x >= 'A' && x <= 'Z' || x >= 'a' && x <= 'z' || x >= '0' && x <= '9' || x == '+' || x == '/') {
			return false
		}
	}
	return true
}

// lastLineLength reports whether w can be the length of the last line of a
// PEM body wrapped at width: base64 with padding is a multiple of 4
// characters long, so after full lines of 64 the last is one too, and
// after lines of 70 (2 modulo 4) it is even. An ordinary short word after a
// body-like line is then mostly not taken for one.
func lastLineLength(w, width int) bool {
	if width == 64 {
		return w%4 == 0
	}
	return w%2 == 0
}

// fullLine reports whether c, a line of PEM width, is base64 and not all
// hexadecimal (a SHA-256 is 64 hex digits).
func fullLine(c []byte) bool {
	if !base64Line(c) {
		return false
	}
	for _, x := range c {
		if !(x >= '0' && x <= '9' || x >= 'a' && x <= 'f' || x >= 'A' && x <= 'F') {
			return true
		}
	}
	return false
}
