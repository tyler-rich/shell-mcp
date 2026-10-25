//go:build linux

package fsx

import (
	"encoding/binary"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

// decodePreviewEntry is appendPreviewEntry's inverse, for the fuzz target.
func decodePreviewEntry(b []byte) (path string, id ident, rest []byte, ok bool) {
	n, k := binary.Uvarint(b)
	if k <= 0 || uint64(len(b)-k) < n { //nolint:gosec // G115: len(b)-k is not negative here
		return "", ident{}, nil, false
	}
	path, b = string(b[k:k+int(n)]), b[k+int(n):] //nolint:gosec // G115: n is at most len(b)
	if len(b) < 4+8*4+4+1 {
		return "", ident{}, nil, false
	}
	id.typ, b = binary.BigEndian.Uint32(b), b[4:]
	id.size, b = int64(binary.BigEndian.Uint64(b)), b[8:] //nolint:gosec // G115: bits back
	id.dev, b = binary.BigEndian.Uint64(b), b[8:]
	id.ino, b = binary.BigEndian.Uint64(b), b[8:]
	id.ctime.Sec, b = int64(binary.BigEndian.Uint64(b)), b[8:] //nolint:gosec // G115: bits back
	id.ctime.Nsec, b = binary.BigEndian.Uint32(b), b[4:]
	switch b[0] {
	case 0:
		return path, id, b[1:], true
	case 1:
		b = b[1:]
		if len(b) < 12 {
			return "", ident{}, nil, false
		}
		id.hasBtime = true
		id.btime.Sec, b = int64(binary.BigEndian.Uint64(b)), b[8:] //nolint:gosec // G115: bits back
		id.btime.Nsec, b = binary.BigEndian.Uint32(b), b[4:]
		return path, id, b, true
	}
	return "", ident{}, nil, false
}

// FuzzPreviewEntryEncoding: an entry's hash input decodes back to exactly
// that entry, so two different entries (or lists of entries) never feed
// the preview hash the same bytes.
func FuzzPreviewEntryEncoding(f *testing.F) {
	f.Add("/srv/app/old", uint32(0o100000), int64(12), uint64(2049), uint64(77), int64(1760000000), uint32(5), true, int64(1750000000), uint32(9), "/srv/app/old/a")
	f.Add("", uint32(0), int64(-1), uint64(0), uint64(0), int64(0), uint32(0), false, int64(0), uint32(0), "")
	f.Fuzz(func(t *testing.T, path string, typ uint32, size int64, dev, ino uint64, cs int64, cn uint32, hasB bool, bs int64, bn uint32, path2 string) {
		id := ident{typ: typ, size: size, dev: dev, ino: ino, ctime: unix.StatxTimestamp{Sec: cs, Nsec: cn}, hasBtime: hasB}
		if hasB {
			id.btime = unix.StatxTimestamp{Sec: bs, Nsec: bn}
		}
		b := appendPreviewEntry(nil, path, &id)
		b = appendPreviewEntry(b, path2, &id)
		p, got, rest, ok := decodePreviewEntry(b)
		if !ok || p != path || got != id {
			t.Fatalf("first entry: %q %+v ok %v; want %q %+v", p, got, ok, path, id)
		}
		p, got, rest, ok = decodePreviewEntry(rest)
		if !ok || p != path2 || got != id || len(rest) != 0 {
			t.Fatalf("second entry: %q %+v ok %v rest %d", p, got, ok, len(rest))
		}
	})
}

// FuzzHasSetAsideComponent: a path is refused as holding a set-aside name
// exactly when one of its components starts with the prefix.
func FuzzHasSetAsideComponent(f *testing.F) {
	for _, s := range []string{"/srv/app/.shell-mcp-delete-0123", "/srv/app/x.shell-mcp-delete-", ".shell-mcp-delete-", "/srv/.shell-mcp-delet", "//.shell-mcp-delete-/x", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if got, want := hasSetAsideComponent(p), strings.Contains("/"+p, "/"+deleteTempPrefix); got != want {
			t.Fatalf("hasSetAsideComponent(%q) = %v, want %v", p, got, want)
		}
	})
}

// FuzzPreviewPrefix: the prefix a preview hash covers before the entries
// decodes back to exactly its recursive flag and binding (or none, the
// gate's), so two different pairs never hash the same input, and a bound
// prefix never equals the gate's.
func FuzzPreviewPrefix(f *testing.F) {
	f.Add(false, false, "")
	f.Add(true, true, "")
	f.Add(true, true, strings.Repeat("ab", 32))
	f.Add(false, true, "shell-mcp delete preview v1\x00\x01")
	f.Fuzz(func(t *testing.T, recursive, bound bool, binding string) {
		var bp *string
		if bound {
			bp = &binding
		}
		b := previewPrefix(recursive, bp)
		var gotBound bool
		var got string
		switch {
		case strings.HasPrefix(string(b), boundPreviewDomain):
			rest := b[len(boundPreviewDomain):]
			n, k := binary.Uvarint(rest)
			if k <= 0 || uint64(len(rest)-k) < n { //nolint:gosec // G115: not negative here
				t.Fatalf("bound prefix %q does not decode", b)
			}
			gotBound, got, b = true, string(rest[k:k+int(n)]), rest[k+int(n):] //nolint:gosec // G115: n is at most len(rest)
		case strings.HasPrefix(string(b), previewDomain):
			b = b[len(previewDomain):]
		default:
			t.Fatalf("prefix %q has no domain", b)
		}
		if len(b) != 1 || b[0] > 1 || (b[0] == 1) != recursive || gotBound != bound || got != binding && bound {
			t.Fatalf("prefix decodes to recursive %v bound %v binding %q (rest %q), want %v %v %q", b[0] == 1, gotBound, got, b, recursive, bound, binding)
		}
	})
}
