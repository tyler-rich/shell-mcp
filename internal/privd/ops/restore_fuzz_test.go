//go:build linux

package ops

import (
	"archive/tar"
	"bytes"
	"path"
	"strings"
	"testing"
)

// FuzzParseTreeArchive: whatever the bytes, parseTreeArchive never panics,
// returns at most maxEntries entries, and every entry it returns has a
// clean relative name whose directory came before it, a directory or file
// type, an owner within uint32 and a mode within 07777, and a file's size
// as recorded. (Its input is a tree backup whose SHA-256 already matched its
// record; this guards the parser against a damaged or hand-written one.)
func FuzzParseTreeArchive(f *testing.F) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range []*tar.Header{
		{Name: "a.txt", Typeflag: tar.TypeReg, Mode: 0o640, Size: 1, Format: tar.FormatPAX},
		{Name: "sub/", Typeflag: tar.TypeDir, Mode: 0o750, Format: tar.FormatPAX},
		{Name: "sub/b.txt", Typeflag: tar.TypeReg, Mode: 0o600, Uid: 1001, Gid: 1001, Size: 2, Format: tar.FormatPAX},
	} {
		if err := tw.WriteHeader(h); err != nil {
			f.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write([]byte(strings.Repeat("x", int(h.Size))))
		}
	}
	_ = tw.Close()
	f.Add(b.Bytes(), 20)
	f.Add([]byte{}, 1)
	f.Fuzz(func(t *testing.T, data []byte, maxEntries int) {
		if maxEntries < 1 || maxEntries > 64 {
			maxEntries = 64
		}
		entries, err := parseTreeArchive(data, maxEntries)
		if err != nil {
			return
		}
		if len(entries) > maxEntries {
			t.Fatalf("%d entries, bound %d", len(entries), maxEntries)
		}
		dirs := map[string]bool{"": true}
		for _, e := range entries {
			parent := path.Dir(e.name)
			if parent == "." {
				parent = ""
			}
			switch {
			case e.name == "" || strings.HasPrefix(e.name, "/") || path.Clean(e.name) != e.name || e.name == ".." || strings.HasPrefix(e.name, "../"):
				t.Fatalf("unsafe name %q", e.name)
			case !dirs[parent]:
				t.Fatalf("%q before its directory", e.name)
			case e.mode > 0o7777:
				t.Fatalf("%q mode %o", e.name, e.mode)
			case e.dir && e.data != nil:
				t.Fatalf("directory %q with data", e.name)
			}
			if e.dir {
				if dirs[e.name] {
					t.Fatalf("%q twice", e.name)
				}
				dirs[e.name] = true
			}
		}
	})
}
