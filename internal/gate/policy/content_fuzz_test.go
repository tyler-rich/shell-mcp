package policy

import (
	"bytes"
	"testing"
)

// FuzzScanFor: the chunked scan finds exactly the patterns bytes.Contains
// finds in the whole input, whatever the chunk size, so a marker split
// across two reads is never missed.
func FuzzScanFor(f *testing.F) {
	f.Add([]byte("xx\x00env\x00yy"), []byte("\x00env\x00"), []byte("BusyBox v"), uint8(1))
	f.Add([]byte("the BusyBox v1 banner"), []byte("Box v"), []byte(""), uint8(3))
	f.Add([]byte("aaaa"), []byte("aaaaa"), []byte("a"), uint8(2))
	f.Fuzz(func(t *testing.T, data, p1, p2 []byte, chunk uint8) {
		if len(p1) == 0 || len(p2) == 0 || len(p1) > 64 || len(p2) > 64 {
			return
		}
		pats := [][]byte{p1, p2}
		found, err := scanFor(bytes.NewReader(data), pats, int(chunk%17)+1)
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range pats {
			if found[i] != bytes.Contains(data, p) {
				t.Fatalf("pattern %q in %q: found %v", p, data, found[i])
			}
		}
	})
}
