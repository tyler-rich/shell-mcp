//go:build linux

package selfcheck_test

import (
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/selfcheck"
)

// FuzzParseStatus: arbitrary bytes never panic the parser, and whatever it
// accepts passes Process only with all four uids 0 and NoNewPrivs set.
func FuzzParseStatus(f *testing.F) {
	f.Add([]byte(status("0", "1", "000000000000000f")))
	f.Add([]byte(status("1000", "0", "000001ffffffffff")))
	f.Add([]byte("Uid:\t0 0 0 0\nCapBnd:\t0\nNoNewPrivs:\t1\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := selfcheck.ParseStatus(b)
		if err != nil {
			return
		}
		if selfcheck.Process(&s) == nil && (s.UIDs != [4]uint32{} || !s.NoNewPrivs) {
			t.Fatalf("Process accepted %+v", s)
		}
	})
}
