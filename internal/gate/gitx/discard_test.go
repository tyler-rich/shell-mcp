package gitx

import (
	"strings"
	"testing"
)

// Records as git 2.47.3 prints them (shapes taken from a throwaway
// repository; paths and ids invented).
const (
	oidA = "78981922613b2afb6025042ff6bd878ac1994e85"
	oidB = "28ce6a8b26aa170e1de65536fe8abe1832bd3242"
	oid0 = "0000000000000000000000000000000000000000"
)

func rec(fields ...string) string { return strings.Join(fields, " ") + "\x00" }

func TestParseDiscardStatus(t *testing.T) {
	in := "# branch.oid " + oidA + "\x00" +
		rec("1", "MM", "N...", "100644", "100644", "100644", oidA, oidB, "d/a") +
		rec("1", "A.", "N...", "000000", "100644", "100644", oid0, oidB, "new file.txt") +
		rec("1", ".D", "N...", "120000", "120000", "000000", oidA, oidA, "lnk") +
		rec("u", "UU", "N...", "100644", "100644", "100644", "100644", oidA, oidB, oidA, "conflict")
	got, truncated, err := ParseDiscardStatus([]byte(in), 10)
	if err != nil || truncated {
		t.Fatalf("parse: %v %v", err, truncated)
	}
	want := []DiscardEntry{
		{Kind: "changed", XY: "MM", Sub: "N...", ModeHead: "100644", ModeIndex: "100644", ModeWorktree: "100644", OIDHead: oidA, OIDIndex: oidB, Path: "d/a"},
		{Kind: "changed", XY: "A.", Sub: "N...", ModeHead: "000000", ModeIndex: "100644", ModeWorktree: "100644", OIDHead: oid0, OIDIndex: oidB, Path: "new file.txt"},
		{Kind: "changed", XY: ".D", Sub: "N...", ModeHead: "120000", ModeIndex: "120000", ModeWorktree: "000000", OIDHead: oidA, OIDIndex: oidA, Path: "lnk"},
		{Kind: "unmerged", XY: "UU", Sub: "N...", ModeHead: "", ModeIndex: "", ModeWorktree: "100644", Path: "conflict"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %+v want %+v", i, got[i], want[i])
		}
	}
	if got, truncated, err = ParseDiscardStatus([]byte(in), 2); err != nil || !truncated || len(got) != 2 {
		t.Fatalf("bounded: %d %v %v", len(got), truncated, err)
	}
	if got, _, err = ParseDiscardStatus(nil, 10); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestParseDiscardStatusRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"renamed":       "2 R. N... 100644 100644 100644 " + oidA + " " + oidA + " R100 b\x00a\x00",
		"untracked":     "? x\x00",
		"ignored":       "! x\x00",
		"short xy":      rec("1", "M", "N...", "100644", "100644", "100644", oidA, oidB, "a"),
		"bad sub":       rec("1", "M.", "N..", "100644", "100644", "100644", oidA, oidB, "a"),
		"bad mode":      rec("1", "M.", "N...", "10064x", "100644", "100644", oidA, oidB, "a"),
		"bad oid":       rec("1", "M.", "N...", "100644", "100644", "100644", oidA[:39], oidB, "a"),
		"upper oid":     rec("1", "M.", "N...", "100644", "100644", "100644", strings.ToUpper(oidA), oidB, "a"),
		"empty path":    rec("1", "M.", "N...", "100644", "100644", "100644", oidA, oidB, ""),
		"missing field": rec("1", "M.", "N...", "100644", "100644", oidA, oidB, "a"),
		"unknown":       "x y\x00",
		"no terminator": strings.TrimSuffix(rec("1", "M.", "N...", "100644", "100644", "100644", oidA, oidB, "a"), "\x00"),
	} {
		if _, _, err := ParseDiscardStatus([]byte(in), 10); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzParseDiscardStatus: never panics, honours the bound, and every entry
// it returns has fields of the documented shapes; a record it accepts
// round-trips through the format.
func FuzzParseDiscardStatus(f *testing.F) {
	f.Add([]byte(rec("1", "MM", "N...", "100644", "100644", "100644", oidA, oidB, "d/a")), 3)
	f.Add([]byte(rec("u", "UU", "N...", "100644", "100644", "100644", "100644", oidA, oidB, oidA, "c")), 1)
	f.Add([]byte("# branch.oid (initial)\x00"), 0)
	f.Fuzz(func(t *testing.T, b []byte, maxEntries int) {
		if maxEntries < 0 || maxEntries > 1000 {
			return
		}
		got, _, err := ParseDiscardStatus(b, maxEntries)
		if err != nil {
			return
		}
		if len(got) > maxEntries {
			t.Fatalf("%d entries above the bound %d", len(got), maxEntries)
		}
		for i := range got {
			e := &got[i]
			if len(e.XY) != 2 || len(e.Sub) != 4 || e.Path == "" || strings.IndexByte(e.Path, 0) >= 0 {
				t.Fatalf("bad entry %+v", e)
			}
			if e.Kind == "changed" {
				for _, m := range []string{e.ModeHead, e.ModeIndex, e.ModeWorktree} {
					if !isMode(m) {
						t.Fatalf("bad mode in %+v", e)
					}
				}
				if !isOID(e.OIDHead) || !isOID(e.OIDIndex) {
					t.Fatalf("bad oid in %+v", e)
				}
				again, _, err := ParseDiscardStatus([]byte(rec("1", e.XY, e.Sub, e.ModeHead, e.ModeIndex, e.ModeWorktree, e.OIDHead, e.OIDIndex, e.Path)), 1)
				if err != nil || len(again) != 1 || again[0] != *e {
					t.Fatalf("round trip of %+v: %+v %v", e, again, err)
				}
			}
		}
	})
}
