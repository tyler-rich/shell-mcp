package gitx

import (
	"slices"
	"strings"
	"testing"
)

// Inputs are invented; the format is `git diff --cached --raw -z
// --no-renames --full-index` (git 2.47.3 and 2.55).

// rawRec is one raw record: ":<src mode> <dst mode> <src oid> <dst oid> <status>" and the path.
func rawRec(src, dst, srcOID, dstOID, status, path string) string {
	return ":" + src + " " + dst + " " + srcOID + " " + dstOID + " " + status + "\x00" + path + "\x00"
}

var zeroOID = strings.Repeat("0", 40)

func TestParseStagedGitlinks(t *testing.T) {
	in := rawRec("160000", "160000", oidA, oidB, "M", "vendor/lib") +
		rawRec("100644", "100644", oidA, oidB, "M", "app.conf") + // not a gitlink: status reports it
		rawRec("000000", "160000", zeroOID, oidA, "A", "vendor/new lib") +
		rawRec("160000", "000000", oidB, zeroOID, "D", "old") +
		rawRec("160000", "100644", oidA, oidB, "T", "was-lib")
	got, truncated, err := ParseStagedGitlinks([]byte(in), 100)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	want := []Entry{{"changed", "M.", "vendor/lib", ""}, {"changed", "A.", "vendor/new lib", ""}, {"changed", "D.", "old", ""}, {"changed", "T.", "was-lib", ""}}
	if !slices.Equal(got, want) {
		t.Fatalf("entries\n got %+v\nwant %+v", got, want)
	}
	if got, cut, err := ParseStagedGitlinks([]byte(in), 2); err != nil || !cut || len(got) != 2 {
		t.Fatalf("entry bound not applied: %+v %v %v", got, cut, err)
	}
	if got, _, err := ParseStagedGitlinks(nil, 10); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty: %+v %v", got, err)
	}
	for _, b := range []string{
		":160000 160000 " + oidA + " " + oidB + " M\x00", // no path
		rawRec("160000", "160000", oidA, oidB, "R100", "x"),
		rawRec("160000", "160000", "abc", oidB, "M", "x"),
		rawRec("16000", "160000", oidA, oidB, "M", "x"),
		rawRec("160000", "160000", oidA, oidB, "M", ""),
		rawRec("160000", "160000", oidA, oidB, "M", "x")[:20],
		"160000 160000 " + oidA + " " + oidB + " M\x00x\x00",
	} {
		if _, _, err := ParseStagedGitlinks([]byte(b), 10); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

// FuzzParseStagedGitlinks: never panics, honours the bound, and every entry
// is a changed entry with a status letter and a path.
func FuzzParseStagedGitlinks(f *testing.F) {
	f.Add([]byte(rawRec("160000", "160000", oidA, oidB, "M", "vendor/lib")), 3)
	f.Add([]byte(rawRec("000000", "160000", zeroOID, oidA, "A", "a")+rawRec("100644", "100644", oidA, oidB, "M", "b")), 1)
	f.Add([]byte{}, 0)
	f.Fuzz(func(t *testing.T, b []byte, maxEntries int) {
		if maxEntries < 0 || maxEntries > 1000 {
			return
		}
		got, _, err := ParseStagedGitlinks(b, maxEntries)
		if err != nil {
			return
		}
		if len(got) > maxEntries {
			t.Fatalf("%d entries above the bound %d", len(got), maxEntries)
		}
		for _, e := range got {
			if e.Kind != "changed" || len(e.XY) != 2 || e.XY[1] != '.' || !strings.ContainsRune("ADMT", rune(e.XY[0])) || e.Path == "" ||
				strings.IndexByte(e.Path, 0) >= 0 || e.OrigPath != "" {
				t.Fatalf("bad entry %+v", e)
			}
		}
	})
}

func TestSubmoduleKeyName(t *testing.T) {
	for _, k := range []string{"submodule.recurse", "submodule.<name>.url", "diff.ignoreSubmodules", "fetch.recurseSubmodules", "status.submoduleSummary",
		"advice.submodulesNotUpdated", "extensions.submodulePathConfig"} {
		if !SubmoduleKeyName(k) {
			t.Errorf("%s not matched", k)
		}
	}
	for _, k := range []string{"core.editor", "diff.external", "status.showUntrackedFiles", "fetch.prune"} {
		if SubmoduleKeyName(k) {
			t.Errorf("%s matched", k)
		}
	}
	// Every table key is one the rule matches, once.
	seen := map[string]bool{}
	for _, k := range SubmoduleKeys {
		if !SubmoduleKeyName(k.Key) || seen[strings.ToLower(k.Key)] {
			t.Errorf("table key %s: not matched by the rule, or listed twice", k.Key)
		}
		seen[strings.ToLower(k.Key)] = true
	}
}
