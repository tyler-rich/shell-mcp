package approvers

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Seeds are generated at test time; names are invented.

func readFile(t *testing.T, path string) (string, os.FileInfo) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), fi
}

// onlyFile fails unless dir holds exactly the one file name: no temporary
// file is left behind.
func onlyFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only %s", names, name)
	}
}

func TestAddCreatesFile(t *testing.T) {
	requireModes(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "approvers")
	seed := randBytes(t, MinSeedBytes)
	if err := Add(path, "alice", seed, false); err != nil {
		t.Fatalf("Add: %v", err)
	}
	content, fi := readFile(t, path)
	if want := "alice " + b32.EncodeToString(seed) + "\n"; content != want {
		t.Fatalf("content %q, want the new line", content)
	}
	if fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatalf("mode %v, want 0600", fi.Mode())
	}
	onlyFile(t, dir, "approvers")
	got, err := Load(path, 1)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Seed(), seed) {
		t.Fatalf("Load after Add = %v, %v", got, err)
	}
}

func TestAddAppendsAtomically(t *testing.T) {
	requireModes(t)
	first := "alice " + randSeed(t) + "\n"
	path := writeFile(t, first, 0o600)
	_, before := readFile(t, path)
	seed := randBytes(t, MinSeedBytes)
	if err := Add(path, "bob", seed, true); err != nil {
		t.Fatalf("Add: %v", err)
	}
	content, after := readFile(t, path)
	if want := first + "bob " + b32.EncodeToString(seed) + "\n"; content != want {
		t.Fatalf("content %q, want the old line then the new", content)
	}
	if after.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", after.Mode())
	}
	// Replaced by a rename, never rewritten in place.
	if os.SameFile(before, after) {
		t.Fatal("the file was rewritten in place, not replaced")
	}
	onlyFile(t, filepath.Dir(path), "approvers")
}

func TestAddAddsMissingNewline(t *testing.T) {
	requireModes(t)
	first := "alice " + randSeed(t)
	path := writeFile(t, first, 0o600)
	seed := randBytes(t, MinSeedBytes)
	if err := Add(path, "bob", seed, true); err != nil {
		t.Fatal(err)
	}
	if content, _ := readFile(t, path); content != first+"\nbob "+b32.EncodeToString(seed)+"\n" {
		t.Fatalf("content %q", content)
	}
}

func TestAddToEmptyFile(t *testing.T) {
	requireModes(t)
	path := writeFile(t, "", 0o600)
	seed := randBytes(t, MinSeedBytes)
	if err := Add(path, "alice", seed, false); err != nil {
		t.Fatalf("Add to an empty file: %v", err)
	}
	if content, _ := readFile(t, path); content != "alice "+b32.EncodeToString(seed)+"\n" {
		t.Fatalf("content %q", content)
	}
}

func TestAddRefuses(t *testing.T) {
	requireModes(t)
	seed := randBytes(t, MinSeedBytes)
	one := "alice " + randSeed(t) + "\n"
	var full strings.Builder
	for i := range MaxApprovers {
		fmt.Fprintf(&full, "a%d %s\n", i, randSeed(t))
	}
	for _, c := range []struct {
		name     string
		content  string
		mode     os.FileMode
		approver string
		seed     []byte
		multiple bool
		want     error
		wantText string
	}{
		{"duplicate name", one, 0o600, "alice", seed, true, ErrDuplicate, ""},
		{"second without allow-multiple", one, 0o600, "bob", seed, false, ErrMultiple, ""},
		{"full", full.String(), 0o600, "bob", seed, true, ErrFull, ""},
		{"group-readable", one, 0o640, "bob", seed, true, nil, "group or other"},
		{"other-readable", one, 0o604, "bob", seed, true, nil, "group or other"},
		{"unparsable", "Alice " + randSeed(t) + "\n", 0o600, "bob", seed, true, nil, "line 1"},
		{"invalid name", one, 0o600, "Bob", seed, true, nil, "name"},
		{"short seed", one, 0o600, "bob", seed[:MinSeedBytes-1], true, nil, "seed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeFile(t, c.content, c.mode)
			_, before := readFile(t, path)
			err := Add(path, c.approver, c.seed, c.multiple)
			switch {
			case err == nil:
				t.Fatal("Add accepted it")
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("Add = %v, want %v", err, c.want)
			case c.wantText != "" && !strings.Contains(err.Error(), c.wantText):
				t.Fatalf("Add = %v, want an error containing %q", err, c.wantText)
			}
			noSecret(t, err, b32.EncodeToString(c.seed))
			content, after := readFile(t, path)
			if content != c.content || !os.SameFile(before, after) || after.Mode().Perm() != c.mode {
				t.Fatal("a refused Add changed the file")
			}
			onlyFile(t, filepath.Dir(path), "approvers")
		})
	}
}

func TestAddRefusesWithoutFileWhenDirMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "approvers")
	if err := Add(path, "alice", randBytes(t, MinSeedBytes), false); err == nil {
		t.Fatal("Add into a missing directory succeeded")
	}
}

func TestRemove(t *testing.T) {
	requireModes(t)
	a, b, c := "alice "+randSeed(t)+"\n", "bob "+randSeed(t)+"\n", "carol "+randSeed(t)+"\n"
	path := writeFile(t, a+b+c, 0o600)
	_, before := readFile(t, path)
	if err := Remove(path, "bob"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	content, after := readFile(t, path)
	if content != a+c {
		t.Fatalf("content %q, want the other lines unchanged", content)
	}
	if after.Mode().Perm() != 0o600 || os.SameFile(before, after) {
		t.Fatal("Remove did not replace the file atomically with mode 0600")
	}
	onlyFile(t, filepath.Dir(path), "approvers")

	if err := Remove(path, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path, "carol"); err != nil {
		t.Fatalf("removing the last approver: %v", err)
	}
	if content, _ := readFile(t, path); content != "" {
		t.Fatalf("content %q after removing every approver", content)
	}
}

func TestRemoveRefuses(t *testing.T) {
	requireModes(t)
	one := "alice " + randSeed(t) + "\n"
	for _, c := range []struct {
		name, content, approver string
		mode                    os.FileMode
		want                    error
		wantText                string
	}{
		{"unknown", one, "bob", 0o600, ErrUnknown, ""},
		{"group-readable", one, "alice", 0o640, nil, "group or other"},
		{"unparsable", "Alice " + randSeed(t) + "\n", "alice", 0o600, nil, "line 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeFile(t, c.content, c.mode)
			err := Remove(path, c.approver)
			switch {
			case err == nil:
				t.Fatal("Remove accepted it")
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("Remove = %v, want %v", err, c.want)
			case c.wantText != "" && !strings.Contains(err.Error(), c.wantText):
				t.Fatalf("Remove = %v, want an error containing %q", err, c.wantText)
			}
			if content, _ := readFile(t, path); content != c.content {
				t.Fatal("a refused Remove changed the file")
			}
		})
	}
	if err := Remove(filepath.Join(t.TempDir(), "missing"), "alice"); err == nil {
		t.Fatal("Remove on a missing file succeeded")
	}
}

func TestList(t *testing.T) {
	requireModes(t)
	s1, s2 := randSeed(t), randSeed(t)
	path := writeFile(t, "alice "+s1+"\nbob "+s2+"\n", 0o600)
	got, err := List(path)
	if err != nil || !slices.Equal(got, []string{"alice", "bob"}) {
		t.Fatalf("List = %v, %v", got, err)
	}
	if _, err := List(writeFile(t, "alice "+s1+"\n", 0o644)); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("List of a world-readable file = %v", err)
	}
	if got, err := List(writeFile(t, "", 0o600)); err != nil || len(got) != 0 {
		t.Fatalf("List of an empty file = %v, %v", got, err)
	}
}
