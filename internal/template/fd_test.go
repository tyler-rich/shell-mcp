package template

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// {path:read:fd} (POLICY §4, handoff N-22): a {path:read} the gate passes
// to the command as its open descriptor, /dev/fd/(4+k) for the k-th such
// placeholder of the template. Paths are invented.

// fdResolver opens real files under dir for values under /srv/app/, and
// remembers every file it opened.
type fdResolver struct {
	dir    string
	opened []*os.File
}

func (r *fdResolver) ResolvePath(v string, _ bool) (string, error) {
	if strings.HasPrefix(v, "/srv/app/") {
		return "/real" + v, nil
	}
	return "", errDenied
}

func (r *fdResolver) ResolveReadFD(v string) (*os.File, string, error) {
	if !strings.HasPrefix(v, "/srv/app/") {
		return nil, "", errDenied
	}
	f, err := os.Open(filepath.Join(r.dir, filepath.Base(v)))
	if err != nil {
		return nil, "", err
	}
	r.opened = append(r.opened, f)
	return f, "/real" + v, nil
}

func (r *fdResolver) MatchUnit(string) bool { return false }

func newFDResolver(t *testing.T, names ...string) *fdResolver {
	t.Helper()
	r := &fdResolver{dir: t.TempDir()}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(r.dir, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// closed reports whether f was closed (an *os.File refuses Stat once
// closed).
func closed(f *os.File) bool {
	_, err := f.Stat()
	return errors.Is(err, os.ErrClosed)
}

func TestParsePathReadFD(t *testing.T) {
	tpl := mustParse(t, "cat", "{path:read:fd}")
	if tpl.Tokens[1].Kind != PathReadFD || !tpl.UsesPathReadFD() || mustParse(t, "cat", "{path:read}").UsesPathReadFD() {
		t.Fatalf("tokens %+v", tpl.Tokens)
	}
	if got := tpl.String(); !slices.Equal(got, []string{"cat", "{path:read:fd}"}) {
		t.Fatalf("String() = %q", got)
	}
	eight := slices.Repeat([]string{"{path:read:fd}"}, MaxFDTokens)
	if _, err := Parse(eight); err != nil {
		t.Fatalf("%d descriptors: %v", MaxFDTokens, err)
	}
	if _, err := Parse(append(eight, "{path:read:fd}")); err == nil || !strings.Contains(err.Error(), "at most 8 {path:read:fd}") {
		t.Fatalf("%d descriptors: %v", MaxFDTokens+1, err)
	}
	for _, bad := range []string{"{path:read:fd:x}", "{path:write:fd}", "{path:fd}", "{path:read:FD}"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

// TestMatchFD: each {path:read:fd} becomes /dev/fd/(4+k), in template
// order, with the opened file and its real path; the other placeholders
// are unchanged.
func TestMatchFD(t *testing.T) {
	r := newFDResolver(t, "a", "b")
	tpls := []Template{mustParse(t, "x"), mustParse(t, "diff", "{path:read:fd}", "{path:read}", "{path:read:fd}")}
	m, err := MatchFD(tpls, []string{"diff", "/srv/app/a", "/srv/app/c", "/srv/app/b"}, r)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.Index != 1 || !slices.Equal(m.Args, []string{"diff", "/dev/fd/4", "/real/srv/app/c", "/dev/fd/5"}) || len(m.Descriptors) != 2 {
		t.Fatalf("match %+v", m)
	}
	for k, want := range []string{"a", "b"} {
		d := m.Descriptors[k]
		b := make([]byte, 8)
		n, _ := d.File.Read(b)
		if d.FD != FirstFD+k || d.Path != "/real/srv/app/"+want || string(b[:n]) != want {
			t.Fatalf("descriptor %d: %+v read %q", k, d, b[:n])
		}
	}
	m.Close()
	for _, f := range r.opened {
		if !closed(f) {
			t.Fatal("Close left a descriptor open")
		}
	}
	if FDPath(11) != "/dev/fd/11" {
		t.Fatal(FDPath(11))
	}
}

// TestMatchFDClosesOnFailure: a template that opened a descriptor and then
// did not match closes it, and the template that matches gets its own
// numbering from 4; a refused value is a path error.
func TestMatchFDClosesOnFailure(t *testing.T) {
	r := newFDResolver(t, "a")
	tpls := []Template{mustParse(t, "{path:read:fd}", "{int:1-2}"), mustParse(t, "{path:read:fd}", "{regex:^[0-9]+$}")}
	m, err := MatchFD(tpls, []string{"/srv/app/a", "9"}, r)
	if err != nil {
		t.Fatal(err)
	}
	if m.Index != 1 || len(r.opened) != 2 || !closed(r.opened[0]) || closed(r.opened[1]) || m.Descriptors[0].FD != FirstFD {
		t.Fatalf("match %+v, opened %d", m, len(r.opened))
	}
	m.Close()
	r = newFDResolver(t, "a")
	if _, err := MatchFD(tpls[:1], []string{"/srv/app/a", "9"}, r); !errors.Is(err, ErrNoMatch) || len(r.opened) != 1 || !closed(r.opened[0]) {
		t.Fatalf("no match: %v, opened %d", err, len(r.opened))
	}
	var pe *PathError
	if _, err := MatchFD(tpls[:1], []string{"/etc/example-app/a", "1"}, r); !errors.As(err, &pe) || !errors.Is(err, errDenied) {
		t.Fatalf("refused value: %v", err)
	}
	if _, err := MatchFD(tpls[:1], []string{"relative", "1"}, r); err == nil {
		t.Fatal("a relative path matched")
	}
}

// TestMatchIndexRefusesDescriptors: a caller that cannot pass descriptors
// (MatchIndex returns only strings) never gets a {path:read:fd} template:
// its descriptors are closed and the match refused.
func TestMatchIndexRefusesDescriptors(t *testing.T) {
	r := newFDResolver(t, "a")
	_, _, err := MatchIndex([]Template{mustParse(t, "cat", "{path:read:fd}")}, []string{"cat", "/srv/app/a"}, r)
	var pe *PathError
	if !errors.As(err, &pe) || len(r.opened) != 1 || !closed(r.opened[0]) {
		t.Fatalf("MatchIndex: %v, opened %d", err, len(r.opened))
	}
}
