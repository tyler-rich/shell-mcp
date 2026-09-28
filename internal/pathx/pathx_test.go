package pathx

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckClean(t *testing.T) {
	ok := []string{"/", "/a", "/srv/app", "/a b/c", "/a/.hidden", "/a/..b", "/a/b..", "/" + strings.Repeat("a", MaxPathBytes-1)}
	for _, p := range ok {
		if err := CheckClean(p); err != nil {
			t.Errorf("CheckClean(%q) = %v, want nil", p, err)
		}
	}
	bad := map[string]error{
		"":                                      ErrEmpty,
		"a/b":                                   ErrNotAbsolute,
		"./a":                                   ErrNotAbsolute,
		"/a/":                                   ErrNotClean,
		"//a":                                   ErrNotClean,
		"/a//b":                                 ErrNotClean,
		"/a/./b":                                ErrNotClean,
		"/a/../b":                               ErrNotClean,
		"/..":                                   ErrNotClean,
		"/a/..":                                 ErrNotClean,
		"/.":                                    ErrNotClean,
		"/a\x00b":                               ErrNUL,
		"/" + strings.Repeat("a", MaxPathBytes): ErrTooLong,
	}
	for p, want := range bad {
		if err := CheckClean(p); !errors.Is(err, want) {
			t.Errorf("CheckClean(%q) = %v, want %v", p, err, want)
		}
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		root, p string
		want    bool
	}{
		{"/srv/app", "/srv/app", true},
		{"/srv/app", "/srv/app/x", true},
		{"/srv/app", "/srv/app/x/y", true},
		{"/srv/app", "/srv/apple", false},
		{"/srv/app", "/srv", false},
		{"/srv/app", "/", false},
		{"/", "/anything", true},
		{"/", "/", true},
	}
	for _, c := range cases {
		if got := Within(c.root, c.p); got != c.want {
			t.Errorf("Within(%q, %q) = %v, want %v", c.root, c.p, got, c.want)
		}
	}
}

func TestRel(t *testing.T) {
	cases := map[[2]string]string{
		{"/srv/app", "/srv/app"}:     ".",
		{"/srv/app", "/srv/app/x"}:   "x",
		{"/srv/app", "/srv/app/x/y"}: "x/y",
		{"/", "/x"}:                  "x",
		{"/", "/"}:                   ".",
	}
	for in, want := range cases {
		if got := Rel(in[0], in[1]); got != want {
			t.Errorf("Rel(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestLongest(t *testing.T) {
	roots := []string{"/srv/app", "/srv/app/config", "/srv/apple", "/etc/example-app"}
	cases := map[string]string{
		"/srv/app/config/x.yaml": "/srv/app/config",
		"/srv/app/config":        "/srv/app/config",
		"/srv/app/configs":       "/srv/app",
		"/srv/app/x":             "/srv/app",
		"/srv/apple/x":           "/srv/apple",
		"/etc/example-app":       "/etc/example-app",
	}
	for p, want := range cases {
		got, ok := Longest(roots, p)
		if !ok || got != want {
			t.Errorf("Longest(%q) = %q, %v; want %q", p, got, ok, want)
		}
	}
	for _, p := range []string{"/srv", "/etc", "/srv/ap", "/"} {
		if got, ok := Longest(roots, p); ok {
			t.Errorf("Longest(%q) = %q, want no root", p, got)
		}
	}
}
