package pathx

import (
	"path"
	"strings"
	"testing"
)

// FuzzGlob: compiling and matching never panic; a match on a path is also a
// match through Covers; a pattern that matches dir/x may contain beneath
// dir; a literal glob matches exactly its own path.
func FuzzGlob(f *testing.F) {
	for _, s := range [][2]string{
		{"/etc/shadow*", "/etc/shadow-"}, {"**/.ssh/**", "/srv/.ssh/k"}, {"/a/**/b", "/a/x/y/b"},
		{"/a*b*c", "/axxbyyc"}, {"**/*.key", "/srv/app/tls.key"}, {"/", "/"}, {"/home/*/.ssh/**", "/home/u/.ssh"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pat, p string) {
		g, err := CompileGlob(pat)
		if err != nil || CheckClean(p) != nil {
			return
		}
		m := &Matcher{}
		m.Add(g)
		if g.Match(p) && !m.Covers(p) {
			t.Fatalf("%q matches %q but Covers does not", pat, p)
		}
		if p != "/" && g.Match(p) && !g.MayContain(path.Dir(p)) {
			t.Fatalf("%q matches %q but MayContain(%q) is false", pat, p, path.Dir(p))
		}
		if !g.Anchored() && p != "/" && g.Match(p) && !m.MayContain("/", false) {
			t.Fatalf("unanchored %q matches %q but MayContain(/) is false", pat, p)
		}
		lit, err := LiteralGlob(p)
		if err != nil {
			t.Fatalf("LiteralGlob(%q): %v", p, err)
		}
		if !lit.Match(p) {
			t.Fatalf("literal glob %q does not match itself", p)
		}
		if q := p + "/x"; len(q) <= MaxPathBytes && lit.Match(q) {
			t.Fatalf("literal glob %q matches %q", p, q)
		}
	})
}

// FuzzPathRules: CheckClean accepts exactly absolute, clean, NUL-free paths
// within the length limit; root selection only ever returns a root the path
// is within on a component boundary, and Rel rebuilds the path.
func FuzzPathRules(f *testing.F) {
	f.Add("/srv/app", "/srv/app/config/x")
	f.Add("/srv/app", "/srv/apple")
	f.Add("/srv/app/", "/srv/app/../x")
	f.Add("/", "/a")
	f.Fuzz(func(t *testing.T, root, p string) {
		err := CheckClean(p)
		clean := p != "" && len(p) <= MaxPathBytes && strings.IndexByte(p, 0) < 0 && p[0] == '/' && path.Clean(p) == p
		if (err == nil) != clean {
			t.Fatalf("CheckClean(%q) = %v, want clean=%v", p, err, clean)
		}
		if err != nil || CheckClean(root) != nil {
			return
		}
		r, ok := Longest([]string{root, "/nonexistent-other-root"}, p)
		if !ok {
			if Within(root, p) {
				t.Fatalf("Longest missed root %q for %q", root, p)
			}
			return
		}
		if !Within(r, p) {
			t.Fatalf("Longest chose %q for %q", r, p)
		}
		if p != r && r != "/" && p[len(r)] != '/' {
			t.Fatalf("root %q is not on a component boundary of %q", r, p)
		}
		rel := Rel(r, p)
		rebuilt := path.Join(r, rel)
		if rebuilt != p {
			t.Fatalf("Rel(%q, %q) = %q; rebuilt %q", r, p, rel, rebuilt)
		}
	})
}
