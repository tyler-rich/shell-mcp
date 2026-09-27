package pathx

import (
	"strings"
	"testing"
)

func TestCompileGlobRejects(t *testing.T) {
	bad := []string{
		"", "relative", "*.key", "/a//b", "/a/", "/a/./b", "/a/../b", "/a**b", "/**x", "/x**",
		"/a?", "/a[bc]", "/a{b,c}", `/a\b`, "/a\x00", "**", "/" + strings.Repeat("a/", 200) + "b",
	}
	for _, s := range bad {
		if _, err := CompileGlob(s); err == nil {
			t.Errorf("CompileGlob(%q) accepted", s)
		}
	}
	for _, s := range []string{"/", "/a", "/a/*", "/a/**", "**/.ssh", "**/.ssh/**", "/etc/cron*", "/home/*/.ssh/**", "/**/x", "/a/**/**/b"} {
		if _, err := CompileGlob(s); err != nil {
			t.Errorf("CompileGlob(%q) = %v", s, err)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/etc/shadow*", "/etc/shadow", true},
		{"/etc/shadow*", "/etc/shadow-", true},
		{"/etc/shadow*", "/etc/shadow/x", false},
		{"/etc/shadow*", "/etc/gshadow", false},
		{"/etc/sudoers.d/**", "/etc/sudoers.d", true},
		{"/etc/sudoers.d/**", "/etc/sudoers.d/a", true},
		{"/etc/sudoers.d/**", "/etc/sudoers.d/a/b", true},
		{"/etc/sudoers.d/**", "/etc/sudoers.dx", false},
		{"/etc/ssh/*_key", "/etc/ssh/ssh_host_ed25519_key", true},
		{"/etc/ssh/*_key", "/etc/ssh/ssh_host_ed25519_key.pub", false},
		{"/home/*/.ssh/**", "/home/u/.ssh/id_ed25519", true},
		{"/home/*/.ssh/**", "/home/u/x/.ssh/id", false},
		{"**/.ssh/**", "/srv/app/.ssh/k", true},
		{"**/.ssh/**", "/.ssh", true},
		{"**/.ssh/**", "/srv/.ssh", true},
		{"**/.ssh/**", "/srv/.sshx/k", false},
		{"**/*.key", "/srv/app/tls.key", true},
		{"**/*.key", "/srv/app/.key", true},
		{"**/*.key", "/srv/app/tls.key/x", false},
		{"**/.docker/config.json", "/home/u/.docker/config.json", true},
		{"**/.docker/config.json", "/home/u/.docker/config.jsonx", false},
		{"/a/**/b", "/a/b", true},
		{"/a/**/b", "/a/x/y/b", true},
		{"/a/**/b", "/a/x/y/c", false},
		{"/a/*/b", "/a/b", false},
		{"/a/*", "/a", false},
		{"/a*b*c", "/abc", true},
		{"/a*b*c", "/axxbyyc", true},
		{"/a*b*c", "/axxbyy", false},
		{"/", "/", true},
		{"/", "/a", false},
	}
	for _, c := range cases {
		g, err := CompileGlob(c.pat)
		if err != nil {
			t.Fatalf("CompileGlob(%q): %v", c.pat, err)
		}
		if got := g.Match(c.p); got != c.want {
			t.Errorf("%q.Match(%q) = %v, want %v", c.pat, c.p, got, c.want)
		}
	}
}

func TestGlobMayContain(t *testing.T) {
	cases := []struct {
		pat, dir string
		want     bool
	}{
		{"/etc/cron*", "/etc", true},
		{"/etc/cron*", "/", true},
		{"/etc/cron*", "/etc/cron.d", false}, // equal/inside is Match, not MayContain
		{"/etc/cron*", "/srv", false},
		{"/etc/ssh", "/etc", true},
		{"/etc/ssh", "/etc/ssh", false},
		{"/etc/ssh", "/etc/sshd", false},
		{"/usr", "/", true},
		{"/usr", "/usr/local", false},
		{"**/.ssh", "/srv/app", true},
		{"/srv/app/secrets/**", "/srv/app", true},
		{"/srv/app/secrets/**", "/srv/app/secrets", true},
		{"/srv/app/secrets/**", "/srv/other", false},
	}
	for _, c := range cases {
		g, err := CompileGlob(c.pat)
		if err != nil {
			t.Fatalf("CompileGlob(%q): %v", c.pat, err)
		}
		if got := g.MayContain(c.dir); got != c.want {
			t.Errorf("%q.MayContain(%q) = %v, want %v", c.pat, c.dir, got, c.want)
		}
	}
}

func TestMatcherCoversAncestors(t *testing.T) {
	m, err := NewMatcher([]string{"/srv/app/secrets", "**/.gnupg/**"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/srv/app/secrets", "/srv/app/secrets/a", "/srv/app/secrets/a/b", "/home/u/.gnupg"} {
		if !m.Covers(p) {
			t.Errorf("Covers(%q) = false", p)
		}
	}
	for _, p := range []string{"/srv/app", "/srv/app/secretsx", "/srv/app/x"} {
		if m.Covers(p) {
			t.Errorf("Covers(%q) = true", p)
		}
	}
	if !m.MayContain("/srv/app", true) || m.MayContain("/srv/other", true) {
		t.Error("anchored MayContain wrong")
	}
	if !m.MayContain("/srv/other", false) {
		t.Error("unanchored MayContain must consider ** patterns")
	}
	if got := m.Patterns(); len(got) != 2 || got[0] != "/srv/app/secrets" {
		t.Errorf("Patterns() = %v", got)
	}
}

func TestGlobAnchored(t *testing.T) {
	for pat, want := range map[string]bool{"/a/b": true, "/a/**": true, "**/x": false, "/**/x": false} {
		g, err := CompileGlob(pat)
		if err != nil {
			t.Fatal(err)
		}
		if g.Anchored() != want {
			t.Errorf("%q.Anchored() = %v", pat, !want)
		}
	}
}
