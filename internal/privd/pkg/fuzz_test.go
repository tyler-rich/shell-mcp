//go:build linux

package pkg_test

import (
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
)

// FuzzParseSimulation: apt-get -s output is host data; the parser never
// panics, stays bounded, and every entry it returns names a valid package
// with a version of Debian's characters.
func FuzzParseSimulation(f *testing.F) {
	for _, s := range []string{
		"Inst example-lib (2.1-1 Invented:1.0/stable [all])\n",
		"Inst example-hello [1.0] (1.1 Invented:1.0/stable [all]) []\nRemv example-old [0.9-1]\nPurg x-y [1]\n",
		"Inst a:i386 [1:2~3] (4 R [i386]) [a on b]\nConf a (4 R)\n",
		"Inst \nRemv\nPurg [x]\nInst x [y\n", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s := pkg.ParseSimulation(b)
		if len(s.Install) > pkg.MaxChanges || len(s.Upgrade) > pkg.MaxChanges || len(s.Remove) > pkg.MaxChanges {
			t.Fatalf("unbounded: %d %d %d", len(s.Install), len(s.Upgrade), len(s.Remove))
		}
		check := func(name string, versions ...string) {
			base, arch, _ := strings.Cut(name, ":")
			if !pkg.ValidName(base) || strings.ContainsAny(arch, " :") {
				t.Fatalf("invalid name %q from %q", name, b)
			}
			for _, v := range versions {
				if v == "" || strings.ContainsAny(v, " \t\n[]()") {
					t.Fatalf("invalid version %q from %q", v, b)
				}
			}
		}
		for _, e := range s.Install {
			check(e.Name, e.Version)
		}
		for _, e := range s.Upgrade {
			check(e.Name, e.From, e.To)
		}
		for _, e := range s.Remove {
			check(e.Name, e.Version)
		}
	})
}
