//go:build linux

package pkg_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// FuzzParseStatus: dpkg's status file is host data; the parser never
// panics, stays bounded, and every entry it keeps has a valid name,
// architecture and version; a status diffed against itself is empty.
func FuzzParseStatus(f *testing.F) {
	f.Add([]byte(statusFile))
	f.Add([]byte("Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\nPackage: a\n"))
	f.Add([]byte("Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n \nPackage: x\n\n\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := pkg.ParseStatus(b)
		if err != nil {
			return
		}
		if len(st.Packages) > pkg.MaxStatusPackages+1 || st.Native == "" {
			t.Fatalf("unbounded or no native architecture: %d %q", len(st.Packages), st.Native)
		}
		for k, p := range st.Packages {
			base, arch, qualified := strings.Cut(k, ":")
			if !pkg.ValidName(base) || base != p.Name || qualified && arch != p.Arch || strings.ContainsAny(p.Version, " \t\n") {
				t.Fatalf("entry %q: %+v", k, p)
			}
		}
		if d := pkg.Diff(st, st); !d.Empty() {
			t.Fatalf("self-diff %+v", d)
		}
		_ = st.Unfinished()
	})
}

// FuzzPackageNames: whatever the client sends as names, apt-get's argv
// either is refused or carries only valid Debian package names, each
// after "--", none that apt could read as an option, a version, a path or
// the other operation.
func FuzzPackageNames(f *testing.F) {
	for _, s := range []string{"example-hello", "example-hello,example-lib", "-oAPT::Get::Purge=true", "example-hello=1.0", "./x.deb",
		"/tmp/x.deb", "example-hello-", "example-hello+", "--", "a", "example_hello", "example-hello/stable", "example-hello:i386"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, list string) {
		names := strings.Split(list, ",")
		for _, op := range []pkg.Op{pkg.OpInstall, pkg.OpRemove} {
			args, err := pkg.Args(op, false, names)
			if err != nil {
				continue
			}
			i := slices.Index(args, "--")
			if i < 0 || !slices.Equal(args[i+1:], names) {
				t.Fatalf("%s %q: argv %q", op, names, args)
			}
			for _, n := range names {
				if !pkg.ValidName(n) || strings.ContainsAny(n, "=/:_ ") || strings.HasPrefix(n, "-") ||
					op == pkg.OpInstall && strings.HasSuffix(n, "-") || op == pkg.OpRemove && strings.HasSuffix(n, "+") {
					t.Fatalf("%s accepted %q", op, n)
				}
			}
		}
	})
}

// FuzzPinnedArgs: versions in the pinned argv come from host data (apt's
// simulation); whatever they are, the argv is refused or every argument
// after "--" is name=version of a valid name and a version of Debian's
// characters that apt cannot read as anything else.
func FuzzPinnedArgs(f *testing.F) {
	f.Add("example-hello", "1.1")
	f.Add("example-arch:i386", "1:2.0~rc1+dfsg-1")
	f.Add("example-hello", "1.0-")
	f.Add("example-hello", "-o")
	f.Fuzz(func(t *testing.T, name, version string) {
		tx := pkg.Transaction{Upgrade: []pkg.Upgrade{{Name: name, From: "0", To: version}}}
		args, err := pkg.PinnedArgs(pkg.OpUpgrade, false, nil, tx)
		if err != nil {
			return
		}
		i := slices.Index(args, "--")
		if i < 0 || len(args) != i+2 {
			t.Fatalf("argv %q", args)
		}
		n, v, ok := strings.Cut(args[i+1], "=")
		base, _, _ := strings.Cut(n, ":")
		if !ok || !pkg.ValidName(base) || v == "" || strings.HasSuffix(v, "-") || strings.HasPrefix(v, "-") ||
			strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+~:-") != "" {
			t.Fatalf("pinned %q from %q %q", args[i+1], name, version)
		}
	})
}

// FuzzUnfinishedPackages (S7-4): whatever dpkg's status holds, the
// unfinished packages are exactly Unfinished's, sorted, each with a known
// recovery and, for a dependency, only package names as missing; a state
// settles with itself to nothing configured and nothing changed; the
// recovery hash does not depend on the packages' order.
func FuzzUnfinishedPackages(f *testing.F) {
	f.Add([]byte(statusFile))
	f.Add([]byte("Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\nPackage: a1\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1\nDepends: b1 (>= 2) | c1:any, d1 [amd64], e1 <!nocheck>\nPre-Depends: ,|, x\n\nPackage: f1\nStatus: install ok installed\nArchitecture: all\nVersion: 1\nProvides: e1 (= 1), g1\n"))
	f.Add([]byte("Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\nPackage: a1\nStatus: hold reinstreq half-installed\nArchitecture: all\nVersion: 1\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := pkg.ParseStatus(b)
		if err != nil {
			return
		}
		u := st.UnfinishedPackages()
		got := []string{}
		for _, p := range u {
			got = append(got, p.Name)
			switch p.Recovery {
			case pkg.RecoverConfigure, pkg.RecoverReinstall:
				if len(p.Missing) != 0 {
					t.Fatalf("%s: %s with missing %q", p.Name, p.Recovery, p.Missing)
				}
			case pkg.RecoverDependency:
				if len(p.Missing) == 0 {
					t.Fatalf("%s: a dependency recovery without a missing dependency", p.Name)
				}
				for _, g := range p.Missing {
					for _, n := range strings.Split(g, " | ") {
						if !pkg.ValidName(n) {
							t.Fatalf("%s: missing %q is not a package name", p.Name, n)
						}
					}
				}
			default:
				t.Fatalf("%s: recovery %q", p.Name, p.Recovery)
			}
		}
		if len(got)+len(st.Unfinished()) > 0 && !slices.Equal(got, st.Unfinished()) {
			t.Fatalf("unfinished %v, Unfinished %v", got, st.Unfinished())
		}
		if r := pkg.Settle(st, st); len(r.Configured) != 0 || !r.Other.Empty() || len(r.Still) != len(u) {
			t.Fatalf("self-settle %+v", r)
		}
		rev := slices.Clone(u)
		slices.Reverse(rev)
		pol := strings.Repeat("a", 64)
		if pkg.RecoverPreviewHash(pol, pkg.RecoverArgs(), u, nil) != pkg.RecoverPreviewHash(pol, pkg.RecoverArgs(), rev, nil) {
			t.Fatal("the hash depends on the order")
		}
	})
}

// FuzzReadStateJournal (S7-4): whatever one journal record holds, folding
// it either fails or yields a state whose every entry is keyed by a valid
// name, with the record reported in Journal.
func FuzzReadStateJournal(f *testing.F) {
	base := "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.22.22\n\nPackage: example-b\nStatus: install ok unpacked\nArchitecture: all\nVersion: 1.0\n"
	f.Add([]byte("Package: example-b\nStatus: install ok half-configured\nArchitecture: all\nVersion: 1.0\nDepends: dpkg\nDescription: invented\n"))
	f.Add([]byte("Package: example-c\nStatus: install ok unpacked\nArchitecture: i386\nVersion: 2:1.0~rc1\n"))
	f.Add([]byte("Package: example-b\n\nPackage: example-c\n"))
	f.Add([]byte("#padding\n"))
	f.Fuzz(func(t *testing.T, rec []byte) {
		d := filepath.Join(t.TempDir(), "dpkg")
		if err := os.MkdirAll(filepath.Join(d, "updates"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "status"), []byte(base), 0o644); err != nil { //nolint:gosec // G306: dpkg's status is world-readable
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "updates", "0000"), rec, 0o644); err != nil { //nolint:gosec // G306: as dpkg writes it
			t.Fatal(err)
		}
		st, err := pkg.ReadState(d)
		if err != nil {
			if !errors.Is(err, pkg.ErrJournal) {
				t.Fatalf("a journal record's error is not ErrJournal: %v", err)
			}
			return
		}
		if !slices.Equal(st.Journal, []string{"0000"}) || len(st.Packages) < 2 || len(st.Packages) > 3 {
			t.Fatalf("state %+v", st)
		}
		for k, p := range st.Packages {
			base, _, _ := strings.Cut(k, ":")
			if !pkg.ValidName(base) || base != p.Name {
				t.Fatalf("entry %q: %+v", k, p)
			}
		}
	})
}

// FuzzReinstallArgs: the reinstall's pins are host data (a name and the
// version dpkg's status names); the argv is either refused or the fixed
// options, then "--", then only name=version pins of a valid name and a
// Debian version, never an option.
func FuzzReinstallArgs(f *testing.F) {
	for _, s := range [][2]string{{"example-a", "1.0"}, {"example-a", "2:1.4+dfsg-3"}, {"example-a", "-o"}, {"-s", "1.0"}, {"example-a-", "1"}, {"example-a", "1.0-"}, {"x", ""}} {
		f.Add(s[0], s[1], "example-b", "1.0")
	}
	f.Fuzz(func(t *testing.T, n1, v1, n2, v2 string) {
		args, err := pkg.ReinstallArgs(true, []pkg.Version{{Name: n1, Version: v1}, {Name: n2, Version: v2}})
		if err != nil {
			return
		}
		i := slices.Index(args, "--")
		if i < 0 || !slices.Equal(args[i-3:i], []string{"-s", "install", "--reinstall"}) || len(args) != i+3 {
			t.Fatalf("argv %q", args)
		}
		for _, a := range args[i+1:] {
			name, version, ok := strings.Cut(a, "=")
			if !ok || !pkg.ValidName(name) || strings.HasPrefix(a, "-") || strings.HasSuffix(name, "-") || version == "" || version[0] < '0' || version[0] > '9' ||
				strings.HasSuffix(version, "-") || strings.ContainsAny(version, " /=\t\n") {
				t.Fatalf("pin %q in %q", a, args)
			}
		}
	})
}
