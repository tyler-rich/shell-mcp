//go:build linux

package pkg_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
)

// The recovery of an unfinished database (handoff N-14, S7-4): dpkg's
// state with its journal folded in, what each unfinished package needs,
// the recovery's argv and hash, and what a recovery settled. Packages are
// invented; the journal's layout (updates/NNNN, one status stanza each,
// applied in order; tmp.i padding) is dpkg 1.22.22's, measured after a
// SIGTERM to dpkg --configure --pending in a throwaway container.

const dpkgEntry = "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.22.22\n\n"

func stanza(name, status, version, extra string) string {
	s := fmt.Sprintf("Package: %s\nStatus: %s\nArchitecture: all\n", name, status)
	if version != "" {
		s += "Version: " + version + "\n"
	}
	if extra != "" {
		s += extra + "\n"
	}
	return s + "\n"
}

func dpkgDir(t *testing.T, status string, journal map[string]string) string {
	t.Helper()
	d := filepath.Join(gatetest.SecureDir(t), "dpkg")
	gatetest.Mkdir(t, filepath.Join(d, "updates"), 0o755)
	gatetest.WriteFile(t, filepath.Join(d, "status"), status, 0o644)
	for n, c := range journal {
		gatetest.WriteFile(t, filepath.Join(d, "updates", n), c, 0o644)
	}
	return d
}

func stateOf(st pkg.Status, name string) string {
	p, ok := st.Packages[name]
	if !ok {
		return "absent"
	}
	return p.Flag + " " + p.State + " " + p.Version
}

// TestReadStateFoldsJournal: dpkg's journal entries are applied over the
// status file in name order, a later one replacing an earlier one; a new
// package in the journal is added; tmp.i (dpkg's padding file) is not a
// record, but every entry is reported in Journal.
func TestReadStateFoldsJournal(t *testing.T) {
	t.Parallel()
	d := dpkgDir(t, dpkgEntry+stanza("example-a", "install ok unpacked", "1.0", "")+stanza("example-b", "install ok unpacked", "1.0", ""), map[string]string{
		"0000":  stanza("example-b", "install ok unpacked", "1.0", "Depends: dpkg\nDescription: invented"),
		"0001":  stanza("example-b", "install ok half-configured", "1.0", "Depends: dpkg\nDescription: invented"),
		"0002":  stanza("example-new", "install ok half-installed", "2.0", ""),
		"tmp.i": strings.Repeat("#padding\n", 512),
	})
	st, err := pkg.ReadState(d)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"example-a": "ok unpacked 1.0", "example-b": "ok half-configured 1.0", "example-new": "ok half-installed 2.0"} {
		if got := stateOf(st.Status, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if !slices.Equal(st.Journal, []string{"0000", "0001", "0002", "tmp.i"}) {
		t.Errorf("journal %v", st.Journal)
	}
	clean, err := pkg.ReadState(dpkgDir(t, dpkgEntry+stanza("example-a", "install ok installed", "1.0", ""), nil))
	if err != nil || len(clean.Journal) != 0 || stateOf(clean.Status, "example-a") != "ok installed 1.0" {
		t.Fatalf("clean %+v %v", clean, err)
	}
}

// TestReadStateRefusesBadJournal: a journal record that does not parse, or
// one larger than the status bound, is an error, never ignored.
func TestReadStateRefusesBadJournal(t *testing.T) {
	t.Parallel()
	for name, rec := range map[string]string{
		"no status":  "Package: example-b\nArchitecture: all\nVersion: 1.0\n",
		"bad name":   stanza("Example_B", "install ok unpacked", "1.0", ""),
		"bad status": stanza("example-b", "install ok sideways", "1.0", ""),
		"two":        stanza("example-b", "install ok unpacked", "1.0", "") + stanza("example-c", "install ok unpacked", "1.0", ""),
	} {
		d := dpkgDir(t, dpkgEntry+stanza("example-b", "install ok unpacked", "1.0", ""), map[string]string{"0000": rec})
		if _, err := pkg.ReadState(d); err == nil {
			t.Errorf("%s: a bad journal record was accepted", name)
		}
	}
}

// TestUnfinishedPackagesRecovery: what each unfinished state needs.
// Unpacked, half-configured and trigger-waiting packages are configured;
// half-installed ones and any with reinstreq must be reinstalled
// (dpkg --configure --pending exits 0 and leaves them, measured); one whose
// dependency no package on the system provides stays unconfigured
// ("dependency problems - leaving unconfigured", measured).
func TestUnfinishedPackagesRecovery(t *testing.T) {
	t.Parallel()
	st := mustParse(t, dpkgEntry+
		stanza("example-unpacked", "install ok unpacked", "1.0", "Depends: dpkg (>= 1.0), example-lib | example-alt")+
		stanza("example-half", "install ok half-configured", "1.0", "")+
		stanza("example-trig", "install ok triggers-pending", "1.0", "")+
		stanza("example-await", "install ok triggers-awaited", "1.0", "")+
		stanza("example-mess", "install reinstreq half-installed", "1.0", "")+
		stanza("example-halfinst", "install ok half-installed", "1.0", "")+
		stanza("example-reinst", "install reinstreq unpacked", "1.0", "")+
		stanza("example-dep", "install ok unpacked", "1.0", "Pre-Depends: example-pre\nDepends: example-missing (>= 2), example-gone | example-absent, example-virtual, example-lib:any")+
		stanza("example-lib", "install ok installed", "2.1", "Provides: example-virtual (= 1)")+
		stanza("example-gone", "purge ok not-installed", "", "")+
		stanza("example-pre", "deinstall ok config-files", "0.9", "")+
		stanza("example-fine", "install ok installed", "1.0", ""))
	got := map[string]string{}
	for _, u := range st.UnfinishedPackages() {
		got[u.Name] = string(u.Recovery) + " " + u.State + " " + u.Flag + " " + strings.Join(u.Missing, ";")
	}
	want := map[string]string{
		"example-unpacked": "configure unpacked ok ",
		"example-half":     "configure half-configured ok ",
		"example-trig":     "configure triggers-pending ok ",
		"example-await":    "configure triggers-awaited ok ",
		"example-mess":     "reinstall half-installed reinstreq ",
		"example-halfinst": "reinstall half-installed ok ",
		"example-reinst":   "reinstall unpacked reinstreq ",
		"example-dep":      "dependency unpacked ok example-pre;example-missing;example-gone | example-absent",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("recoveries\n got %v\nwant %v", got, want)
	}
	names := []string{}
	for _, u := range st.UnfinishedPackages() {
		names = append(names, u.Name)
	}
	if !slices.IsSorted(names) {
		t.Fatalf("not sorted: %v", names)
	}
	if u := mustParse(t, statusFile).UnfinishedPackages(); len(u) != 0 {
		t.Fatalf("a final status has unfinished packages: %+v", u)
	}
}

// TestRecoverArgs: the recovery's argv is fixed: existing configuration
// files kept, every pending package configured, nothing from the client.
func TestRecoverArgs(t *testing.T) {
	t.Parallel()
	if got := pkg.RecoverArgs(); !slices.Equal(got, []string{"--force-confold", "--configure", "--pending"}) {
		t.Fatalf("argv %q", got)
	}
}

// TestRecoverPreviewHash: the hash covers the policy, the argv, every
// unfinished package's name, version, want, flag and state, and the
// journal's entries; never the derived recovery or missing dependencies,
// nor the order the packages are given in.
func TestRecoverPreviewHash(t *testing.T) {
	t.Parallel()
	pol := strings.Repeat("a", 64)
	argv := []string{"--force-confold", "--configure", "--pending"}
	base := []pkg.UnfinishedPackage{
		{Name: "example-a", Version: "1.0", Want: "install", Flag: "ok", State: "unpacked", Recovery: pkg.RecoverConfigure},
		{Name: "example-b", Version: "2.0", Want: "install", Flag: "ok", State: "half-configured", Recovery: pkg.RecoverConfigure},
	}
	h := pkg.RecoverPreviewHash(pol, argv, base, []string{"0000"})
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("hash %q", h)
	}
	with := func(f func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage) []pkg.UnfinishedPackage {
		return f(slices.Clone(base))
	}
	differ := map[string]string{
		"policy":  pkg.RecoverPreviewHash(strings.Repeat("b", 64), argv, base, []string{"0000"}),
		"argv":    pkg.RecoverPreviewHash(pol, []string{"--configure", "--pending"}, base, []string{"0000"}),
		"journal": pkg.RecoverPreviewHash(pol, argv, base, []string{"0000", "0001"}),
		"none":    pkg.RecoverPreviewHash(pol, argv, base, nil),
		"fewer":   pkg.RecoverPreviewHash(pol, argv, base[:1], []string{"0000"}),
		"version": pkg.RecoverPreviewHash(pol, argv, with(func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage { u[0].Version = "1.1"; return u }), []string{"0000"}),
		"state":   pkg.RecoverPreviewHash(pol, argv, with(func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage { u[0].State = "half-configured"; return u }), []string{"0000"}),
		"flag":    pkg.RecoverPreviewHash(pol, argv, with(func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage { u[0].Flag = "reinstreq"; return u }), []string{"0000"}),
		"want":    pkg.RecoverPreviewHash(pol, argv, with(func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage { u[0].Want = "hold"; return u }), []string{"0000"}),
		"name":    pkg.RecoverPreviewHash(pol, argv, with(func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage { u[0].Name = "example-c"; return u }), []string{"0000"}),
	}
	for what, d := range differ {
		if d == h {
			t.Errorf("the hash does not cover the %s", what)
		}
	}
	same := map[string]string{
		"order": pkg.RecoverPreviewHash(pol, argv, []pkg.UnfinishedPackage{base[1], base[0]}, []string{"0000"}),
		"recovery": pkg.RecoverPreviewHash(pol, argv, with(func(u []pkg.UnfinishedPackage) []pkg.UnfinishedPackage {
			u[0].Recovery, u[0].Missing = pkg.RecoverDependency, []string{"example-x"}
			return u
		}), []string{"0000"}),
	}
	for what, s := range same {
		if s != h {
			t.Errorf("the hash depends on the %s", what)
		}
	}
	if pkg.RecoverPreviewHash(pol, argv, nil, nil) == pkg.RecoverPreviewHash(pol, argv, nil, []string{"tmp.i"}) {
		t.Error("an empty database and one with a journal entry hash the same")
	}
}

// TestSettle: what a recovery settled: packages it configured (unfinished
// before, installed at the same version after), packages still unfinished
// with what they need, and any other change (which a recovery should never
// make).
func TestSettle(t *testing.T) {
	t.Parallel()
	before := mustParse(t, dpkgEntry+
		stanza("example-a", "install ok unpacked", "1.0", "")+
		stanza("example-b", "install ok half-configured", "1.0", "")+
		stanza("example-c", "install ok triggers-pending", "1.0", "")+
		stanza("example-d", "install reinstreq half-installed", "1.0", "")+
		stanza("example-e", "install ok installed", "1.0", ""))
	after := mustParse(t, dpkgEntry+
		stanza("example-a", "install ok installed", "1.0", "")+
		stanza("example-b", "install ok half-configured", "1.0", "")+
		stanza("example-c", "install ok installed", "1.0", "")+
		stanza("example-d", "install reinstreq half-installed", "1.0", "")+
		stanza("example-e", "install ok installed", "1.1", ""))
	r := pkg.Settle(before, after)
	if !slices.Equal(r.Configured, []pkg.Configured{{Name: "example-a", Version: "1.0", From: "unpacked"}, {Name: "example-c", Version: "1.0", From: "triggers-pending"}}) {
		t.Errorf("configured %+v", r.Configured)
	}
	still := []string{}
	for _, u := range r.Still {
		still = append(still, u.Name+" "+u.State+" "+string(u.Recovery))
	}
	if !slices.Equal(still, []string{"example-b half-configured configure", "example-d half-installed reinstall"}) {
		t.Errorf("still %v", still)
	}
	if !r.Other.Equal(pkg.Transaction{Upgrade: []pkg.Upgrade{{Name: "example-e", From: "1.0", To: "1.1"}}}) {
		t.Errorf("other %+v", r.Other)
	}
	clean := pkg.Settle(after, after)
	if len(clean.Configured) != 0 || !clean.Other.Empty() || len(clean.Still) != 2 {
		t.Errorf("self-settle %+v", clean)
	}
}

// TestLockHeldDpkg: dpkg's own refusals of a held lock (dpkg 1.22.22,
// lib/dpkg/dbmodify.c and lock.c; the first measured), and its holder.
func TestLockHeldDpkg(t *testing.T) {
	t.Parallel()
	msg := "dpkg: error: dpkg frontend lock was locked by /usr/bin/dpkg process with pid 51\nNote: removing the lock file is always wrong\n"
	for _, s := range []string{msg, "dpkg: error: dpkg status database is locked by another process\n"} {
		if !pkg.LockHeld([]byte(s)) {
			t.Errorf("%q not recognised as a held lock", s)
		}
	}
	if h, ok := pkg.HolderFromStderr([]byte(msg)); !ok || h.PID != 51 || h.Comm != "dpkg" {
		t.Errorf("holder %+v %v", h, ok)
	}
	if pkg.LockHeld([]byte("dpkg: error processing package example-a (--configure):\n dependency problems - leaving unconfigured\n")) {
		t.Error("a configure error taken for a held lock")
	}
}
