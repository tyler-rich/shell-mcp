//go:build linux

package pkg_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
)

// What a recovery leaves (handoff N-36, S7-7): the reinstall's fixed,
// pinned argv and its hash, and the hash a removal of exactly the
// unfinished packages adds to its preview. Packages are invented.

var aptCommon = []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Use-Pty=0", "-o", "APT::Get::AutomaticRemove=false"}

// TestReinstallArgs: install --reinstall, never removing or adding a
// recommended package, every name pinned to a Debian version after "--";
// nothing else is accepted.
func TestReinstallArgs(t *testing.T) {
	t.Parallel()
	pins := []pkg.Version{{Name: "example-a", Version: "1.0"}, {Name: "example-b", Version: "2:1.4+dfsg-3"}}
	got, err := pkg.ReinstallArgs(false, pins)
	want := slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "install", "--reinstall", "--", "example-a=1.0", "example-b=2:1.4+dfsg-3"})
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("argv %q, %v\nwant %q", got, err, want)
	}
	got, err = pkg.ReinstallArgs(true, pins[:1])
	want = slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "-s", "install", "--reinstall", "--", "example-a=1.0"})
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("simulated argv %q, %v\nwant %q", got, err, want)
	}
	many := make([]pkg.Version, pkg.MaxNames+1)
	for i := range many {
		many[i] = pkg.Version{Name: "example-" + strings.Repeat("a", i+1), Version: "1.0"}
	}
	for name, bad := range map[string][]pkg.Version{
		"none":              nil,
		"too many":          many,
		"no version":        {{Name: "example-a"}},
		"not a version":     {{Name: "example-a", Version: "-o"}},
		"empty revision":    {{Name: "example-a", Version: "1.0-"}},
		"not a name":        {{Name: "-oAPT::X=1", Version: "1.0"}},
		"removal suffix":    {{Name: "example-a-", Version: "1.0"}},
		"twice":             {{Name: "example-a", Version: "1.0"}, {Name: "example-a", Version: "1.0"}},
		"version with path": {{Name: "example-a", Version: "1.0/../x"}},
	} {
		if args, err := pkg.ReinstallArgs(false, bad); err == nil {
			t.Errorf("%s: accepted as %q", name, args)
		}
	}
}

// TestCheckNames: the reinstall takes the install's names (no trailing
// "-", which apt-get reads as a removal).
func TestCheckNames(t *testing.T) {
	t.Parallel()
	if err := pkg.CheckNames(pkg.OpReinstall, []string{"example-a"}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]string{"none": nil, "suffix": {"example-a-"}, "option": {"-s"}, "twice": {"example-a", "example-a"}} {
		if pkg.CheckNames(pkg.OpReinstall, bad) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if pkg.CheckNames(pkg.OpRemove, []string{"example-a+"}) == nil {
		t.Error("a removal ending in + accepted")
	}
}

var unfinishedState = []pkg.UnfinishedPackage{
	{Name: "example-a", Version: "1.0", Want: "install", Flag: "reinstreq", State: "half-installed", Recovery: pkg.RecoverReinstall},
	{Name: "example-b", Version: "2.0", Want: "install", Flag: "ok", State: "unpacked", Recovery: pkg.RecoverDependency, Missing: []string{"example-x"}},
}

func withState(f func(u []pkg.UnfinishedPackage)) []pkg.UnfinishedPackage {
	u := slices.Clone(unfinishedState)
	f(u)
	return u
}

// stateDiffers are states that differ from unfinishedState in one value a
// hash must cover.
func stateDiffers() map[string][]pkg.UnfinishedPackage {
	return map[string][]pkg.UnfinishedPackage{
		"name":    withState(func(u []pkg.UnfinishedPackage) { u[0].Name = "example-c" }),
		"version": withState(func(u []pkg.UnfinishedPackage) { u[0].Version = "1.1" }),
		"want":    withState(func(u []pkg.UnfinishedPackage) { u[0].Want = "hold" }),
		"flag":    withState(func(u []pkg.UnfinishedPackage) { u[0].Flag = "ok" }),
		"state":   withState(func(u []pkg.UnfinishedPackage) { u[1].State = "half-configured" }),
		"fewer":   unfinishedState[:1],
		"none":    nil,
	}
}

// TestUnfinishedPreviewHash: a preview's hash bound to dpkg's unfinished
// state is never the hash of the clean preview, and covers the base hash,
// every unfinished package's name, version, want, flag and state, and the
// journal's entries, in any order; never what is derived from them.
func TestUnfinishedPreviewHash(t *testing.T) {
	t.Parallel()
	base := strings.Repeat("c", 64)
	h := pkg.UnfinishedPreviewHash(base, unfinishedState, nil)
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" || h == base {
		t.Fatalf("hash %q (base %q)", h, base)
	}
	if pkg.UnfinishedPreviewHash(base, nil, nil) == base {
		t.Fatal("an empty state leaves the base hash as it is: the unfinished mode would share the clean mode's hash")
	}
	differ := map[string]string{
		"base":    pkg.UnfinishedPreviewHash(strings.Repeat("d", 64), unfinishedState, nil),
		"journal": pkg.UnfinishedPreviewHash(base, unfinishedState, []string{"0000"}),
	}
	for what, u := range stateDiffers() {
		differ[what] = pkg.UnfinishedPreviewHash(base, u, nil)
	}
	for what, d := range differ {
		if d == h {
			t.Errorf("the hash does not cover the %s", what)
		}
	}
	same := map[string]string{
		"order":   pkg.UnfinishedPreviewHash(base, []pkg.UnfinishedPackage{unfinishedState[1], unfinishedState[0]}, nil),
		"derived": pkg.UnfinishedPreviewHash(base, withState(func(u []pkg.UnfinishedPackage) { u[1].Recovery, u[1].Missing = pkg.RecoverConfigure, nil }), nil),
	}
	for what, s := range same {
		if s != h {
			t.Errorf("the hash depends on the %s", what)
		}
	}
}

// TestReinstallPreviewHash: the reinstall's hash covers the policy, the
// names, the transaction with every version, the argv, the unfinished
// state and the journal; never what is derived from the state.
func TestReinstallPreviewHash(t *testing.T) {
	t.Parallel()
	pol := strings.Repeat("a", 64)
	names := []string{"example-a"}
	tx := pkg.Transaction{Upgrade: []pkg.Upgrade{{Name: "example-a", From: "1.0", To: "1.0"}}}
	argv := slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "-s", "install", "--reinstall", "--", "example-a=1.0"})
	u := unfinishedState
	h := pkg.ReinstallPreviewHash(pol, names, tx, argv, u, nil)
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("hash %q", h)
	}
	if h == pkg.PreviewHash(pol, pkg.OpInstall, names, tx, argv) {
		t.Fatal("the reinstall shares the install preview's domain")
	}
	differ := map[string]string{
		"policy":  pkg.ReinstallPreviewHash(strings.Repeat("b", 64), names, tx, argv, u, nil),
		"names":   pkg.ReinstallPreviewHash(pol, []string{"example-b"}, tx, argv, u, nil),
		"to":      pkg.ReinstallPreviewHash(pol, names, pkg.Transaction{Upgrade: []pkg.Upgrade{{Name: "example-a", From: "1.0", To: "1.1"}}}, argv, u, nil),
		"install": pkg.ReinstallPreviewHash(pol, names, pkg.Transaction{Upgrade: tx.Upgrade, Install: []pkg.Version{{Name: "example-x", Version: "1"}}}, argv, u, nil),
		"argv":    pkg.ReinstallPreviewHash(pol, names, tx, argv[:len(argv)-1], u, nil),
		"journal": pkg.ReinstallPreviewHash(pol, names, tx, argv, u, []string{"0000"}),
	}
	for what, s := range stateDiffers() {
		differ["state "+what] = pkg.ReinstallPreviewHash(pol, names, tx, argv, s, nil)
	}
	for what, d := range differ {
		if d == h {
			t.Errorf("the hash does not cover the %s", what)
		}
	}
	if pkg.ReinstallPreviewHash(pol, names, tx, argv, withState(func(u []pkg.UnfinishedPackage) { u[0].Missing = []string{"x"} }), nil) != h {
		t.Error("the hash depends on what is derived from the state")
	}
}
