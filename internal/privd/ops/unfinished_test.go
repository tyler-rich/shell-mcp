//go:build linux

package ops_test

import (
	"slices"
	"strings"
	"testing"
)

// What the recovery cannot finish (handoff N-36, S7-7; PRIVILEGED §6,
// "What the recovery leaves"): a removal of exactly the unfinished
// packages, bound to their state by its preview, which leaves packages
// that need a reinstall as they are; and the pinned reinstall of exactly
// the packages that need one. Both run through the apt-get stand-in's
// model (fakeapt), which refuses as apt 3.0.3 and 3.2.0 do (measured in
// S7-7): a real run while dpkg's journal has entries, any run while a
// package that needs a reinstall has no archive, and dpkg's refusal to
// remove such a package. Packages are invented.

// unfinishedLists puts the invented packages on the allow-lists.
func unfinishedLists() opt {
	return replace("  install: [example-hello]\n  remove: [example-hello]\n",
		"  install: [example-hello, example-bad, example-bad2]\n  remove: [example-hello, example-needs, example-dep, example-bad]\n")
}

// unfinishedRepo has an archive of every invented package at the version
// the tests leave unfinished.
func unfinishedRepo() []mpkg {
	return append(repoV1(), mpkg{Name: "example-bad", Version: "1.0"}, mpkg{Name: "example-bad2", Version: "2.0"},
		mpkg{Name: "example-needs", Version: "1.0", Depends: []string{"example-absent"}})
}

func unfinishedFixture(t *testing.T) *fixture {
	t.Helper()
	return modelFixture(t, &pkgModel{Repo: unfinishedRepo()}, nil, unfinishedLists())
}

var (
	needsUnpacked = pkgStanza("example-needs", "install ok unpacked", "1.0", "Depends: example-absent")
	badReinstreq  = pkgStanza("example-bad", "install reinstreq half-installed", "1.0", "")
	needs         = m{"packages": []string{"example-needs"}}
	bad           = m{"packages": []string{"example-bad"}}
)

type unfinishedPreview struct {
	preview
	Unfinished []recoverEntry `json:"unfinished"`
}

type reinstallPreview struct {
	Op            string         `json:"op"`
	Packages      []string       `json:"packages"`
	Reinstall     []recoverEntry `json:"reinstall"`
	Argv          []string       `json:"argv"`
	ExitCode      *int           `json:"exit_code"`
	PolicySHA256  string         `json:"policy_sha256"`
	PreviewSHA256 string         `json:"preview_sha256"`
}

type reinstallResult struct {
	Op          string              `json:"op"`
	Packages    []string            `json:"packages"`
	Reinstalled []recoverConfigured `json:"reinstalled"`
	ExitCode    *int                `json:"exit_code"`
	Attempts    int                 `json:"attempts"`
}

func (f *fixture) unfinishedPreview(op string, args m) unfinishedPreview {
	f.t.Helper()
	var p unfinishedPreview
	f.ok(op, args, &p)
	return p
}

func (f *fixture) reinstallPreview(args m) reinstallPreview {
	f.t.Helper()
	var p reinstallPreview
	f.ok("priv_pkg_reinstall_preview", args, &p)
	return p
}

func withExpected(args m, hash string) m {
	out := m{"expected_preview_sha256": hash}
	for k, v := range args {
		out[k] = v
	}
	return out
}

// refused serves op with args and requires a refusal with code whose
// message holds every string of in.
func (f *fixture) refused(what, op string, args any, code string, in ...string) {
	t := f.t
	t.Helper()
	r := f.serve(op, args)
	if r.OK || r.Error == nil || r.Error.Code != code {
		t.Fatalf("%s: %+v, want %s", what, r.Error, code)
	}
	for _, w := range in {
		if !strings.Contains(r.Error.Message, w) {
			t.Errorf("%s: %q lacks %q", what, r.Error.Message, w)
		}
	}
}

// TestPkgInstallPreviewUnfinishedField: a clean database's install and
// remove previews carry unfinished, empty, and keep their hash.
func TestPkgInstallPreviewUnfinishedField(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(pkgStanza("example-hello", "install ok installed", "1.0", ""), nil)
	for _, op := range []string{"priv_pkg_install_preview", "priv_pkg_remove_preview"} {
		p := f.unfinishedPreview(op, hello)
		if p.Unfinished == nil || len(p.Unfinished) != 0 {
			t.Fatalf("%s: unfinished %v, want []", op, p.Unfinished)
		}
	}
}

// TestPkgRemoveUnfinished (N-36 (ii), U1): a package whose dependency
// nothing provides is removed by a removal naming exactly it. The preview
// lists it with its version, state and missing dependency (so an approver
// sees a package that worked at an older version being removed, M2), and
// its hash binds that state; the operation runs the removal and answers
// from dpkg's status. The same hash again is refused: the state changed.
func TestPkgRemoveUnfinished(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(needsUnpacked+pkgStanza("example-hello", "install ok installed", "1.0", ""), nil)
	p := f.unfinishedPreview("priv_pkg_remove_preview", needs)
	if !slices.Equal(p.Remove, []entry{{Name: "example-needs", Version: "1.0"}}) || len(p.Install)+len(p.Upgrade) != 0 {
		t.Fatalf("preview %+v", p)
	}
	if len(p.Unfinished) != 1 || p.Unfinished[0].Name != "example-needs" || p.Unfinished[0].Version != "1.0" || p.Unfinished[0].State != "unpacked" ||
		p.Unfinished[0].Flag != "ok" || !slices.Equal(p.Unfinished[0].MissingDepends, []string{"example-absent"}) {
		t.Fatalf("unfinished %+v", p.Unfinished)
	}
	if again := f.unfinishedPreview("priv_pkg_remove_preview", needs); again.PreviewSHA256 != p.PreviewSHA256 {
		t.Fatal("the same state hashes differently")
	}
	var r pkgResult
	f.ok("priv_pkg_remove", withExpected(needs, p.PreviewSHA256), &r)
	if r.Applied == nil || !slices.Equal(r.Applied.Remove, []entry{{Name: "example-needs", Version: "1.0"}}) || len(r.Applied.Install)+len(r.Applied.Upgrade) != 0 {
		t.Fatalf("applied %+v", r.Applied)
	}
	if c := f.lastApt(); !slices.Equal(c.Args, slices.Concat(aptCommon, []string{"-o", "APT::Get::Purge=false", "remove", "--", "example-needs"})) {
		t.Fatalf("argv %q", c.Args)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-hello 1.0 installed", "example-needs 1.0 config-files"}) {
		t.Fatalf("dpkg %v", got)
	}
	if l := f.lastAudit(); !strings.Contains(l, `"op":"priv_pkg_remove"`) || !strings.Contains(l, `"outcome":"ok"`) {
		t.Fatalf("audit %q", l)
	}
	runs := len(f.realRuns())
	f.refused("the same hash again", "priv_pkg_remove", withExpected(needs, p.PreviewSHA256), "exists", "nothing was run")
	if len(f.realRuns()) != runs {
		t.Fatal("apt-get ran again")
	}
}

// TestPkgRemoveUnfinishedHash: the unfinished mode's hash is not the
// clean mode's for the same transaction, and covers the state: a package
// deselected on the host (its want changed) between the preview and the run is
// refused with exists, and nothing runs.
func TestPkgRemoveUnfinishedHash(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(needsUnpacked, nil)
	p := f.unfinishedPreview("priv_pkg_remove_preview", needs)
	f.setState(strings.Replace(needsUnpacked, "install ok unpacked", "deinstall ok unpacked", 1), nil)
	if moved := f.unfinishedPreview("priv_pkg_remove_preview", needs); moved.PreviewSHA256 == p.PreviewSHA256 {
		t.Fatal("a changed want left the hash unchanged")
	}
	f.refused("state changed", "priv_pkg_remove", withExpected(needs, p.PreviewSHA256), "exists", "nothing was run")
	if len(f.realRuns()) != 0 {
		t.Fatal("apt-get ran")
	}
	clean := unfinishedFixture(t)
	clean.setState(pkgStanza("example-needs", "install ok installed", "1.0", ""), nil)
	if c := clean.unfinishedPreview("priv_pkg_remove_preview", needs); c.PreviewSHA256 == p.PreviewSHA256 {
		t.Fatal("the unfinished and the clean removal of the same package hash the same")
	}
}

// TestPkgRemoveUnfinishedExactSet: in that state a removal must name
// exactly the unfinished packages that do not need a reinstall; anything
// else is refused, before anything runs, naming what each package needs;
// so is a removal while dpkg's journal has entries (apt refuses it), and
// one naming a package that needs a reinstall (dpkg refuses it).
func TestPkgRemoveUnfinishedExactSet(t *testing.T) {
	t.Parallel()
	two := needsUnpacked + pkgStanza("example-dep", "install ok unpacked", "1.0", "Depends: example-needs")
	for name, c := range map[string]struct {
		state   string
		journal map[string]string
		args    m
		want    []string
	}{
		"a subset":    {state: two, args: needs, want: []string{"exactly", "example-dep"}},
		"another":     {state: needsUnpacked, args: hello, want: []string{"exactly", "example-needs", "priv_pkg_remove"}},
		"one more":    {state: needsUnpacked, args: m{"packages": []string{"example-needs", "example-hello"}}, want: []string{"exactly", "example-needs"}},
		"journal":     {state: needsUnpacked, journal: map[string]string{"0000": needsUnpacked}, args: needs, want: []string{"journal", "priv_pkg_recover"}},
		"reinstall":   {state: badReinstreq, args: bad, want: []string{"example-bad", "cannot be removed", "priv_pkg_reinstall"}},
		"unreadable":  {state: needsUnpacked, journal: map[string]string{"0000": "not a stanza"}, args: needs, want: []string{"interrupted"}},
		"nothing set": {state: badReinstreq, args: needs, want: []string{"exactly", "priv_pkg_reinstall"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := unfinishedFixture(t)
			f.setState(c.state, c.journal)
			f.refused("preview", "priv_pkg_remove_preview", c.args, "exec_failed", c.want...)
			f.refused("operation", "priv_pkg_remove", withExpected(c.args, strings.Repeat("a", 64)), "exec_failed", c.want...)
			if len(f.realRuns()) != 0 {
				t.Fatal("apt-get ran")
			}
		})
	}
	// The whole set is accepted, as apt resolves it (U3, measured).
	f := unfinishedFixture(t)
	f.setState(two, nil)
	both := m{"packages": []string{"example-dep", "example-needs"}}
	p := f.unfinishedPreview("priv_pkg_remove_preview", both)
	if len(p.Remove) != 2 || len(p.Unfinished) != 2 {
		t.Fatalf("preview %+v", p)
	}
}

// TestPkgRemoveLeavesReinstall (M1, measured): with a package that needs
// a reinstall also unfinished, a removal of exactly the others runs, and
// the one left as it was is not a verify_failed; the result says what was
// removed. Then the reinstall finishes the last one.
func TestPkgRemoveLeavesReinstall(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(needsUnpacked+badReinstreq, nil)
	p := f.unfinishedPreview("priv_pkg_remove_preview", needs)
	if len(p.Unfinished) != 2 {
		t.Fatalf("the preview should show every unfinished package, the one left too: %+v", p.Unfinished)
	}
	var r pkgResult
	f.ok("priv_pkg_remove", withExpected(needs, p.PreviewSHA256), &r)
	if r.Applied == nil || !slices.Equal(r.Applied.Remove, []entry{{Name: "example-needs", Version: "1.0"}}) {
		t.Fatalf("applied %+v", r.Applied)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-bad 1.0 half-installed", "example-needs 1.0 config-files"}) {
		t.Fatalf("dpkg %v", got)
	}
	rp := f.reinstallPreview(bad)
	var rr reinstallResult
	f.ok("priv_pkg_reinstall", withExpected(bad, rp.PreviewSHA256), &rr)
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-bad 1.0 installed", "example-needs 1.0 config-files"}) {
		t.Fatalf("dpkg after the reinstall %v", got)
	}
}

// TestPkgRemoveUnfinishedResult: the removal's result in that state comes
// from dpkg's status: a package that needs a reinstall changed meanwhile,
// or an unfinished package left, is verify_failed; nothing removed is
// exec_failed.
func TestPkgRemoveUnfinishedResult(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(needsUnpacked, nil)
	p := f.unfinishedPreview("priv_pkg_remove_preview", needs)
	f.setModel(&pkgModel{Repo: unfinishedRepo(), Run: mrun{Fail: true}})
	f.refused("nothing changed", "priv_pkg_remove", withExpected(needs, p.PreviewSHA256), "exec_failed", "changed nothing")
	f.setModel(&pkgModel{Repo: unfinishedRepo(), Run: mrun{Extra: []mpkg{{Name: "example-extra", Version: "1.0"}}}})
	f.refused("more than approved", "priv_pkg_remove", withExpected(needs, p.PreviewSHA256), "verify_failed", "approved")
}

// TestPkgReinstall: a package that needs a reinstall, previewed and
// reinstalled at the version dpkg's status names, with the exact pinned
// argv, the package environment, and the result from dpkg's state.
func TestPkgReinstall(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(badReinstreq+pkgStanza("example-hello", "install ok installed", "1.0", ""), nil)
	p := f.reinstallPreview(bad)
	argv := slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "-s", "install", "--reinstall", "--", "example-bad=1.0"})
	if p.Op != "reinstall" || !slices.Equal(p.Packages, []string{"example-bad"}) || !slices.Equal(p.Argv, argv) || p.PolicySHA256 != f.opts.ExpectedSHA256 ||
		len(p.Reinstall) != 1 || p.Reinstall[0].Name != "example-bad" || p.Reinstall[0].Version != "1.0" || p.Reinstall[0].State != "half-installed" ||
		p.Reinstall[0].Flag != "reinstreq" || p.Reinstall[0].MissingDepends == nil {
		t.Fatalf("preview %+v", p)
	}
	if len(p.PreviewSHA256) != 64 || f.reinstallPreview(bad).PreviewSHA256 != p.PreviewSHA256 {
		t.Fatal("the hash is not stable")
	}
	if len(f.realRuns()) != 0 {
		t.Fatal("the preview ran apt-get for real")
	}
	var r reinstallResult
	f.ok("priv_pkg_reinstall", withExpected(bad, p.PreviewSHA256), &r)
	if r.Op != "reinstall" || !slices.Equal(r.Reinstalled, []recoverConfigured{{Name: "example-bad", Version: "1.0", FromState: "half-installed"}}) || r.Attempts != 1 {
		t.Fatalf("result %+v", r)
	}
	c := f.lastApt()
	if !slices.Equal(c.Args, slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "install", "--reinstall", "--", "example-bad=1.0"})) ||
		!slices.Contains(c.Env, "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("run %+v", c)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-bad 1.0 installed", "example-hello 1.0 installed"}) {
		t.Fatalf("dpkg %v", got)
	}
	l := f.lastAudit()
	if !strings.Contains(l, `"op":"priv_pkg_reinstall"`) || !strings.Contains(l, `"outcome":"ok"`) || !strings.Contains(l, `"reinstalled":["example-bad"]`) || strings.Contains(l, p.PreviewSHA256) {
		t.Fatalf("audit %q", l)
	}
	f.refused("the same hash again", "priv_pkg_reinstall", withExpected(bad, p.PreviewSHA256), "exec_failed", "nothing needs a reinstall")
}

// TestPkgReinstallRefusals: refused before anything runs, at the preview
// (so no approval is requested) and the operation alike.
func TestPkgReinstallRefusals(t *testing.T) {
	t.Parallel()
	two := badReinstreq + pkgStanza("example-bad2", "install ok half-installed", "2.0", "")
	for name, c := range map[string]struct {
		state   string
		journal map[string]string
		repo    []mpkg
		args    m
		code    string
		want    []string
	}{
		"not allowed":      {state: pkgStanza("example-hello", "install reinstreq half-installed", "1.0", ""), args: m{"packages": []string{"example-other"}}, code: "policy_denied", want: []string{"packages.install"}},
		"nothing":          {state: pkgStanza("example-hello", "install ok installed", "1.0", ""), args: bad, code: "exec_failed", want: []string{"nothing needs a reinstall"}},
		"another":          {state: badReinstreq, args: m{"packages": []string{"example-bad2"}}, code: "exec_failed", want: []string{"exactly", "example-bad"}},
		"a subset":         {state: two, args: bad, code: "exec_failed", want: []string{"exactly", "example-bad2"}},
		"to configure too": {state: badReinstreq + pkgStanza("example-hello", "install ok unpacked", "1.0", ""), args: bad, code: "exec_failed", want: []string{"example-hello", "priv_pkg_recover"}},
		"dependency too":   {state: badReinstreq + needsUnpacked, args: bad, code: "exec_failed", want: []string{"example-needs", "priv_pkg_remove"}},
		"journal":          {state: badReinstreq, journal: map[string]string{"0000": badReinstreq}, args: bad, code: "exec_failed", want: []string{"journal", "priv_pkg_recover"}},
		"no archive": {state: badReinstreq, repo: repoV1(), args: bad, code: "exec_failed",
			want: []string{"incomplete", "can't find an archive"}},
		"bad name":     {state: badReinstreq, args: m{"packages": []string{"example-bad-"}}, code: "bad_request"},
		"no names":     {state: badReinstreq, args: m{}, code: "bad_request"},
		"extra fields": {state: badReinstreq, args: m{"packages": []string{"example-bad"}, "version": "1.0"}, code: "bad_request"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := unfinishedFixture(t)
			if c.repo != nil {
				f.setModel(&pkgModel{Repo: c.repo})
			}
			f.setState(c.state, c.journal)
			f.refused("preview", "priv_pkg_reinstall_preview", c.args, c.code, c.want...)
			f.refused("operation", "priv_pkg_reinstall", withExpected(c.args, strings.Repeat("a", 64)), c.code, c.want...)
			if len(f.realRuns()) != 0 {
				t.Fatal("apt-get ran")
			}
		})
	}
	off := newFixture(t, broadUsers(), unfinishedLists(), withModel(&pkgModel{Repo: unfinishedRepo()}), asBroad(),
		replace("  enabled: true\n", "  enabled: false\n"))
	off.fail("priv_pkg_reinstall_preview", bad, "policy_denied")
	core := newFixture(t, broadUsers(), unfinishedLists(), withModel(&pkgModel{Repo: unfinishedRepo()}))
	core.fail("priv_pkg_reinstall_preview", bad, "helper_wrong_unit")
	core.fail("priv_pkg_reinstall", withExpected(bad, strings.Repeat("a", 64)), "helper_wrong_unit")
	f := unfinishedFixture(t)
	f.setState(badReinstreq, nil)
	f.fail("priv_pkg_reinstall", bad, "bad_request")
	f.fail("priv_pkg_reinstall", withExpected(bad, "nothex"), "bad_request")
}

// TestPkgReinstallStateChanged: the state changes between the preview and
// the run (the package's want, on the host): exists, and nothing runs.
func TestPkgReinstallStateChanged(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(badReinstreq, nil)
	p := f.reinstallPreview(bad)
	f.setState(strings.Replace(badReinstreq, "install reinstreq", "deinstall reinstreq", 1), nil)
	f.refused("state changed", "priv_pkg_reinstall", withExpected(bad, p.PreviewSHA256), "exists", "nothing was run")
	if len(f.realRuns()) != 0 {
		t.Fatal("apt-get ran")
	}
}

// TestPkgReinstallResult: decided from dpkg's state: nothing changed is
// exec_failed; the package left unfinished, or anything else changed, is
// verify_failed.
func TestPkgReinstallResult(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		run  mrun
		code string
		want string
	}{
		"nothing":    {mrun{Fail: true}, "exec_failed", "changed nothing"},
		"unfinished": {mrun{Unfinished: "example-bad"}, "verify_failed", "example-bad"},
		"more":       {mrun{Extra: []mpkg{{Name: "example-extra", Version: "1.0"}}}, "verify_failed", "example-extra"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := unfinishedFixture(t)
			f.setState(badReinstreq, nil)
			p := f.reinstallPreview(bad)
			f.setModel(&pkgModel{Repo: unfinishedRepo(), Run: c.run})
			f.refused(name, "priv_pkg_reinstall", withExpected(bad, p.PreviewSHA256), c.code, c.want)
		})
	}
}

// TestPkgReinstallInProgress: the reinstall takes the package operation
// record, so a preview meanwhile refuses, and it waits for the dpkg lock
// by the lock rule like the other package operations.
func TestPkgReinstallInProgress(t *testing.T) {
	t.Parallel()
	f := unfinishedFixture(t)
	f.setState(badReinstreq, nil)
	release := f.holdRecord(`{"request_id":"0b5c0000-0000-4000-8000-0000000000bb","started":"2026-09-29T12:00:00Z","until":"2026-09-29T12:15:00Z"}`)
	f.refused("preview", "priv_pkg_reinstall_preview", bad, "exec_failed", "package operation in progress")
	f.refused("operation", "priv_pkg_reinstall", withExpected(bad, strings.Repeat("a", 64)), "exec_failed", "package operation in progress")
	release()
	_, unlock := f.holdDpkgLock()
	f.refused("lock held", "priv_pkg_reinstall_preview", bad, "exec_failed", "locked by")
	unlock()
}

// TestPkgRecoverRefusesOnlyMissingDependencies (F1, U1 measured): with
// only packages whose dependency nothing provides (and those that need a
// reinstall), a recovery would change nothing (dpkg exits 1 and leaves
// them), so its preview refuses, naming the removal; nothing runs.
func TestPkgRecoverRefusesOnlyMissingDependencies(t *testing.T) {
	t.Parallel()
	for name, state := range map[string]string{"dependency": needsUnpacked, "with a reinstall": needsUnpacked + badReinstreq} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := recoverFixture(t)
			f.setState(state, nil)
			f.refused("preview", "priv_pkg_recover_preview", m{}, "exec_failed", "would change nothing", "example-needs", "priv_pkg_remove")
			f.refused("operation", "priv_pkg_recover", m{"expected_preview_sha256": strings.Repeat("a", 64)}, "exec_failed", "would change nothing")
			if len(f.dpkgRuns()) != 0 {
				t.Fatal("dpkg ran")
			}
		})
	}
	// With the journal it still runs: the recovery folds it.
	f := recoverFixture(t)
	f.setState(needsUnpacked, map[string]string{"0000": needsUnpacked})
	if p := f.recoverPreview(); p.JournalEntries != 1 {
		t.Fatalf("preview %+v", p)
	}
}
