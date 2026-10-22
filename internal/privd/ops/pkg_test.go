//go:build linux

package ops_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
)

// The package operations (S4c-7; PRIVILEGED §6 "Package operations";
// handoff D5, P-2e, P-3, P-5, P-6) against the apt-get stand-in's model of
// an invented repository and dpkg status file (internal/privd/pkg/
// testdata/fakeapt). Real apt and dpkg are the e2e job's.

type aptCall struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

func (f *fixture) aptCalls() []aptCall {
	f.t.Helper()
	fh, err := os.Open(f.aptLog)
	if err != nil {
		return nil
	}
	defer func() { _ = fh.Close() }()
	var out []aptCall
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var c aptCall
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func (f *fixture) lastApt() aptCall {
	f.t.Helper()
	c := f.aptCalls()
	if len(c) == 0 {
		f.t.Fatal("apt-get was not run")
	}
	return c[len(c)-1]
}

// realRuns are the apt-get runs that were not simulations.
func (f *fixture) realRuns() []aptCall {
	var out []aptCall
	for _, c := range f.aptCalls() {
		if !slices.Contains(c.Args, "-s") {
			out = append(out, c)
		}
	}
	return out
}

var aptCommon = []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Use-Pty=0", "-o", "APT::Get::AutomaticRemove=false"}

type entry struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

type txLists struct {
	Install []entry `json:"install"`
	Upgrade []entry `json:"upgrade"`
	Remove  []entry `json:"remove"`
}

type pkgResult struct {
	Op         string   `json:"op"`
	Packages   []string `json:"packages"`
	Applied    *txLists `json:"applied"`
	ExitCode   *int     `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	Truncated  bool     `json:"stdout_truncated"`
	Attempts   int      `json:"attempts"`
	LockWaitMS int64    `json:"lock_wait_ms"`
}

type preview struct {
	Op            string   `json:"op"`
	Packages      []string `json:"packages"`
	Install       []entry  `json:"install"`
	Upgrade       []entry  `json:"upgrade"`
	Remove        []entry  `json:"remove"`
	Complete      bool     `json:"complete"`
	ExitCode      *int     `json:"exit_code"`
	Argv          []string `json:"argv"`
	PolicySHA256  string   `json:"policy_sha256"`
	PreviewSHA256 string   `json:"preview_sha256"`
}

// The model of the apt-get stand-in (fakeapt's modelDef).
type mpkg struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Depends   []string `json:"depends,omitempty"`
	Conflicts []string `json:"conflicts,omitempty"`
}

type mrun struct {
	Extra           []mpkg `json:"extra,omitempty"`
	Partial         int    `json:"partial,omitempty"`
	Unfinished      string `json:"unfinished,omitempty"`
	SlowMS          int    `json:"slow_ms,omitempty"`
	OnInt           string `json:"on_int,omitempty"`
	IgnoreTerm      bool   `json:"ignore_term,omitempty"`
	UnfinishedFirst bool   `json:"unfinished_first,omitempty"`
	Child           string `json:"child,omitempty"`
	Fail            bool   `json:"fail,omitempty"`
	Exit            int    `json:"exit,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Flood           bool   `json:"flood,omitempty"`
}

type pkgModel struct {
	DpkgDir   string `json:"dpkg_dir"`
	Repo      []mpkg `json:"repo"`
	SwapAfter int    `json:"swap_after,omitempty"`
	SwapRepo  []mpkg `json:"swap_repo,omitempty"`
	Run       mrun   `json:"run"`
}

// repoV1 is the invented repository: example-hello 1.1 (its candidate)
// depends on example-lib.
func repoV1() []mpkg {
	return []mpkg{{Name: "example-lib", Version: "2.1-1"}, {Name: "example-hello", Version: "1.0", Depends: []string{"example-lib"}},
		{Name: "example-hello", Version: "1.1", Depends: []string{"example-lib"}}, {Name: "example-extra", Version: "1.0"}}
}

// dpkgStatus is a dpkg status file with dpkg itself (the native
// architecture) and the given "name=version" packages installed.
func dpkgStatus(installed ...string) string {
	var b strings.Builder
	b.WriteString("Package: dpkg\nStatus: install ok installed\nPriority: required\nArchitecture: amd64\nVersion: 1.22.22\nDescription: invented\n continuation\n\n")
	for _, p := range installed {
		n, v, _ := strings.Cut(p, "=")
		state := "installed"
		if s, ok := strings.CutPrefix(v, "half:"); ok {
			v, state = s, "half-configured"
		}
		fmt.Fprintf(&b, "Package: %s\nStatus: install ok %s\nArchitecture: all\nVersion: %s\n\n", n, state, v)
	}
	return b.String()
}

// withModel makes the stand-in the model with mod, and dpkg's status the
// given installed packages.
func withModel(mod *pkgModel, installed ...string) opt {
	return func(f *fixture, s *string) {
		withFakeApt("model")(f, s)
		f.setModel(mod)
		gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "status"), dpkgStatus(installed...), 0o644)
	}
}

func (f *fixture) setModel(mod *pkgModel) {
	f.t.Helper()
	m := *mod
	m.DpkgDir = f.dpkg
	if m.Repo == nil {
		m.Repo = repoV1()
	}
	b, _ := json.Marshal(&m)
	gatetest.WriteFile(f.t, f.aptLog+".model.json", string(b), 0o600)
}

// aptRuns is how many apt-get runs the stand-in has finished.
func (f *fixture) aptRuns() int {
	b, _ := os.ReadFile(f.aptLog + ".count")
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// dpkgState is the status file as "name version state" per package (dpkg
// itself left out).
func (f *fixture) dpkgState() []string {
	f.t.Helper()
	var out []string
	for _, stanza := range strings.Split(strings.TrimSpace(readFile(f.t, filepath.Join(f.dpkg, "status"))), "\n\n") {
		var n, v, s string
		for _, l := range strings.Split(stanza, "\n") {
			k, val, _ := strings.Cut(l, ": ")
			switch k {
			case "Package":
				n = val
			case "Version":
				v = val
			case "Status":
				s = val[strings.LastIndex(val, " ")+1:]
			}
		}
		if n != "dpkg" {
			out = append(out, n+" "+v+" "+s)
		}
	}
	slices.Sort(out)
	return out
}

// pkgFixture is the broad unit's helper with packages enabled and the
// apt-get stand-in.
func pkgFixture(t *testing.T, mode string, opts ...opt) *fixture {
	t.Helper()
	return newFixture(t, append([]opt{broadUsers(), withFakeApt(mode), asBroad()}, opts...)...)
}

// modelFixture is pkgFixture with the model and the installed packages.
func modelFixture(t *testing.T, mod *pkgModel, installed []string, opts ...opt) *fixture {
	t.Helper()
	return newFixture(t, append([]opt{broadUsers(), withModel(mod, installed...), asBroad()}, opts...)...)
}

func allowUpgrade() opt {
	return replace("  allow_update_index: true\n", "  allow_update_index: true\n  allow_upgrade: true\n")
}

func (f *fixture) pkgPreview(op string, args m) *preview {
	f.t.Helper()
	var p preview
	f.ok(op+"_preview", args, &p)
	return &p
}

// bound returns args with the preview's hash as expected_preview_sha256.
func bound(args m, p *preview) m {
	out := m{"expected_preview_sha256": p.PreviewSHA256}
	for k, v := range args {
		out[k] = v
	}
	return out
}

var hello = m{"packages": []string{"example-hello"}}

// TestPkgPreview (P-5): a preview returns the simulated transaction with
// exact versions, the argv it simulated, the privileged policy's hash and
// a preview_sha256 that is stable and changes with the transaction; it
// changes nothing.
func TestPkgPreview(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, nil)
	p := f.pkgPreview("priv_pkg_install", hello)
	if p.Op != "install" || !slices.Equal(p.Packages, []string{"example-hello"}) || !p.Complete ||
		!slices.Equal(p.Install, []entry{{Name: "example-hello", Version: "1.1"}, {Name: "example-lib", Version: "2.1-1"}}) || len(p.Upgrade)+len(p.Remove) != 0 {
		t.Fatalf("preview %+v", p)
	}
	if want := slices.Concat(aptCommon, []string{"--no-install-recommends", "-s", "install", "--", "example-hello"}); !slices.Equal(p.Argv, want) || !slices.Equal(f.lastApt().Args, want) {
		t.Fatalf("argv %q (ran %q)\nwant %q", p.Argv, f.lastApt().Args, want)
	}
	if p.PolicySHA256 != f.opts.ExpectedSHA256 || len(p.PreviewSHA256) != 64 || strings.Trim(p.PreviewSHA256, "0123456789abcdef") != "" {
		t.Fatalf("hashes %q %q", p.PolicySHA256, p.PreviewSHA256)
	}
	if again := f.pkgPreview("priv_pkg_install", hello); again.PreviewSHA256 != p.PreviewSHA256 {
		t.Fatal("the same transaction hashes differently")
	}
	f.setModel(&pkgModel{Repo: append(repoV1(), mpkg{Name: "example-hello", Version: "1.2", Depends: []string{"example-lib"}})})
	if moved := f.pkgPreview("priv_pkg_install", hello); moved.PreviewSHA256 == p.PreviewSHA256 || moved.Install[0].Version != "1.2" {
		t.Fatalf("a new candidate: %+v", moved)
	}
	if len(f.realRuns()) != 0 || len(f.dpkgState()) != 0 {
		t.Fatalf("a preview changed something: %v %v", f.realRuns(), f.dpkgState())
	}
	var u struct {
		Argv          []string `json:"argv"`
		PolicySHA256  string   `json:"policy_sha256"`
		PreviewSHA256 string   `json:"preview_sha256"`
	}
	f.ok("priv_pkg_update_index_preview", m{}, &u)
	if !slices.Equal(u.Argv, []string{"-q", "update"}) || u.PolicySHA256 != f.opts.ExpectedSHA256 || len(u.PreviewSHA256) != 64 {
		t.Fatalf("update preview %+v", u)
	}
	if len(f.realRuns()) != 0 {
		t.Fatal("the update preview ran apt-get")
	}
	off := modelFixture(t, &pkgModel{}, nil, replace("  allow_update_index: true\n", "  allow_update_index: false\n"))
	off.fail("priv_pkg_update_index_preview", m{}, "policy_denied")
}

// TestPkgInstallBound: an install runs exactly the approved transaction:
// the preview's argv simulated again, then the pinned argv simulated and
// run (each requested name pinned, --no-remove); the result is what dpkg's
// status shows changed.
func TestPkgInstallBound(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, nil)
	p := f.pkgPreview("priv_pkg_install", hello)
	var r pkgResult
	f.ok("priv_pkg_install", bound(hello, p), &r)
	want := txLists{Install: []entry{{Name: "example-hello", Version: "1.1"}, {Name: "example-lib", Version: "2.1-1"}}, Upgrade: []entry{}, Remove: []entry{}}
	if r.Applied == nil || fmt.Sprint(*r.Applied) != fmt.Sprint(want) || r.Op != "install" || r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("result %+v applied %+v", r, r.Applied)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-hello 1.1 installed", "example-lib 2.1-1 installed"}) {
		t.Fatalf("dpkg %v", got)
	}
	calls := f.aptCalls()
	pinned := slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "install", "--", "example-hello=1.1"})
	if len(calls) != 4 || !slices.Equal(calls[1].Args, p.Argv) || !slices.Equal(calls[2].Args, slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "-s", "install", "--", "example-hello=1.1"})) ||
		!slices.Equal(calls[3].Args, pinned) {
		t.Fatalf("apt-get runs %q", calls)
	}
	if !slices.Contains(calls[3].Env, "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("env %q", calls[3].Env)
	}
	l := f.lastAudit()
	if !strings.HasPrefix(l, "<4>") || !strings.Contains(l, `"packages":["example-hello"]`) || !strings.Contains(l, `"applied":`) ||
		!strings.Contains(l, `"example-lib"`) || strings.Contains(l, p.PreviewSHA256) {
		t.Fatalf("audit %q", l)
	}
}

// TestPkgRequiresPreviewHash (P-3): every package operation requires the
// preview's hash, well formed; nothing runs without it.
func TestPkgRequiresPreviewHash(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, []string{"example-hello=1.0", "example-lib=2.1-1"}, allowUpgrade())
	for op, args := range map[string]m{"priv_pkg_install": hello, "priv_pkg_remove": hello, "priv_pkg_upgrade": {}, "priv_pkg_update_index": {}} {
		f.fail(op, args, "bad_request")
		for _, bad := range []string{"", "abc", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
			f.fail(op, bound(args, &preview{PreviewSHA256: bad}), "bad_request")
		}
	}
	if r := f.realRuns(); len(r) != 0 {
		t.Fatalf("apt-get ran for refused requests: %q", r)
	}
}

// TestPkgChangedSincePreview: a transaction that changed after its preview
// is refused with exists and nothing runs: a new candidate version, a new
// dependency, or a pinned argv whose transaction differs from the approved
// one (the repository changed between the two simulations of the
// operation; an extra dependency pulled in by --only-upgrade).
func TestPkgChangedSincePreview(t *testing.T) {
	t.Parallel()
	newDep := func(r []mpkg) []mpkg {
		for i := range r {
			if r[i].Name == "example-hello" && r[i].Version == "1.1" {
				r[i].Depends = append(r[i].Depends, "example-new")
			}
		}
		return append(r, mpkg{Name: "example-new", Version: "0.1"})
	}
	for name, c := range map[string]struct {
		op        string
		args      m
		installed []string
		change    func(f *fixture)
	}{
		"install/version": {"priv_pkg_install", hello, nil, func(f *fixture) {
			f.setModel(&pkgModel{Repo: append(repoV1(), mpkg{Name: "example-hello", Version: "1.2", Depends: []string{"example-lib"}})})
		}},
		"install/dependency": {"priv_pkg_install", hello, nil, func(f *fixture) { f.setModel(&pkgModel{Repo: newDep(repoV1())}) }},
		"install/between simulations": {"priv_pkg_install", hello, nil, func(f *fixture) {
			f.setModel(&pkgModel{SwapAfter: f.aptRuns() + 1, SwapRepo: slices.Concat([]mpkg{{Name: "example-lib", Version: "2.2-1"}}, repoV1()[1:])})
		}},
		"upgrade/new dependency between simulations": {"priv_pkg_upgrade", m{}, []string{"example-hello=1.0", "example-lib=2.1-1"}, func(f *fixture) {
			f.setModel(&pkgModel{SwapAfter: f.aptRuns() + 1, SwapRepo: newDep(repoV1())})
		}},
		"upgrade/version": {"priv_pkg_upgrade", m{}, []string{"example-hello=1.0", "example-lib=2.1-1"}, func(f *fixture) {
			f.setModel(&pkgModel{Repo: append(repoV1(), mpkg{Name: "example-hello", Version: "1.2", Depends: []string{"example-lib"}})})
		}},
		"remove/version": {"priv_pkg_remove", hello, []string{"example-hello=1.1", "example-lib=2.1-1"}, func(f *fixture) {
			gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "status"), dpkgStatus("example-hello=1.0", "example-lib=2.1-1"), 0o644)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := modelFixture(t, &pkgModel{}, c.installed, allowUpgrade())
			p := f.pkgPreview(c.op, c.args)
			c.change(f)
			before := f.dpkgState()
			f.fail(c.op, bound(c.args, p), "exists")
			if r := f.realRuns(); len(r) != 0 {
				t.Fatalf("apt-get ran: %q", r)
			}
			if got := f.dpkgState(); !slices.Equal(got, before) {
				t.Fatalf("dpkg changed: %v, was %v", got, before)
			}
		})
	}
}

// TestPkgResultFromStatus (maintainer condition 2): the result is decided
// by dpkg's status and its unfinished state alone, never by apt's exit
// code.
func TestPkgResultFromStatus(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		run      mrun
		code     string
		state    []string
		inMsg    string
		exitCode int
	}{
		"exactly":                {mrun{}, "", []string{"example-hello 1.1 installed", "example-lib 2.1-1 installed"}, "", 0},
		"exactly; apt exits 100": {mrun{Exit: 100}, "", []string{"example-hello 1.1 installed", "example-lib 2.1-1 installed"}, "", 100},
		"extra package":          {mrun{Extra: []mpkg{{Name: "example-extra", Version: "1.0"}}}, "verify_failed", nil, "example-extra", 0},
		"part of it; exit 0":     {mrun{Partial: 1}, "verify_failed", nil, "approved", 0},
		"unfinished":             {mrun{Unfinished: "example-hello"}, "verify_failed", nil, "dpkg --configure -a", 0},
		"nothing changed":        {mrun{Fail: true}, "exec_failed", []string{}, "Failed to fetch", 100},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := modelFixture(t, &pkgModel{Run: c.run}, nil)
			p := f.pkgPreview("priv_pkg_install", hello)
			r := f.serve("priv_pkg_install", bound(hello, p))
			if c.code == "" {
				var d pkgResult
				if !r.OK || json.Unmarshal(r.Data, &d) != nil || d.ExitCode == nil || *d.ExitCode != c.exitCode {
					t.Fatalf("%+v %s", r.Error, r.Data)
				}
			} else if r.OK || r.Error == nil || r.Error.Code != c.code || !strings.Contains(r.Error.Message, c.inMsg) {
				t.Fatalf("got %+v, want %s mentioning %q", r.Error, c.code, c.inMsg)
			}
			if c.state != nil && !slices.Equal(f.dpkgState(), c.state) {
				t.Fatalf("dpkg %v", f.dpkgState())
			}
			if l := f.lastAudit(); c.code != "" && !strings.Contains(l, `"outcome":"`+c.code+`"`) {
				t.Fatalf("audit %q", l)
			}
		})
	}
}

// TestPkgUpgradeAndRemove: an upgrade runs exactly the approved list as
// install --only-upgrade --no-remove with every package pinned, never
// apt-get upgrade; a removal is not pinned and never purges; a transaction
// with nothing to change runs nothing.
func TestPkgUpgradeAndRemove(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, []string{"example-hello=1.0", "example-lib=2.1-1"}, allowUpgrade())
	p := f.pkgPreview("priv_pkg_upgrade", m{})
	if !slices.Equal(p.Upgrade, []entry{{Name: "example-hello", From: "1.0", To: "1.1"}}) || !slices.Equal(p.Argv, slices.Concat(aptCommon, []string{"--no-install-recommends", "-s", "upgrade"})) {
		t.Fatalf("upgrade preview %+v", p)
	}
	var r pkgResult
	f.ok("priv_pkg_upgrade", bound(m{}, p), &r)
	if want := slices.Concat(aptCommon, []string{"--no-install-recommends", "--no-remove", "--only-upgrade", "install", "--", "example-hello=1.1"}); !slices.Equal(f.lastApt().Args, want) {
		t.Fatalf("upgrade argv %q\nwant %q", f.lastApt().Args, want)
	}
	if r.Applied == nil || len(r.Applied.Upgrade) != 1 || r.Applied.Upgrade[0] != (entry{Name: "example-hello", From: "1.0", To: "1.1"}) {
		t.Fatalf("upgrade applied %+v", r.Applied)
	}
	p = f.pkgPreview("priv_pkg_remove", hello)
	if !slices.Equal(p.Remove, []entry{{Name: "example-hello", Version: "1.1"}}) {
		t.Fatalf("remove preview %+v", p)
	}
	f.ok("priv_pkg_remove", bound(hello, p), &r)
	if c := f.lastApt(); !slices.Equal(c.Args, slices.Concat(aptCommon, []string{"-o", "APT::Get::Purge=false", "remove", "--", "example-hello"})) {
		t.Fatalf("remove argv %q", c.Args)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-hello 1.1 config-files", "example-lib 2.1-1 installed"}) {
		t.Fatalf("dpkg %v", got)
	}
	// Nothing to change: approved, and nothing runs.
	runs := len(f.realRuns())
	p = f.pkgPreview("priv_pkg_upgrade", m{})
	if len(p.Upgrade)+len(p.Install)+len(p.Remove) != 0 {
		t.Fatalf("nothing to upgrade: %+v", p)
	}
	f.ok("priv_pkg_upgrade", bound(m{}, p), &r)
	if len(f.realRuns()) != runs || r.Applied == nil || len(r.Applied.Upgrade) != 0 {
		t.Fatalf("an empty transaction ran apt-get, or applied %+v", r.Applied)
	}
	// Its journal line says what changed: nothing.
	if l := f.lastAudit(); !strings.Contains(l, `"applied":{"install":[],"upgrade":[],"remove":[]}`) {
		t.Fatalf("audit of an empty transaction %q", l)
	}
}

// TestPkgRefusedUpFront: a preview refuses whatever the operation would
// refuse, so no approval is requested, and the operation refuses it too,
// before anything runs: packages dpkg left unfinished, dpkg's journal not
// empty, an incomplete simulation, an install that would remove a package.
func TestPkgRefusedUpFront(t *testing.T) {
	t.Parallel()
	anyHash := strings.Repeat("a", 64)
	for name, c := range map[string]struct {
		mode      string
		installed []string
		setup     func(f *fixture)
		code      string
		inMsg     string
	}{
		"unfinished": {"model", []string{"example-hello=half:1.0"}, nil, "exec_failed", "dpkg --configure -a"},
		"journal": {"model", nil, func(f *fixture) {
			gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "updates", "0000"), "Package: example-hello\n", 0o644)
		}, "exec_failed", "dpkg --configure -a"},
		"incomplete": {"sim", nil, nil, "exec_failed", "incomplete"},
		"removes": {"model", []string{"example-old=0.9"}, func(f *fixture) {
			f.setModel(&pkgModel{Repo: []mpkg{{Name: "example-hello", Version: "1.1", Conflicts: []string{"example-old"}}}})
		}, "policy_denied", "remove"},
		"unknown package": {"model", nil, func(f *fixture) { f.setModel(&pkgModel{Repo: []mpkg{{Name: "example-lib", Version: "1"}}}) }, "exec_failed", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var f *fixture
			if c.mode == "model" {
				f = modelFixture(t, &pkgModel{}, c.installed)
			} else {
				f = pkgFixture(t, c.mode)
			}
			if c.setup != nil {
				c.setup(f)
			}
			for op, args := range map[string]m{"priv_pkg_install_preview": hello, "priv_pkg_install": bound(hello, &preview{PreviewSHA256: anyHash})} {
				r := f.serve(op, args)
				if r.OK || r.Error == nil || r.Error.Code != c.code || !strings.Contains(r.Error.Message, c.inMsg) {
					t.Fatalf("%s: %+v, want %s mentioning %q", op, r.Error, c.code, c.inMsg)
				}
			}
			if len(f.realRuns()) != 0 {
				t.Fatal("apt-get ran")
			}
		})
	}
}

// Only names from packages.install (packages.remove for removal); names
// that are not Debian package names, options, versions, paths and anything
// else are refused; nothing runs.
func TestPkgAllowList(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, nil)
	h := strings.Repeat("a", 64)
	for op, args := range map[string]m{
		"priv_pkg_install":         {"packages": []string{"example-other"}, "expected_preview_sha256": h},
		"priv_pkg_install_preview": {"packages": []string{"example-hello", "example-other"}},
		"priv_pkg_remove":          {"packages": []string{"example-other"}, "expected_preview_sha256": h},
		"priv_pkg_remove_preview":  {"packages": []string{"example-other"}},
	} {
		f.fail(op, args, "policy_denied")
	}
	for _, names := range [][]string{{}, {"-oAPT::Get::Purge=true"}, {"Example-hello"}, {"example-hello", "example-hello"}, {"example-hello=1.0"},
		{"./example-hello_1.1_all.deb"}, {"/srv/invented/example-hello_1.1_all.deb"}, {"example-hello/stable"}, {"example-hello:i386"}, {"example-hello-"},
		strings.Fields(strings.Repeat("example-hello ", 21))} {
		f.fail("priv_pkg_install_preview", m{"packages": names}, "bad_request")
		f.fail("priv_pkg_install", m{"packages": names, "expected_preview_sha256": h}, "bad_request")
	}
	for _, extra := range []m{{"options": []string{"-o", "x"}}, {"source": "deb file:/srv/invented ./"}, {"key": "x"}, {"hold": true}, {"version": "1.0"}} {
		a := m{"packages": []string{"example-hello"}, "expected_preview_sha256": h}
		for k, v := range extra {
			a[k] = v
		}
		f.fail("priv_pkg_install", a, "bad_request")
		f.fail("priv_pkg_upgrade_preview", extra, "bad_request")
	}
	f.fail("priv_pkg_install", m{"expected_preview_sha256": h}, "bad_request")
	if n := len(f.aptCalls()); n != 0 {
		t.Fatalf("apt-get ran %d times for refused requests", n)
	}
}

// Upgrade (and its preview) only with allow_upgrade: true; the index
// update only with allow_update_index: true; nothing with packages
// disabled.
func TestPkgPolicySwitches(t *testing.T) {
	t.Parallel()
	h := strings.Repeat("a", 64)
	f := modelFixture(t, &pkgModel{}, nil)
	f.fail("priv_pkg_upgrade", m{"expected_preview_sha256": h}, "policy_denied")
	f.fail("priv_pkg_upgrade_preview", m{}, "policy_denied")
	off := modelFixture(t, &pkgModel{}, nil, replace("  enabled: true\n", "  enabled: false\n"))
	for op, args := range map[string]m{
		"priv_pkg_update_index":         {"expected_preview_sha256": h},
		"priv_pkg_update_index_preview": {},
		"priv_pkg_install":              {"packages": []string{"example-hello"}, "expected_preview_sha256": h},
		"priv_pkg_install_preview":      hello,
		"priv_pkg_remove":               {"packages": []string{"example-hello"}, "expected_preview_sha256": h},
	} {
		off.fail(op, args, "policy_denied")
	}
	if len(off.aptCalls()) != 0 {
		t.Fatal("apt-get ran with packages disabled")
	}
	// At max_tier read, the operations themselves are refused.
	r := modelFixture(t, &pkgModel{}, nil, maxTier("read"))
	for _, op := range []string{"priv_pkg_install", "priv_pkg_remove", "priv_pkg_update_index", "priv_pkg_upgrade"} {
		r.fail(op, m{"packages": []string{"example-hello"}, "expected_preview_sha256": h}, "tier_denied")
	}
	r.ok("priv_pkg_install_preview", hello, nil)
}

// TestPkgUpdateIndex: the index update is bound to its preview and its lock
// is waited for, bounded, then reported; nothing else is retried. Not
// parallel: it bounds the wait's wall-clock time.
func TestPkgUpdateIndex(t *testing.T) {
	f := pkgFixture(t, "lock 1")
	f.opts.PkgLockRetry = 20 * time.Millisecond
	var u preview
	f.ok("priv_pkg_update_index_preview", m{}, &u)
	f.fail("priv_pkg_update_index", m{"expected_preview_sha256": strings.Repeat("b", 64)}, "exists")
	var r pkgResult
	f.ok("priv_pkg_update_index", m{"expected_preview_sha256": u.PreviewSHA256}, &r)
	if r.Attempts != 2 || r.LockWaitMS <= 0 || *r.ExitCode != 0 || !slices.Equal(f.lastApt().Args, []string{"-q", "update"}) {
		t.Fatalf("after one held lock: %+v %q", r, f.lastApt().Args)
	}
	held := pkgFixture(t, "lockforever")
	held.opts.PkgLockRetry = 50 * time.Millisecond
	held.ok("priv_pkg_update_index_preview", m{}, &u)
	start := time.Now()
	resp := held.serve("priv_pkg_update_index", m{"expected_preview_sha256": u.PreviewSHA256})
	if resp.OK || resp.Error == nil || resp.Error.Code != "exec_failed" || !strings.Contains(resp.Error.Message, "apt-get (pid 4242)") {
		t.Fatalf("held lock: %+v", resp.Error)
	}
	// The fixture's request timeout is 5 s: the wait is at most half of it.
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("waited %v for the lock", d)
	}
}

// Output is capped and redacted.
func TestPkgOutput(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{Run: mrun{Stdout: "-----BEGIN " + "OPENSSH PRIVATE KEY-----\naW52ZW50ZWQgdGVzdCBrZXkgbWF0ZXJpYWw=\n-----END " + "OPENSSH PRIVATE KEY-----"}}, nil)
	var r pkgResult
	f.ok("priv_pkg_install", bound(hello, f.pkgPreview("priv_pkg_install", hello)), &r)
	if strings.Contains(r.Stdout, "aW52ZW50ZWQ") || !strings.Contains(r.Stdout, "REDACTED") {
		t.Fatalf("private key not redacted: %q", r.Stdout)
	}
	fl := modelFixture(t, &pkgModel{Run: mrun{Flood: true}}, nil)
	fl.ok("priv_pkg_install", bound(hello, fl.pkgPreview("priv_pkg_install", hello)), &r)
	if len(r.Stdout) > 4096 || !r.Truncated {
		t.Fatalf("output %d bytes, truncated %v (max_output_bytes 4096)", len(r.Stdout), r.Truncated)
	}
}

// holdRecord holds the package operation record as a running operation
// would (an exclusive flock(2) on its own open file description) with the
// given content, until the test ends or release is called.
func (f *fixture) holdRecord(content string) (release func()) {
	f.t.Helper()
	fh, err := os.OpenFile(f.record, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := unix.Flock(int(fh.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.t.Fatal(err)
	}
	if _, err := fh.WriteString(content); err != nil {
		f.t.Fatal(err)
	}
	done := false
	release = func() {
		if !done {
			done = true
			_ = fh.Close()
		}
	}
	f.t.Cleanup(release)
	return release
}

// TestPkgInProgress (maintainer condition 3): while a package operation
// holds its record, previews and further package operations say so, naming
// its request id, start and the time it may run until, instead of a lock
// error or a simulation of a state about to change. The record decides,
// not its contents alone: a record nobody holds is not in progress.
func TestPkgInProgress(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, nil, allowUpgrade())
	p := f.pkgPreview("priv_pkg_install", hello)
	other := "0b5c0000-0000-4000-8000-0000000000aa"
	rec := `{"request_id":"` + other + `","started":"2026-09-29T12:00:00Z","until":"2026-09-29T12:15:00Z"}`
	release := f.holdRecord(rec)
	for op, args := range map[string]m{"priv_pkg_install_preview": hello, "priv_pkg_upgrade_preview": {}, "priv_pkg_remove_preview": hello, "priv_pkg_install": bound(hello, p)} {
		r := f.serve(op, args)
		if r.OK || r.Error == nil || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "package operation in progress") ||
			!strings.Contains(r.Error.Message, other) || !strings.Contains(r.Error.Message, "2026-09-29T12:15:00Z") {
			t.Fatalf("%s: %+v", op, r.Error)
		}
	}
	if len(f.realRuns()) != 0 {
		t.Fatal("apt-get ran while another operation was in progress")
	}
	release()
	// The same record, no longer held: not in progress.
	gatetest.WriteFile(t, f.record, rec, 0o600)
	var r pkgResult
	f.ok("priv_pkg_install", bound(hello, p), &r)
}

// TestPkgLockHolder (maintainer condition 7): the dpkg frontend lock held
// by another process: a preview refuses at once, naming the holder; an
// operation waits, at most min(60 s, timeout / 2), then is exec_failed
// naming the holder, nothing changed; released during the wait, the
// operation goes on. Not parallel: it bounds the wait's wall-clock time.
func TestPkgLockHolder(t *testing.T) {
	f := modelFixture(t, &pkgModel{}, nil)
	f.opts.PkgLockRetry = 50 * time.Millisecond
	p := f.pkgPreview("priv_pkg_install", hello)
	holder, release := f.holdDpkgLock()
	r := f.serve("priv_pkg_install_preview", hello)
	want := fmt.Sprintf("apt-get (pid %d)", holder)
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, want) {
		t.Fatalf("preview: %+v, want the holder %s", r.Error, want)
	}
	start := time.Now()
	r = f.serve("priv_pkg_install", bound(hello, p))
	took := time.Since(start)
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, want) || !strings.Contains(r.Error.Message, "nothing was changed") {
		t.Fatalf("install: %+v", r.Error)
	}
	// The fixture's timeout is 5 s: the wait is about 2.5 s.
	if took < 2*time.Second || took > 4*time.Second {
		t.Fatalf("waited %v", took)
	}
	if len(f.realRuns()) != 0 || len(f.dpkgState()) != 0 {
		t.Fatal("something ran or changed while the lock was held")
	}
	go func() { time.Sleep(500 * time.Millisecond); release() }()
	var res pkgResult
	f.ok("priv_pkg_install", bound(hello, p), &res)
	if res.LockWaitMS < 300 {
		t.Fatalf("lock_wait_ms %d", res.LockWaitMS)
	}
}

// holdDpkgLock starts a process (the stand-in, so its name is apt-get)
// that holds the dpkg frontend lock until release; it returns its pid.
func (f *fixture) holdDpkgLock() (pid int, release func()) {
	f.t.Helper()
	c := exec.CommandContext(f.t.Context(), f.aptGet) //nolint:gosec // G204: the test's own stand-in
	c.Env = []string{"FAKEAPT_HOLD_LOCK=" + filepath.Join(f.dpkg, "lock-frontend")}
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		f.t.Fatal(err)
	}
	done := false
	release = func() {
		if !done {
			done = true
			_ = in.Close()
			_ = c.Wait()
		}
	}
	f.t.Cleanup(release)
	b := make([]byte, 7)
	if _, err := out.Read(b); err != nil || string(b[:6]) != "locked" {
		f.t.Fatalf("lock holder: %q %v", b, err)
	}
	return c.Process.Pid, release
}

// TestPkgReapFailureIsOutcomeUnknown (fail closed, as for a command): when
// the helper cannot confirm that every process apt-get started has ended,
// the result is outcome_unknown, never the transaction's success, and the
// journal line has what was applied and why.
func TestPkgReapFailureIsOutcomeUnknown(t *testing.T) {
	t.Parallel()
	f := modelFixture(t, &pkgModel{}, nil)
	p := f.pkgPreview("priv_pkg_install", hello)
	f.opts.ReapOrphans = true
	calls := 0
	f.opts.ReapHooks = &ops.ReapHooks{
		// The two simulations reap cleanly; the run's reaping fails.
		Children: func() ([]int, error) {
			calls++
			if calls == 3 {
				return nil, errors.New("injected: children unreadable")
			}
			return []int{}, nil
		},
		Wait: func() (int, error) { return 0, unix.ECHILD },
	}
	f.fail("priv_pkg_install", bound(hello, p), "outcome_unknown")
	l := f.lastAudit()
	if !strings.Contains(l, `"outcome":"outcome_unknown"`) || !strings.Contains(l, "injected: children unreadable") || !strings.Contains(l, `"applied":`) {
		t.Fatalf("audit %q", l)
	}
}
