//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The recovery of an unfinished dpkg database (handoff N-14, S7-4;
// PRIVILEGED §6, "Recovering an unfinished database"): priv_pkg_recover_preview
// reports the unfinished packages from dpkg's status with its journal
// folded in, and binds them by hash; priv_pkg_recover re-reads them under
// the package operation record and the lock rule, refuses any change,
// runs dpkg --force-confold --configure --pending with the package
// environment, answers early at a hang-up or the deadline, never sends
// SIGINT, kills only at max_timeout_s, and decides its result from dpkg's
// state alone. The dpkg stand-in is fakeapt's "dpkg" mode; packages are
// invented.

// dpkgModel is the dpkg stand-in's model (fakeapt's dpkgDef).
type dpkgModel struct {
	DpkgDir    string   `json:"dpkg_dir"`
	Fail       []string `json:"fail,omitempty"`
	Noop       bool     `json:"noop,omitempty"`
	Bump       string   `json:"bump,omitempty"`
	SlowMS     int      `json:"slow_ms,omitempty"`
	HalfFirst  bool     `json:"half_first,omitempty"`
	IgnoreTerm bool     `json:"ignore_term,omitempty"`
	Signals    string   `json:"signals,omitempty"`
	Child      string   `json:"child,omitempty"`
	LockRuns   int      `json:"lock_runs,omitempty"`
}

// withFakeDpkg builds the dpkg stand-in as the dpkg the policy checks and
// the recovery runs.
func withFakeDpkg() opt {
	return func(f *fixture, _ *string) {
		dir := filepath.Join(f.d, "dpkgbin")
		gatetest.Mkdir(f.t, dir, 0o755)
		f.dpkgLog = filepath.Join(f.d, "dpkg.log")
		f.dpkgBin = gatetest.Build(f.t, "internal/privd/pkg/testdata/fakeapt", dir, "dpkg", nil, "-ldflags", "-X main.logPath="+f.dpkgLog)
		gatetest.WriteFile(f.t, f.dpkgLog+".mode", "dpkg", 0o600)
		f.setDpkg(&dpkgModel{})
	}
}

func allowRecover() opt {
	return replace("  allow_update_index: true\n", "  allow_update_index: true\n  allow_recover: true\n")
}

func (f *fixture) setDpkg(mod *dpkgModel) {
	f.t.Helper()
	m := *mod
	m.DpkgDir = f.dpkg
	b, _ := json.Marshal(&m)
	gatetest.WriteFile(f.t, f.dpkgLog+".model.json", string(b), 0o600)
}

// dpkgRuns are the dpkg stand-in's runs.
func (f *fixture) dpkgRuns() []aptCall {
	f.t.Helper()
	b, err := os.ReadFile(f.dpkgLog)
	if err != nil {
		return nil
	}
	var out []aptCall
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var c aptCall
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// pkgStanza is a dpkg status entry: "install ok unpacked" and so on.
func pkgStanza(name, status, version, extra string) string {
	s := fmt.Sprintf("Package: %s\nStatus: %s\nArchitecture: all\nVersion: %s\n", name, status, version)
	if extra != "" {
		s += extra + "\n"
	}
	return s + "\n"
}

const dpkgSelf = "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.22.22\n\n"

// setState writes dpkg's status (dpkg itself and stanzas) and its journal.
func (f *fixture) setState(stanzas string, journal map[string]string) {
	f.t.Helper()
	gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "status"), dpkgSelf+stanzas, 0o644)
	ents, _ := os.ReadDir(filepath.Join(f.dpkg, "updates"))
	for _, e := range ents {
		_ = os.Remove(filepath.Join(f.dpkg, "updates", e.Name()))
	}
	for n, c := range journal {
		gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "updates", n), c, 0o644)
	}
}

// recoverFixture is the broad unit's helper with packages and the
// recovery allowed, and the dpkg stand-in.
func recoverFixture(t *testing.T, opts ...opt) *fixture {
	t.Helper()
	f := newFixture(t, append([]opt{broadUsers(), allowRecover(), withFakeApt("ok"), withFakeDpkg(), asBroad()}, opts...)...)
	f.opts.PkgLockRetry = 50 * time.Millisecond
	return f
}

type recoverEntry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	State          string   `json:"state"`
	Flag           string   `json:"flag"`
	MissingDepends []string `json:"missing_depends"`
}

type recoverPreview struct {
	Op             string         `json:"op"`
	Unfinished     []recoverEntry `json:"unfinished"`
	NeedsReinstall []recoverEntry `json:"needs_reinstall"`
	JournalEntries int            `json:"journal_entries"`
	Argv           []string       `json:"argv"`
	PolicySHA256   string         `json:"policy_sha256"`
	PreviewSHA256  string         `json:"preview_sha256"`
}

type recoverConfigured struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	FromState string `json:"from_state"`
}

type recoverResult struct {
	Op         string              `json:"op"`
	Ran        bool                `json:"ran"`
	Configured []recoverConfigured `json:"configured"`
	ExitCode   *int                `json:"exit_code"`
	Stdout     string              `json:"stdout"`
	Attempts   int                 `json:"attempts"`
}

func (f *fixture) recoverPreview() recoverPreview {
	f.t.Helper()
	var p recoverPreview
	f.ok("priv_pkg_recover_preview", m{}, &p)
	return p
}

func names(l []recoverEntry) []string {
	out := []string{}
	for _, e := range l {
		out = append(out, e.Name)
	}
	return out
}

var recoverArgv = []string{"--force-confold", "--configure", "--pending"}

// interrupted is an install interrupted twice: example-a unpacked, and
// example-b unpacked in the status file but half-configured in dpkg's
// journal (what a SIGTERM to dpkg mid-configure leaves, measured).
func (f *fixture) interrupted() {
	f.setState(pkgStanza("example-a", "install ok unpacked", "1.0", "")+pkgStanza("example-b", "install ok unpacked", "1.0", ""),
		map[string]string{"0000": pkgStanza("example-b", "install ok half-configured", "1.0", "")})
}

// TestPkgRecoverPreview: the preview reports every unfinished package
// from dpkg's status with the journal folded in, the ones that need a
// reinstall apart, the missing dependencies, the journal's entries, the
// fixed argv and a stable hash; it runs nothing.
func TestPkgRecoverPreview(t *testing.T) {
	t.Parallel()
	f := recoverFixture(t)
	f.setState(pkgStanza("example-a", "install ok unpacked", "1.0", "")+
		pkgStanza("example-b", "install ok unpacked", "1.0", "")+
		pkgStanza("example-c", "install reinstreq half-installed", "1.0", "")+
		pkgStanza("example-d", "install ok unpacked", "1.0", "Depends: example-missing (>= 1.0)"),
		map[string]string{"0000": pkgStanza("example-b", "install ok half-configured", "1.0", "")})
	p := f.recoverPreview()
	if p.Op != "recover" || !slices.Equal(names(p.Unfinished), []string{"example-a", "example-b", "example-d"}) ||
		!slices.Equal(names(p.NeedsReinstall), []string{"example-c"}) || p.JournalEntries != 1 || !slices.Equal(p.Argv, recoverArgv) {
		t.Fatalf("preview %+v", p)
	}
	if b := p.Unfinished[1]; b.State != "half-configured" || b.Flag != "ok" || b.Version != "1.0" {
		t.Fatalf("the journal was not folded in: %+v", b)
	}
	if d := p.Unfinished[2]; !slices.Equal(d.MissingDepends, []string{"example-missing"}) || len(p.Unfinished[0].MissingDepends) != 0 {
		t.Fatalf("missing dependencies %+v", p.Unfinished)
	}
	if p.PolicySHA256 != f.opts.ExpectedSHA256 || len(p.PreviewSHA256) != 64 || strings.Trim(p.PreviewSHA256, "0123456789abcdef") != "" {
		t.Fatalf("hashes %q %q", p.PolicySHA256, p.PreviewSHA256)
	}
	if again := f.recoverPreview(); again.PreviewSHA256 != p.PreviewSHA256 {
		t.Fatal("the same state hashes differently")
	}
	gatetest.WriteFile(t, filepath.Join(f.dpkg, "updates", "0001"), pkgStanza("example-a", "install ok half-configured", "1.0", ""), 0o644)
	if moved := f.recoverPreview(); moved.PreviewSHA256 == p.PreviewSHA256 {
		t.Fatal("a new journal entry left the hash unchanged")
	}
	if len(f.dpkgRuns()) != 0 {
		t.Fatalf("a preview ran dpkg: %v", f.dpkgRuns())
	}
	l := f.lastAudit()
	if !strings.Contains(l, `"op":"priv_pkg_recover_preview"`) || !strings.Contains(l, `"outcome":"ok"`) || strings.Contains(l, p.PreviewSHA256) {
		t.Fatalf("audit %q", l)
	}
}

// TestPkgRecoverPreviewNothing: with nothing unfinished the preview says
// so (empty lists, a valid hash), and it is the hash of that state.
func TestPkgRecoverPreviewNothing(t *testing.T) {
	t.Parallel()
	f := recoverFixture(t)
	f.setState(pkgStanza("example-a", "install ok installed", "1.0", ""), nil)
	p := f.recoverPreview()
	if len(p.Unfinished)+len(p.NeedsReinstall)+p.JournalEntries != 0 || p.Unfinished == nil || p.NeedsReinstall == nil || len(p.PreviewSHA256) != 64 {
		t.Fatalf("preview %+v", p)
	}
}

// TestPkgRecoverPreviewRefusals: refused, with no approval to request,
// when only packages that need a reinstall are unfinished (configuring
// leaves them as they are), without packages.allow_recover, in the core
// unit, while a package operation is in progress, and while another
// process holds the dpkg lock.
func TestPkgRecoverPreviewRefusals(t *testing.T) {
	t.Parallel()
	f := recoverFixture(t)
	f.setState(pkgStanza("example-c", "install reinstreq half-installed", "1.0", "")+pkgStanza("example-e", "install ok half-installed", "1.0", ""), nil)
	r := f.serve("priv_pkg_recover_preview", m{})
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "reinstall") || !strings.Contains(r.Error.Message, "example-c") ||
		!strings.Contains(r.Error.Message, "example-e") || strings.Contains(r.Error.Message, "finishes") {
		t.Fatalf("only reinstall: %+v", r.Error)
	}
	off := newFixture(t, broadUsers(), withFakeDpkg(), asBroad())
	off.fail("priv_pkg_recover_preview", m{}, "policy_denied")
	off.fail("priv_pkg_recover", m{"expected_preview_sha256": strings.Repeat("a", 64)}, "policy_denied")
	core := newFixture(t, broadUsers(), allowRecover(), withFakeDpkg())
	core.fail("priv_pkg_recover_preview", m{}, "helper_wrong_unit")
	core.fail("priv_pkg_recover", m{"expected_preview_sha256": strings.Repeat("a", 64)}, "helper_wrong_unit")
	busy := recoverFixture(t)
	busy.interrupted()
	release := busy.holdRecord(`{"request_id":"0b5c0000-0000-4000-8000-0000000000aa","started":"2026-09-29T12:00:00Z","until":"2026-09-29T12:15:00Z"}`)
	r = busy.serve("priv_pkg_recover_preview", m{})
	release()
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "package operation in progress") {
		t.Fatalf("in progress: %+v", r.Error)
	}
	_, unlock := busy.holdDpkgLock()
	r = busy.serve("priv_pkg_recover_preview", m{})
	unlock()
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "locked by") {
		t.Fatalf("lock held: %+v", r.Error)
	}
}

// TestPkgRecoverBound: an interrupted install recovered once: the
// operation re-reads the state, finds the previewed hash, runs exactly
// dpkg --force-confold --configure --pending with the package environment,
// and answers from dpkg's state: both packages configured, nothing left in
// the journal. Its journal line names what it configured. The same hash
// again is refused: the state it bound has changed.
func TestPkgRecoverBound(t *testing.T) {
	t.Parallel()
	f := recoverFixture(t)
	f.interrupted()
	p := f.recoverPreview()
	var r recoverResult
	f.ok("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256}, &r)
	if r.Op != "recover" || !r.Ran || r.ExitCode == nil || *r.ExitCode != 0 || r.Attempts != 1 ||
		!slices.Equal(r.Configured, []recoverConfigured{{Name: "example-a", Version: "1.0", FromState: "unpacked"}, {Name: "example-b", Version: "1.0", FromState: "half-configured"}}) {
		t.Fatalf("result %+v", r)
	}
	runs := f.dpkgRuns()
	if len(runs) != 1 || !slices.Equal(runs[0].Args, recoverArgv) || !slices.Contains(runs[0].Env, "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("dpkg runs %+v", runs)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-a 1.0 installed", "example-b 1.0 installed"}) {
		t.Fatalf("dpkg %v", got)
	}
	if ents, _ := os.ReadDir(filepath.Join(f.dpkg, "updates")); len(ents) != 0 {
		t.Fatalf("journal left %v", ents)
	}
	l := f.lastAudit()
	if !strings.HasPrefix(l, "<4>") || !strings.Contains(l, `"op":"priv_pkg_recover"`) || !strings.Contains(l, `"outcome":"ok"`) ||
		!strings.Contains(l, `"configured":["example-a","example-b"]`) || strings.Contains(l, p.PreviewSHA256) {
		t.Fatalf("audit %q", l)
	}
	r2 := f.serve("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256})
	if r2.OK || r2.Error.Code != "exists" || len(f.dpkgRuns()) != 1 {
		t.Fatalf("the same hash again: %+v (dpkg runs %d)", r2.Error, len(f.dpkgRuns()))
	}
}

// TestPkgRecoverStateChanged: a change to the unfinished packages or the
// journal between the preview and the run is refused, and nothing runs.
func TestPkgRecoverStateChanged(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(f *fixture){
		"configured elsewhere": func(f *fixture) {
			f.setState(pkgStanza("example-a", "install ok installed", "1.0", "")+pkgStanza("example-b", "install ok unpacked", "1.0", ""),
				map[string]string{"0000": pkgStanza("example-b", "install ok half-configured", "1.0", "")})
		},
		"another unfinished": func(f *fixture) {
			gatetest.WriteFile(f.t, filepath.Join(f.dpkg, "updates", "0001"), pkgStanza("example-z", "install ok unpacked", "2.0", ""), 0o644)
		},
		"journal folded": func(f *fixture) {
			f.setState(pkgStanza("example-a", "install ok unpacked", "1.0", "")+pkgStanza("example-b", "install ok half-configured", "1.0", ""), nil)
		},
		"new version": func(f *fixture) {
			f.setState(pkgStanza("example-a", "install ok unpacked", "1.1", "")+pkgStanza("example-b", "install ok unpacked", "1.0", ""),
				map[string]string{"0000": pkgStanza("example-b", "install ok half-configured", "1.0", "")})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := recoverFixture(t)
			f.interrupted()
			p := f.recoverPreview()
			change(f)
			r := f.serve("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256})
			if r.OK || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, "nothing was run") || len(f.dpkgRuns()) != 0 {
				t.Fatalf("got %+v, dpkg runs %d", r.Error, len(f.dpkgRuns()))
			}
		})
	}
}

// TestPkgRecoverNothingUnfinished: bound to a preview that found nothing,
// the operation answers that it ran nothing; a missing or malformed hash is
// bad_request.
func TestPkgRecoverNothingUnfinished(t *testing.T) {
	t.Parallel()
	f := recoverFixture(t)
	f.setState(pkgStanza("example-a", "install ok installed", "1.0", ""), nil)
	p := f.recoverPreview()
	var r recoverResult
	f.ok("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256}, &r)
	if r.Ran || len(r.Configured) != 0 || r.Configured == nil || len(f.dpkgRuns()) != 0 {
		t.Fatalf("result %+v, dpkg runs %d", r, len(f.dpkgRuns()))
	}
	f.fail("priv_pkg_recover", m{}, "bad_request")
	f.fail("priv_pkg_recover", m{"expected_preview_sha256": "ABC"}, "bad_request")
	f.fail("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256, "packages": []string{"example-a"}}, "bad_request")
}

// TestPkgRecoverResults: the result is decided by dpkg's state, never its
// exit code: a package left unfinished, one that needs a reinstall, one
// whose dependency is missing, or any other change is verify_failed,
// naming what was configured and what still needs what; nothing changed is
// exec_failed.
func TestPkgRecoverResults(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		state   string
		mod     dpkgModel
		code    string
		want    []string
		journal []string
	}{
		"partial": {mod: dpkgModel{Fail: []string{"example-b"}}, code: "verify_failed",
			want:    []string{"example-a", "example-b", "half-configured", "cannot be undone"},
			journal: []string{`"outcome":"verify_failed"`, `"configured":["example-a"]`, `"unfinished":["example-b"]`}},
		"noop": {mod: dpkgModel{Noop: true}, code: "exec_failed", want: []string{"dpkg changed nothing"}, journal: []string{`"outcome":"exec_failed"`}},
		"other change": {mod: dpkgModel{Bump: "example-e"}, code: "verify_failed", want: []string{"example-e", "9.9"},
			journal: []string{`"outcome":"verify_failed"`, `"applied":`}},
		"reinstall left": {state: pkgStanza("example-c", "install reinstreq half-installed", "1.0", ""), code: "verify_failed",
			want: []string{"example-c", "reinstall"}, journal: []string{`"unfinished":["example-c"]`}},
		"missing dependency": {state: pkgStanza("example-d", "install ok unpacked", "1.0", "Depends: example-missing"), mod: dpkgModel{Fail: []string{"example-d"}},
			code: "verify_failed", want: []string{"example-d", "example-missing"}, journal: []string{`"unfinished":["example-d"]`}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := recoverFixture(t)
			f.setState(pkgStanza("example-a", "install ok unpacked", "1.0", "")+pkgStanza("example-b", "install ok unpacked", "1.0", "")+
				pkgStanza("example-e", "install ok installed", "1.0", "")+c.state, nil)
			p := f.recoverPreview()
			f.setDpkg(&c.mod)
			r := f.serve("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256})
			if r.OK || r.Error.Code != c.code {
				t.Fatalf("got %+v, want %s", r.Error, c.code)
			}
			for _, w := range c.want {
				if !strings.Contains(r.Error.Message, w) {
					t.Errorf("message %q lacks %q", r.Error.Message, w)
				}
			}
			l := f.lastAudit()
			for _, w := range append(c.journal, `"op":"priv_pkg_recover"`) {
				if !strings.Contains(l, w) {
					t.Errorf("audit %q lacks %q", l, w)
				}
			}
		})
	}
}

// TestPkgRecoverLock: the lock rule: a dpkg lock another process holds is
// waited for and then refused naming its holder, nothing run; dpkg's own
// refusal of a lock taken after the wait is retried within the same bound.
func TestPkgRecoverLock(t *testing.T) {
	f := recoverFixture(t)
	f.interrupted()
	p := f.recoverPreview()
	holder, release := f.holdDpkgLock()
	r := f.serve("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256})
	release()
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, fmt.Sprintf("pid %d", holder)) || len(f.dpkgRuns()) != 0 {
		t.Fatalf("held lock: %+v, dpkg runs %d", r.Error, len(f.dpkgRuns()))
	}
	g := recoverFixture(t)
	g.interrupted()
	p = g.recoverPreview()
	g.setDpkg(&dpkgModel{LockRuns: 1})
	var res recoverResult
	g.ok("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256}, &res)
	if res.Attempts != 2 || len(res.Configured) != 2 {
		t.Fatalf("result after dpkg's lock refusal %+v", res)
	}
}

// TestPkgRecoverEarlyAnswerNoSigint: the stop points as for install,
// upgrade and remove, except SIGINT, which gives dpkg no graceful stop
// (it ignores SIGINT only while it waits for a maintainer script, and
// dies of it otherwise; dpkg 1.22.22's subproc.c and script.c): at the
// request's deadline (1 s) the helper answers outcome_unknown at once and
// lets dpkg go on, sends nothing at the stop point (3 s), and kills the
// process group only at max_timeout_s (4 s); the journal line has the
// result from dpkg's state.
func TestPkgRecoverEarlyAnswerNoSigint(t *testing.T) {
	f := recoverFixture(t, stagePolicy())
	f.interrupted()
	signals := filepath.Join(f.d, "dpkg-signals")
	child := filepath.Join(f.d, "child-signals")
	p := f.recoverPreview()
	f.setDpkg(&dpkgModel{SlowMS: 30000, HalfFirst: true, Signals: signals, Child: child})
	a := f.serveAsync(pkgLine("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256}, 1000))
	r, at := a.answer(3 * time.Second)
	wantEarly(t, &r)
	if !strings.Contains(r.Error.Message, "dpkg") || strings.Contains(r.Error.Message, "apt-get") {
		t.Fatalf("early answer %q", r.Error.Message)
	}
	if d := at.Sub(a.start); d < 900*time.Millisecond || d > 2*time.Second {
		t.Fatalf("answered after %v, want at the 1 s deadline", d)
	}
	pr := f.serve("priv_pkg_recover_preview", m{})
	if pr.OK || !strings.Contains(pr.Error.Message, "package operation in progress") || !strings.Contains(pr.Error.Message, reqID) {
		t.Fatalf("preview during the recovery: %+v", pr.Error)
	}
	took := a.ended(10 * time.Second)
	if took < 3900*time.Millisecond || took > 6*time.Second {
		t.Fatalf("Serve returned after %v, want just after the 4 s kill", took)
	}
	if s := signalsGot(t, signals); strings.Contains(s, "interrupt") || !strings.Contains(s, "terminated") {
		t.Fatalf("dpkg got %q, want SIGTERM at the kill and never SIGINT", s)
	}
	if s := signalsGot(t, child); strings.Contains(s, "interrupt") {
		t.Fatalf("dpkg's process group got %q", s)
	}
	l := f.lastAudit()
	for _, w := range []string{`"op":"priv_pkg_recover"`, `"stopped":"killed"`, `"answered_early":true`, `"outcome":"verify_failed"`, `"unfinished":["example-a","example-b"]`} {
		if !strings.Contains(l, w) {
			t.Fatalf("audit %q lacks %q", l, w)
		}
	}
}

// TestPkgRecoverHangupLetsFinish: a hang-up while dpkg runs sends no
// signal; dpkg finishes and the journal line has the result.
func TestPkgRecoverHangupLetsFinish(t *testing.T) {
	f := recoverFixture(t, stagePolicy())
	f.interrupted()
	signals := filepath.Join(f.d, "dpkg-signals")
	p := f.recoverPreview()
	f.setDpkg(&dpkgModel{SlowMS: 1500, Signals: signals})
	a := f.serveAsync(pkgLine("priv_pkg_recover", m{"expected_preview_sha256": p.PreviewSHA256}, 4000))
	time.Sleep(500 * time.Millisecond)
	_ = unix.Shutdown(a.gate, unix.SHUT_WR)
	r, _ := a.answer(2 * time.Second)
	wantEarly(t, &r)
	if took := a.ended(6 * time.Second); took < 1500*time.Millisecond {
		t.Fatalf("Serve returned after %v, before dpkg finished", took)
	}
	if s := signalsGot(t, signals); s != "" {
		t.Fatalf("dpkg got %q", s)
	}
	if got := f.dpkgState(); !slices.Equal(got, []string{"example-a 1.0 installed", "example-b 1.0 installed"}) {
		t.Fatalf("dpkg %v", got)
	}
	l := f.lastAudit()
	if !strings.Contains(l, `"hung_up":true`) || !strings.Contains(l, `"answered_early":true`) || !strings.Contains(l, `"outcome":"ok"`) {
		t.Fatalf("audit %q", l)
	}
}

// TestUnfinishedRefusalNamesRecovery: install, upgrade and remove previews
// and operations, and the power preview, refuse an unfinished database
// naming what each state needs: configuring (dpkg --configure -a, or the
// recovery), a reinstall (configuring does not fix it), or a missing
// dependency; and dpkg's journal.
func TestUnfinishedRefusalNamesRecovery(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		state   string
		journal map[string]string
		want    []string
		not     []string
	}{
		"unpacked":         {state: pkgStanza("example-a", "install ok unpacked", "1.0", ""), want: []string{"example-a", "to configure", "dpkg --configure -a"}},
		"half-configured":  {state: pkgStanza("example-a", "install ok half-configured", "1.0", ""), want: []string{"example-a", "to configure"}},
		"triggers-pending": {state: pkgStanza("example-a", "install ok triggers-pending", "1.0", ""), want: []string{"example-a", "to configure"}},
		"reinstreq": {state: pkgStanza("example-c", "install reinstreq half-installed", "1.0", ""),
			want: []string{"example-c", "to reinstall", "does not fix"}, not: []string{"to configure"}},
		"half-installed": {state: pkgStanza("example-c", "install ok half-installed", "1.0", ""),
			want: []string{"example-c", "to reinstall"}, not: []string{"to configure"}},
		"missing dependency": {state: pkgStanza("example-d", "install ok unpacked", "1.0", "Depends: example-missing"),
			want: []string{"example-d", "example-missing", "missing dependency"}, not: []string{"to configure"}},
		"journal": {state: pkgStanza("example-a", "install ok unpacked", "1.0", ""),
			journal: map[string]string{"0000": pkgStanza("example-a", "install ok installed", "1.0", "")}, want: []string{"journal"}, not: []string{"to configure", "example-a"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := modelFixture(t, &pkgModel{}, nil)
			f.setState(c.state, c.journal)
			for _, op := range []string{"priv_pkg_install_preview", "priv_pkg_remove_preview"} {
				r := f.serve(op, hello)
				if r.OK || r.Error.Code != "exec_failed" {
					t.Fatalf("%s: %+v", op, r.Error)
				}
				for _, w := range c.want {
					if !strings.Contains(r.Error.Message, w) {
						t.Errorf("%s: %q lacks %q", op, r.Error.Message, w)
					}
				}
				for _, w := range c.not {
					if strings.Contains(r.Error.Message, w) {
						t.Errorf("%s: %q names %q", op, r.Error.Message, w)
					}
				}
			}
		})
	}
	l := &logind{}
	pf := powerFixture(t, l)
	pf.setState(pkgStanza("example-c", "install reinstreq half-installed", "1.0", ""), nil)
	r := pf.serve("priv_power_preview", m{"action": "reboot"})
	if r.OK || r.Error.Code != "exec_failed" || !strings.Contains(r.Error.Message, "to reinstall") || !strings.Contains(r.Error.Message, "nothing was scheduled") {
		t.Fatalf("power preview: %+v", r.Error)
	}
}
