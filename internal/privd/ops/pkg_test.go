//go:build linux

package ops_test

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

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

type pkgResult struct {
	Op         string   `json:"op"`
	Packages   []string `json:"packages"`
	ExitCode   *int     `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	Truncated  bool     `json:"stdout_truncated"`
	Attempts   int      `json:"attempts"`
	LockWaitMS int64    `json:"lock_wait_ms"`
}

type preview struct {
	Op      string `json:"op"`
	Install []struct {
		Name, Version string
	} `json:"install"`
	Upgrade []struct {
		Name, From, To string
	} `json:"upgrade"`
	Remove []struct {
		Name, Version string
		Purge         bool
	} `json:"remove"`
	Complete bool `json:"complete"`
	ExitCode *int `json:"exit_code"`
}

// pkgFixture is the broad unit's helper with packages enabled and the
// apt-get stand-in.
func pkgFixture(t *testing.T, mode string, opts ...opt) *fixture {
	t.Helper()
	return newFixture(t, append([]opt{broadUsers(), withFakeApt(mode), asBroad()}, opts...)...)
}

func TestPkgInstall(t *testing.T) {
	f := pkgFixture(t, "ok")
	var r pkgResult
	f.ok("priv_pkg_install", m{"packages": []string{"example-hello"}}, &r)
	if r.Op != "install" || !slices.Equal(r.Packages, []string{"example-hello"}) || r.ExitCode == nil || *r.ExitCode != 0 || !strings.Contains(r.Stdout, "fake apt-get: done") {
		t.Fatalf("install %+v", r)
	}
	c := f.lastApt()
	want := []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Use-Pty=0", "-o", "APT::Get::AutomaticRemove=false",
		"--no-install-recommends", "install", "--", "example-hello"}
	if !slices.Equal(c.Args, want) {
		t.Fatalf("argv %q\nwant %q", c.Args, want)
	}
	if !slices.Contains(c.Env, "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("env %q", c.Env)
	}
	// Broad operations are audited at WARN (PRIVILEGED §8), with the
	// package names (allow-listed identifiers, not content).
	if l := f.lastAudit(); !strings.HasPrefix(l, "<4>") || !strings.Contains(l, `"op":"priv_pkg_install"`) || !strings.Contains(l, `"packages":["example-hello"]`) {
		t.Fatalf("audit %q", l)
	}
}

// Only names from packages.install (packages.remove for removal); names
// that are not Debian package names are bad_request; nothing runs.
func TestPkgAllowList(t *testing.T) {
	f := pkgFixture(t, "ok")
	for op, args := range map[string]m{
		"priv_pkg_install":         {"packages": []string{"example-other"}},
		"priv_pkg_install_preview": {"packages": []string{"example-hello", "example-other"}},
		"priv_pkg_remove":          {"packages": []string{"example-other"}},
		"priv_pkg_remove_preview":  {"packages": []string{"example-other"}},
	} {
		f.fail(op, args, "policy_denied")
	}
	for _, names := range [][]string{{}, {"-oAPT::Get::Purge=true"}, {"Example-hello"}, {"example-hello", "example-hello"}, {"example-hello=1.0"},
		strings.Fields(strings.Repeat("example-hello ", 21))} {
		f.fail("priv_pkg_install", m{"packages": names}, "bad_request")
	}
	f.fail("priv_pkg_install", m{"packages": []string{"example-hello"}, "options": []string{"-o", "x"}}, "bad_request")
	f.fail("priv_pkg_install", m{}, "bad_request")
	if n := len(f.aptCalls()); n != 0 {
		t.Fatalf("apt-get ran %d times for refused requests", n)
	}
}

func TestPkgRemoveNeverPurges(t *testing.T) {
	f := pkgFixture(t, "ok")
	f.ok("priv_pkg_remove", m{"packages": []string{"example-hello"}}, nil)
	c := f.lastApt()
	if !slices.Contains(c.Args, "APT::Get::Purge=false") || slices.Contains(c.Args, "--purge") || slices.Contains(c.Args, "purge") ||
		!slices.Equal(c.Args[len(c.Args)-3:], []string{"remove", "--", "example-hello"}) {
		t.Fatalf("argv %q", c.Args)
	}
}

// Upgrade (and its preview) only with allow_upgrade: true; the index
// update only with allow_update_index: true; nothing with packages
// disabled.
func TestPkgPolicySwitches(t *testing.T) {
	f := pkgFixture(t, "ok")
	f.fail("priv_pkg_upgrade", m{}, "policy_denied")
	f.fail("priv_pkg_upgrade_preview", m{}, "policy_denied")
	f.ok("priv_pkg_update_index", m{}, nil)
	if c := f.lastApt(); !slices.Equal(c.Args, []string{"-q", "update"}) {
		t.Fatalf("update argv %q", c.Args)
	}
	up := pkgFixture(t, "ok", replace("  allow_update_index: true\n", "  allow_upgrade: true\n"))
	up.ok("priv_pkg_upgrade", m{}, nil)
	if c := up.lastApt(); c.Args[len(c.Args)-1] != "upgrade" || !slices.Contains(c.Args, "--no-install-recommends") {
		t.Fatalf("upgrade argv %q", c.Args)
	}
	up.fail("priv_pkg_update_index", m{}, "policy_denied")
	off := pkgFixture(t, "ok", replace("  enabled: true\n", "  enabled: false\n"))
	for op, args := range map[string]m{
		"priv_pkg_update_index":    {},
		"priv_pkg_install":         {"packages": []string{"example-hello"}},
		"priv_pkg_install_preview": {"packages": []string{"example-hello"}},
		"priv_pkg_remove":          {"packages": []string{"example-hello"}},
	} {
		off.fail(op, args, "policy_denied")
	}
	if len(off.aptCalls()) != 0 {
		t.Fatal("apt-get ran with packages disabled")
	}
}

// The previews run the same transaction with apt-get -s and return what
// would be installed, upgraded and removed. They are read tier.
func TestPkgPreviews(t *testing.T) {
	f := pkgFixture(t, "sim", maxTier("read"))
	var p preview
	f.ok("priv_pkg_install_preview", m{"packages": []string{"example-hello"}}, &p)
	if p.Op != "install" || len(p.Install) != 2 || p.Install[0].Name != "example-lib" || p.Install[0].Version != "2.1-1" ||
		len(p.Upgrade) != 1 || p.Upgrade[0].From != "1.0" || p.Upgrade[0].To != "1.1" ||
		len(p.Remove) != 2 || !p.Remove[1].Purge || p.Complete || p.ExitCode == nil || *p.ExitCode != 0 {
		t.Fatalf("preview %+v", p)
	}
	c := f.lastApt()
	if !slices.Contains(c.Args, "-s") || !slices.Equal(c.Args[len(c.Args)-3:], []string{"install", "--", "example-hello"}) {
		t.Fatalf("preview argv %q", c.Args)
	}
	f.ok("priv_pkg_remove_preview", m{"packages": []string{"example-hello"}}, &p)
	if c := f.lastApt(); !slices.Contains(c.Args, "-s") || !slices.Contains(c.Args, "remove") {
		t.Fatalf("remove preview argv %q", c.Args)
	}
	// At max_tier read, the operations themselves are refused.
	for _, op := range []string{"priv_pkg_install", "priv_pkg_remove", "priv_pkg_update_index"} {
		f.fail(op, m{"packages": []string{"example-hello"}}, "tier_denied")
	}
	up := pkgFixture(t, "sim", replace("  allow_update_index: true\n", "  allow_upgrade: true\n"))
	up.ok("priv_pkg_upgrade_preview", m{}, &p)
	if c := up.lastApt(); !slices.Equal(c.Args[len(c.Args)-2:], []string{"-s", "upgrade"}) {
		t.Fatalf("upgrade preview argv %q", c.Args)
	}
}

// A held lock is waited for, bounded, then reported clearly; nothing else
// is retried.
func TestPkgLock(t *testing.T) {
	f := pkgFixture(t, "lock 1")
	f.opts.PkgLockRetry = 20 * time.Millisecond
	var r pkgResult
	f.ok("priv_pkg_install", m{"packages": []string{"example-hello"}}, &r)
	if r.Attempts != 2 || r.LockWaitMS <= 0 || *r.ExitCode != 0 {
		t.Fatalf("after one held lock: %+v", r)
	}
	held := pkgFixture(t, "lockforever")
	held.opts.PkgLockRetry = 50 * time.Millisecond
	start := time.Now()
	resp := held.serve("priv_pkg_install", m{"packages": []string{"example-hello"}})
	if resp.OK || resp.Error == nil || resp.Error.Code != "exec_failed" || !strings.Contains(resp.Error.Message, "lock") {
		t.Fatalf("held lock: %+v", resp.Error)
	}
	// The fixture's request timeout is 5 s: the wait is at most half of it.
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("waited %v for the lock", d)
	}
}

// Output is capped and redacted; a failed transaction is data (exit code
// and stderr), not a helper error.
func TestPkgOutput(t *testing.T) {
	f := pkgFixture(t, "secret")
	var r pkgResult
	f.ok("priv_pkg_install", m{"packages": []string{"example-hello"}}, &r)
	if strings.Contains(r.Stdout, "aW52ZW50ZWQ") || !strings.Contains(r.Stdout, "REDACTED") {
		t.Fatalf("private key not redacted: %q", r.Stdout)
	}
	fl := pkgFixture(t, "flood")
	fl.ok("priv_pkg_install", m{"packages": []string{"example-hello"}}, &r)
	if len(r.Stdout) > 4096 || !r.Truncated {
		t.Fatalf("output %d bytes, truncated %v (max_output_bytes 4096)", len(r.Stdout), r.Truncated)
	}
	fa := pkgFixture(t, "fail")
	fa.ok("priv_pkg_install", m{"packages": []string{"example-hello"}}, &r)
	if r.ExitCode == nil || *r.ExitCode != 100 || !strings.Contains(r.Stderr, "Unable to locate package") {
		t.Fatalf("failed install %+v", r)
	}
}
