//go:build linux

package pkg_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
)

// The argv is fixed per operation (PRIVILEGED §5.2, §6): no free-form apt
// argument ever, package names only after "--", --no-install-recommends
// for install and upgrade, never a purge, the old configuration file kept.
func TestArgs(t *testing.T) {
	common := []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Use-Pty=0", "-o", "APT::Get::AutomaticRemove=false"}
	for name, c := range map[string]struct {
		op    pkg.Op
		sim   bool
		names []string
		want  []string
	}{
		"update":          {pkg.OpUpdate, false, nil, []string{"-q", "update"}},
		"install":         {pkg.OpInstall, false, []string{"htop", "jq"}, append(append(slices.Clone(common), "--no-install-recommends", "install", "--"), "htop", "jq")},
		"install preview": {pkg.OpInstall, true, []string{"htop"}, append(append(slices.Clone(common), "--no-install-recommends", "-s", "install", "--"), "htop")},
		"upgrade":         {pkg.OpUpgrade, false, nil, append(slices.Clone(common), "--no-install-recommends", "upgrade")},
		"upgrade preview": {pkg.OpUpgrade, true, nil, append(slices.Clone(common), "--no-install-recommends", "-s", "upgrade")},
		"remove":          {pkg.OpRemove, false, []string{"htop"}, append(append(slices.Clone(common), "-o", "APT::Get::Purge=false", "remove", "--"), "htop")},
		"remove preview":  {pkg.OpRemove, true, []string{"htop"}, append(append(slices.Clone(common), "-o", "APT::Get::Purge=false", "-s", "remove", "--"), "htop")},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := pkg.Args(c.op, c.sim, c.names)
			if err != nil || !slices.Equal(got, c.want) {
				t.Fatalf("Args = %q, %v\nwant %q", got, err, c.want)
			}
		})
	}
	for name, c := range map[string]struct {
		op    pkg.Op
		sim   bool
		names []string
	}{
		"install without names":  {pkg.OpInstall, false, nil},
		"remove without names":   {pkg.OpRemove, false, nil},
		"update with names":      {pkg.OpUpdate, false, []string{"htop"}},
		"upgrade with names":     {pkg.OpUpgrade, false, []string{"htop"}},
		"update simulated":       {pkg.OpUpdate, true, nil},
		"option as a name":       {pkg.OpInstall, false, []string{"-oAPT::x=y"}},
		"version pin":            {pkg.OpInstall, false, []string{"htop=1.0"}},
		"release pin":            {pkg.OpInstall, false, []string{"htop/stable"}},
		"architecture qualifier": {pkg.OpInstall, false, []string{"htop:i386"}},
		"unknown op":             {pkg.Op("dist-upgrade"), false, nil},
		"too many names":         {pkg.OpInstall, false, strings.Fields(strings.Repeat("htop ", pkg.MaxNames+1))},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := pkg.Args(c.op, c.sim, c.names); err == nil {
				t.Fatalf("Args accepted: %q", got)
			}
		})
	}
}

// Debian Policy §5.6.1: lower-case letters, digits, "+", "-" and ".", at
// least two characters, starting with an alphanumeric.
func TestValidName(t *testing.T) {
	for _, n := range []string{"htop", "g++", "libfoo2.0", "0ad", "a1", "python3-apt", strings.Repeat("a", 128)} {
		if !pkg.ValidName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{"", "a", "-rf", "+x", ".x", "Htop", "htop jq", "htop\n", "htop=1", "htop/x", "htop:any", "a;b", "a_b", strings.Repeat("a", 129)} {
		if pkg.ValidName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

// The simulated transaction (apt-get -s, pkgSimulate in apt 3.0.3 and
// 3.1.16): "Inst name [current] (candidate release)" installs or upgrades,
// "Remv name [current]" and "Purg name [current]" remove; "Conf" lines and
// everything else are not changes.
func TestParseSimulation(t *testing.T) {
	out := `Reading package lists...
NOTE: This is only a simulation!
Inst example-lib (2.1-1 Invented:1.0/stable [all])
Inst example-hello [1.0] (1.1 Invented:1.0/stable [all]) []
Inst example-arch:i386 (3.0-2 Invented:1.0/stable [i386])
Inst example-dep [2:1.0~rc1+dfsg-3] (2:1.0-1 Invented:1.0/stable [amd64]) [example-x on example-y]
Remv example-old [0.9-1]
Purg example-gone [0.1]
Conf example-lib (2.1-1 Invented:1.0/stable [all])
Inst broken line without version
Remv
`
	s := pkg.ParseSimulation([]byte(out))
	wantInstall := []pkg.Version{{Name: "example-lib", Version: "2.1-1"}, {Name: "example-arch:i386", Version: "3.0-2"}}
	wantUpgrade := []pkg.Upgrade{{Name: "example-hello", From: "1.0", To: "1.1"}, {Name: "example-dep", From: "2:1.0~rc1+dfsg-3", To: "2:1.0-1"}}
	wantRemove := []pkg.Removal{{Name: "example-old", Version: "0.9-1"}, {Name: "example-gone", Version: "0.1", Purge: true}}
	if !slices.Equal(s.Install, wantInstall) || !slices.Equal(s.Upgrade, wantUpgrade) || !slices.Equal(s.Remove, wantRemove) {
		t.Fatalf("parsed %+v", s)
	}
	if s.Unparsed != 2 {
		t.Errorf("unparsed %d, want 2 (the malformed Inst and Remv lines)", s.Unparsed)
	}
	if e := pkg.ParseSimulation(nil); len(e.Install)+len(e.Upgrade)+len(e.Remove)+e.Unparsed != 0 {
		t.Errorf("empty output parsed as %+v", e)
	}
	// Bounded: at most MaxChanges entries are kept; the rest are counted.
	var b strings.Builder
	for range pkg.MaxChanges + 5 {
		b.WriteString("Remv example-x [1]\n")
	}
	if big := pkg.ParseSimulation([]byte(b.String())); len(big.Remove) != pkg.MaxChanges || big.Unparsed != 5 {
		t.Errorf("unbounded: %d entries, %d unparsed", len(big.Remove), big.Unparsed)
	}
}

func TestLockHeld(t *testing.T) {
	for _, s := range []string{
		"E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (apt-get)\n",
		"E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?\n",
		"E: Unable to lock directory /var/lib/apt/lists/\n",
		"E: Unable to lock the administration directory (/var/lib/dpkg/), is another process using it?\n",
	} {
		if !pkg.LockHeld([]byte(s)) {
			t.Errorf("%q not recognised as a held lock", s)
		}
	}
	for _, s := range []string{"", "E: Unable to locate package example-missing\n", "W: lock files are fine\n"} {
		if pkg.LockHeld([]byte(s)) {
			t.Errorf("%q taken for a held lock", s)
		}
	}
}

// fake builds the apt-get stand-in in a secure directory and returns its
// path and log.
func fake(t *testing.T, mode string) (bin, log string) {
	t.Helper()
	d := gatetest.SecureDir(t)
	log = filepath.Join(d, "apt.log")
	bin = gatetest.Build(t, "internal/privd/pkg/testdata/fakeapt", d, "apt-get", nil, "-ldflags", "-X main.logPath="+log)
	gatetest.WriteFile(t, log+".mode", mode, 0o600)
	return bin, log
}

type call struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

func calls(t *testing.T, log string) []call {
	t.Helper()
	f, err := os.Open(log) //nolint:gosec // G304: test log
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []call
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c call
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// Run passes exactly the fixed environment (with DEBIAN_FRONTEND
// =noninteractive) and argv.
func TestRunEnvironment(t *testing.T) {
	bin, log := fake(t, "ok")
	r := pkg.Runner{AptGet: bin, Env: pkg.Env("/root"), MaxOutput: 4096, LockWait: time.Second, Retry: 10 * time.Millisecond}
	res, err := r.Run(context.Background(), 10*time.Second, []string{"-q", "update"})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 || res.Attempts != 1 {
		t.Fatalf("run %+v %v", res, err)
	}
	c := calls(t, log)
	if len(c) != 1 || !slices.Equal(c[0].Args, []string{"-q", "update"}) {
		t.Fatalf("calls %+v", c)
	}
	if !slices.Contains(c[0].Env, "DEBIAN_FRONTEND=noninteractive") || !slices.Contains(c[0].Env, "LC_ALL=C.UTF-8") || !slices.Contains(c[0].Env, "HOME=/root") {
		t.Errorf("environment %q", c[0].Env)
	}
	for _, e := range c[0].Env {
		k, _, _ := strings.Cut(e, "=")
		if !slices.Contains([]string{"PATH", "LANG", "LC_ALL", "HOME", "PAGER", "SYSTEMD_PAGER", "SYSTEMD_COLORS", "GIT_TERMINAL_PROMPT", "NO_COLOR", "TERM", "DEBIAN_FRONTEND"}, k) {
			t.Errorf("unexpected variable %s", e)
		}
	}
}

// A held dpkg or lists lock is waited for — bounded — and retried; apt-get
// refuses before changing anything when it cannot lock, so retrying is safe.
func TestRunLockWait(t *testing.T) {
	bin, log := fake(t, "lock 2")
	r := pkg.Runner{AptGet: bin, Env: pkg.Env("/root"), MaxOutput: 4096, LockWait: 5 * time.Second, Retry: 20 * time.Millisecond}
	res, err := r.Run(context.Background(), 10*time.Second, []string{"-q", "update"})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 || res.Attempts != 3 || len(calls(t, log)) != 3 || res.LockWait <= 0 {
		t.Fatalf("run %+v %v, %d calls", res, err, len(calls(t, log)))
	}
	for _, mode := range []string{"lockforever", "listslock"} {
		bin, log := fake(t, mode)
		r := pkg.Runner{AptGet: bin, Env: pkg.Env("/root"), MaxOutput: 4096, LockWait: 300 * time.Millisecond, Retry: 50 * time.Millisecond}
		start := time.Now()
		res, err := r.Run(context.Background(), 10*time.Second, []string{"-q", "update"})
		if !errors.Is(err, pkg.ErrLockHeld) || res.Attempts < 2 {
			t.Fatalf("%s: %+v %v", mode, res, err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("%s: waited %v past a 300ms lock wait", mode, d)
		}
		if n := len(calls(t, log)); n != res.Attempts {
			t.Fatalf("%s: %d calls, %d attempts", mode, n, res.Attempts)
		}
	}
	// Another failure is not a lock: no retry.
	bin, log = fake(t, "fail")
	r.AptGet = bin
	res, err = r.Run(context.Background(), 10*time.Second, []string{"-q", "update"})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 100 || len(calls(t, log)) != 1 {
		t.Fatalf("fail: %+v %v", res, err)
	}
}
