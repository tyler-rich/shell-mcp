//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// testEnv is an invented host: a secure temp dir with a policy, a helper
// binary and fake user and group databases.
func testEnv(t *testing.T, y string) (env *loadEnv, policyPath string) {
	t.Helper()
	d := gatetest.SecureDir(t)
	exe := filepath.Join(d, "libexec", "shell-mcp-privd")
	gatetest.WriteFile(t, exe, "invented helper", 0o755)
	gatetest.Mkdir(t, filepath.Join(d, "srv", "app"), 0o755)
	gatetest.Mkdir(t, filepath.Join(d, "etc", "example-app"), 0o755)
	p := filepath.Join(d, "etc", "shell-mcp", "privileged.yaml")
	gatetest.WriteFile(t, p, strings.ReplaceAll(y, "{D}", d), 0o600)
	if err := os.Symlink("/run", filepath.Join(d, "var-run")); err != nil {
		t.Fatal(err)
	}
	env = &loadEnv{
		trust:         gatetest.Trust(),
		executable:    exe,
		systemBinDirs: []string{filepath.Join(d, "sysbin")},
		varRun:        filepath.Join(d, "var-run"),
		lookups: func(o *policy.LoadOptions) {
			o.LookupUser = func(n string) (uint32, error) {
				if n == "root" {
					return 0, nil
				}
				return 0, errors.New("unknown user")
			}
			o.LookupGroup = func(n string) (uint32, error) {
				if n == "svc-shell-priv" {
					return 60124, nil
				}
				if n == "root" {
					return 0, nil
				}
				return 0, errors.New("unknown group")
			}
			o.UserName = func(uint32) string { return "" }
		},
	}
	return env, p
}

const validPolicy = `version: 1
client_uid: 60123
socket_group: svc-shell-priv
max_tier: operator
sandbox:
  landlock: best-effort
paths:
  read: [{D}/srv/app]
  write: [{D}/etc/example-app]
  persistence:
    - path: /etc/systemd/system/example-app.service.d
      acknowledge: "drop-ins for example-app only"
owners:
  users: [root]
  groups: [root]
`

func TestVersionAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "shell-mcp-privd dev") {
		t.Fatalf("version: exit %d, %q", code, out.String())
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no args exit %d", code)
	}
	if code := run([]string{"exec"}, &out, &errb); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
}

func TestUnits(t *testing.T) {
	env, p := testEnv(t, validPolicy)
	out := t.TempDir()
	var so, se bytes.Buffer
	if code := unitsWith([]string{"--policy", p, "--out", out}, &so, &se, env); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	lo := &policy.LoadOptions{Trust: env.trust, HelperExecutable: env.executable, SystemBinDirs: env.systemBinDirs}
	env.lookups(lo)
	pol, err := policy.Load(p, lo)
	if err != nil {
		t.Fatal(err)
	}
	want, err := units.Core(pol)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{units.SocketUnit: want.Socket, units.ServiceUnit: want.Service} {
		b, err := os.ReadFile(filepath.Join(out, name)) //nolint:gosec // G304: test output
		if err != nil || string(b) != content {
			t.Fatalf("%s: %v\n%s", name, err, b)
		}
		if fi, _ := os.Stat(filepath.Join(out, name)); fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode %04o", name, fi.Mode().Perm())
		}
	}
	if !strings.Contains(so.String(), "systemd-analyze security") || !strings.Contains(so.String(), pol.SHA256) {
		t.Fatalf("output %q", so.String())
	}
	// Refusals write nothing.
	bad, _ := testEnv(t, "version: 1\nsudo: true\n")
	empty := t.TempDir()
	if code := unitsWith([]string{"--policy", p + ".missing", "--out", empty}, &so, &se, bad); code != 1 {
		t.Fatalf("missing policy exit %d", code)
	}
	if code := unitsWith([]string{"--out", empty}, &so, &se, env); code != 2 {
		t.Fatalf("no --policy exit %d", code)
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Fatalf("refused units wrote %v", ents)
	}
}

func TestCheckPolicy(t *testing.T) {
	env, p := testEnv(t, validPolicy)
	var so, se bytes.Buffer
	// go test binaries are built with cgo for -race; serve would refuse those.
	wantCode := 0
	if builtWithCGO() {
		wantCode = 1
	}
	if code := checkPolicyWith([]string{"--policy", p}, &so, &se, env); code != wantCode {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	for _, want := range []string{"policy sha256:", "client_uid: 60123", "socket_group: svc-shell-priv", "max_tier: operator",
		"persistence", "drop-ins for example-app only", "CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER", "landlock best-effort"} {
		if !strings.Contains(so.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, so.String())
		}
	}
	bad, bp := testEnv(t, "version: 1\nclient_uid: 0\nsocket_group: svc-shell-priv\nmax_tier: read\n")
	so.Reset()
	if code := checkPolicyWith([]string{"--policy", bp}, &so, &se, bad); code != 1 || !strings.Contains(so.String()+se.String(), "client_uid") {
		t.Fatalf("invalid policy exit %d: %s %s", code, so.String(), se.String())
	}
	// A policy readable by group or other is flagged (it should be 0600).
	if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // G302: the fixture under test
		t.Fatal(err)
	}
	so.Reset()
	if code := checkPolicyWith([]string{"--policy", p}, &so, &se, env); code != wantCode || !strings.Contains(so.String(), "0600") {
		t.Fatalf("readable policy not flagged: %s", so.String())
	}
}

// serve outside its unit (not root, stdin not a socket, or a cgo build)
// refuses: nothing on stdout, one WARN line on stderr, exit 1.
func TestServeRefusesOutsideItsUnit(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("needs a non-root test user")
	}
	_, p := testEnv(t, validPolicy)
	for _, args := range [][]string{{"serve", "--policy", p}, {"serve"}, {"serve", "--policy", p, "extra"}} {
		var so, se bytes.Buffer
		if code := run(args, &so, &se); code != 1 || so.Len() != 0 || !strings.HasPrefix(se.String(), "<4>") || !strings.Contains(se.String(), `"outcome":"refused"`) {
			t.Fatalf("%v: exit %d stdout %q stderr %q", args, code, so.String(), se.String())
		}
	}
}

// The core unit hides /run behind an empty tmpfs (TemporaryFileSystem=),
// which also hides /var/run only where /var/run is the usual symlink to
// /run. On a host where it is anything else, units and check-policy refuse
// rather than generate a unit that leaves /var/run's sockets reachable.
func TestVarRunMustBeRun(t *testing.T) {
	env, p := testEnv(t, validPolicy)
	var so, se bytes.Buffer
	if code := unitsWith([]string{"--policy", p, "--out", t.TempDir()}, &so, &se, env); code != 0 {
		t.Fatalf("control: exit %d: %s %s", code, so.String(), se.String())
	}
	for name, mk := range map[string]func(string) error{
		"a directory":         func(p string) error { return os.Mkdir(p, 0o755) },
		"a symlink elsewhere": func(p string) error { return os.Symlink("/tmp", p) },
		"missing":             func(string) error { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			env, p := testEnv(t, validPolicy)
			env.varRun = filepath.Join(t.TempDir(), "var-run")
			if err := mk(env.varRun); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			var so, se bytes.Buffer
			if code := unitsWith([]string{"--policy", p, "--out", out}, &so, &se, env); code != 1 || !strings.Contains(se.String(), "/var/run") {
				t.Fatalf("units: exit %d: %s %s", code, so.String(), se.String())
			}
			if ents, _ := os.ReadDir(out); len(ents) != 0 {
				t.Fatalf("refused units wrote %v", ents)
			}
			so.Reset()
			if code := checkPolicyWith([]string{"--policy", p}, &so, &se, env); code != 1 || !strings.Contains(so.String(), "FAIL") || !strings.Contains(so.String(), "/var/run") {
				t.Fatalf("check-policy: exit %d: %s", code, so.String())
			}
		})
	}
}

// units writes the broad unit pair only for a policy that uses the broad
// unit (packages, unit: broad commands, power), and says so either way.
func TestUnitsBroad(t *testing.T) {
	env, p := testEnv(t, validPolicy)
	out := t.TempDir()
	var so, se bytes.Buffer
	if code := unitsWith([]string{"--policy", p, "--out", out}, &so, &se, env); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	if _, err := os.Stat(filepath.Join(out, units.BroadServiceUnit)); err == nil || !strings.Contains(so.String(), "no broad unit") {
		t.Fatalf("a policy without broad users got a broad unit: %s", so.String())
	}
	env, p = testEnv(t, validPolicy+"power:\n  allowed: [reboot]\n  acknowledge: \"invented maintenance window\"\n")
	out = t.TempDir()
	so.Reset()
	if code := unitsWith([]string{"--policy", p, "--out", out}, &so, &se, env); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	lo := &policy.LoadOptions{Trust: env.trust, HelperExecutable: env.executable, SystemBinDirs: env.systemBinDirs}
	env.lookups(lo)
	pol, err := policy.Load(p, lo)
	if err != nil {
		t.Fatal(err)
	}
	want, err := units.Broad(pol)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{units.BroadSocketUnit: want.Socket, units.BroadServiceUnit: want.Service} {
		b, err := os.ReadFile(filepath.Join(out, name)) //nolint:gosec // G304: test output
		if err != nil || string(b) != content {
			t.Fatalf("%s: %v\n%s", name, err, b)
		}
	}
	for _, s := range []string{units.BroadSocketUnit, "root-equivalent"} {
		if !strings.Contains(so.String(), s) {
			t.Errorf("output lacks %q: %s", s, so.String())
		}
	}
}
