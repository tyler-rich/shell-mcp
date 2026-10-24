//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
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
		"a directory":         func(p string) error { return os.Mkdir(p, 0o750) },
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

// TestTrampolineIsNotACommand: the exec trampoline runs only from execx's
// init, when it is exactly argv[1] of a process started with an empty
// environment and its control socket (internal/gate/execx). The helper's
// argv is fixed by its generated unit and starts with serve; as a command
// name the trampoline argument is unknown and nothing is served.
func TestTrampolineIsNotACommand(t *testing.T) {
	var so, se bytes.Buffer
	if code := run([]string{execx.TrampolineArg}, &so, &se); code != 2 || so.Len() != 0 || !strings.Contains(se.String(), "unknown command") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, so.String(), se.String())
	}
}

// TestCheckPolicyProbesRenameFlags: check-policy probes RENAME_NOREPLACE
// (create-only commits, delete) and RENAME_EXCHANGE (every replace as root)
// on each privileged write root, and warns naming the root and the flag.
func TestCheckPolicyProbesRenameFlags(t *testing.T) {
	env, p := testEnv(t, validPolicy)
	pol, err := env.load(p)
	if err != nil {
		t.Fatal(err)
	}
	roots := pol.Paths.WriteRoots()
	if len(roots) < 2 {
		t.Fatalf("fixture write roots %v", roots)
	}
	probed := map[string]int{}
	oldNR, oldEx := probeNoReplace, probeExchange
	t.Cleanup(func() { probeNoReplace, probeExchange = oldNR, oldEx })
	probeNoReplace = func(dir string) error {
		probed[dir]++
		if dir == roots[0] {
			return fsx.ErrNoReplaceUnsupported
		}
		return nil
	}
	probeExchange = func(dir string) error {
		probed[dir]++
		if dir == roots[1] {
			return fsx.ErrExchangeUnsupported
		}
		return nil
	}
	var so, se bytes.Buffer
	_ = checkPolicyWith([]string{"--policy", p}, &so, &se, env)
	out := so.String()
	for _, want := range []string{
		"WARN privileged write root " + roots[0] + ": the filesystem does not support RENAME_NOREPLACE",
		"ok   privileged write root " + roots[0] + ": RENAME_EXCHANGE supported",
		"ok   privileged write root " + roots[1] + ": RENAME_NOREPLACE supported",
		"WARN privileged write root " + roots[1] + ": the filesystem does not support RENAME_EXCHANGE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	for _, r := range roots {
		if probed[r] != 2 {
			t.Errorf("%s probed %d times, want 2 (both flags)", r, probed[r])
		}
	}
}

// TestCheckPolicyChecksTheChain (handoff N-1): check-policy warns about
// every privileged write root with a directory on its path that another
// account could write (owned by an untrusted uid, or group- or
// world-writable): chmod and chown are refused under such a root.
// TestCheckPolicyChecksReadRootChains (S4c-5, N-6/N-7): the moved-in rule
// checks the directories from a root down, so check-policy reports, for
// each read root as for each write root, an open directory on its own path:
// above the root another account could replace the root itself; the root
// itself open makes the rule refuse what that account could not read.
func TestCheckPolicyChecksReadRootChains(t *testing.T) {
	y := strings.Replace(validPolicy, "read: [{D}/srv/app]", "read: [{D}/srv/app, {D}/srv/drop/logs, {D}/srv/shared]", 1)
	env, p := testEnv(t, y)
	d := filepath.Dir(filepath.Dir(filepath.Dir(p)))
	drop, shared := filepath.Join(d, "srv", "drop"), filepath.Join(d, "srv", "shared")
	gatetest.Mkdir(t, filepath.Join(drop, "logs"), 0o755)
	gatetest.Mkdir(t, shared, 0o755)
	if err := os.Chmod(drop, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o775); err != nil { //nolint:gosec // G302: a group-writable read root
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	_ = checkPolicyWith([]string{"--policy", p}, &so, &se, env)
	out := so.String()
	for _, want := range []string{
		"ok   privileged read root " + filepath.Join(d, "srv", "app") + ": every directory from / to it is root's",
		"WARN privileged read root " + filepath.Join(drop, "logs") + ": " + drop + " is group- or world-writable (mode 0777); another account could replace the root itself",
		"which the per-request moved-in check does not see; root commands are given no path (placeholder or cwd) at or under it",
		"WARN privileged read root " + shared + ": " + shared + " is group- or world-writable (mode 0775); files under it are read as root only",
		"could have written them; root commands are given no path (placeholder or cwd) at or under it",
		"WARN privileged write root " + filepath.Join(d, "etc", "example-app") + ": ",
	} {
		if strings.HasPrefix(want, "WARN privileged write root") {
			if strings.Contains(out, want) {
				t.Errorf("a closed write root got a WARN:\n%s", out)
			}
			continue
		}
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckPolicyChecksTheChain(t *testing.T) {
	y := strings.Replace(validPolicy, "write: [{D}/etc/example-app]", "write: [{D}/etc/example-app, {D}/srv/drop/app]", 1)
	env, p := testEnv(t, y)
	d := filepath.Dir(filepath.Dir(filepath.Dir(p)))
	drop := filepath.Join(d, "srv", "drop")
	gatetest.Mkdir(t, filepath.Join(drop, "app"), 0o755)
	if err := os.Chmod(drop, 0o777); err != nil { //nolint:gosec // G302: another account's write access, simulated
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	_ = checkPolicyWith([]string{"--policy", p}, &so, &se, env)
	out := so.String()
	for _, want := range []string{
		"ok   privileged write root " + filepath.Join(d, "etc", "example-app") + ": every directory from / to it is root's",
		"WARN privileged write root " + filepath.Join(drop, "app") + ": " + drop + " is group- or world-writable (mode 0777); chmod and chown are refused under it",
		"does not see; root commands are given no path (placeholder or cwd) at or under it",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

// TestCheckPolicyWarnsGTFOBins (handoff N-16): the helper's check-policy
// prints a WARN line for a command whose binary has documented escape
// techniques, as the gate's does, naming the command, the categories and
// that it runs as root.
func TestCheckPolicyWarnsGTFOBins(t *testing.T) {
	y := validPolicy + "commands:\n  - id: list-archive\n    path: {D}/bin/tar\n    tier: read\n    templates: [[\"-tf\", \"{path:read}\"]]\n"
	env, p := testEnv(t, y)
	d := filepath.Dir(filepath.Dir(filepath.Dir(p)))
	gatetest.WriteFile(t, filepath.Join(d, "bin", "tar"), "invented binary\n", 0o755)
	var so, se bytes.Buffer
	_ = checkPolicyWith([]string{"--policy", p}, &so, &se, env)
	out := so.String()
	if !strings.Contains(out, "WARN commands[list-archive]: tar has documented escape techniques (GTFOBins: command execution, file read, file write)") ||
		!strings.Contains(out, "as root") || !strings.Contains(out, "https://gtfobins.org/gtfobins/tar/") {
		t.Fatalf("check-policy:\n%s", out)
	}
}

// TestCheckPolicyStickyIsOpen (handoff N-24): root commands' paths (N-10)
// count a sticky directory on a root's path as open, writable or not, so
// check-policy reports a root under one, as it does an open one, naming the
// directory, instead of an ok line; chmod and chown, which ignore the
// sticky bit, are not named as refused.
func TestCheckPolicyStickyIsOpen(t *testing.T) {
	y := strings.Replace(validPolicy, "read: [{D}/srv/app]", "read: [{D}/srv/app, {D}/srv/spool/logs]", 1)
	y = strings.Replace(y, "write: [{D}/etc/example-app]", "write: [{D}/etc/example-app, {D}/srv/drop]", 1)
	env, p := testEnv(t, y)
	d := filepath.Dir(filepath.Dir(filepath.Dir(p)))
	spool, drop := filepath.Join(d, "srv", "spool"), filepath.Join(d, "srv", "drop")
	gatetest.Mkdir(t, filepath.Join(spool, "logs"), 0o755)
	gatetest.Mkdir(t, drop, 0o755)
	for _, dir := range []string{spool, drop} {
		if err := os.Chmod(dir, os.ModeSticky|0o755); err != nil {
			t.Fatal(err)
		}
		gatetest.ExactMode(t, dir, os.ModeSticky|0o755)
	}
	var so, se bytes.Buffer
	_ = checkPolicyWith([]string{"--policy", p}, &so, &se, env)
	out := so.String()
	for _, want := range []string{
		"WARN privileged read root " + filepath.Join(spool, "logs") + ": " + spool + " is sticky (mode 1755); root commands are given no path (placeholder or cwd) at or under it",
		"WARN privileged write root " + drop + ": " + drop + " is sticky (mode 1755); root commands are given no path (placeholder or cwd) at or under it",
		"ok   privileged write root " + filepath.Join(d, "etc", "example-app") + ": every directory from / to it is root's",
		"ok   privileged read root " + filepath.Join(d, "srv", "app") + ": every directory from / to it is root's",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"ok   privileged write root " + drop + ":", "ok   privileged read root " + filepath.Join(spool, "logs") + ":"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a root under a sticky directory got an ok line:\n%s", out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " is sticky ") && strings.Contains(line, "chmod and chown are refused") {
			t.Errorf("a sticky directory is reported as refusing chmod and chown: %s", line)
		}
	}
}
