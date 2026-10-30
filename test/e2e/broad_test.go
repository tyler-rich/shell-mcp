//go:build e2e && linux

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The broad unit, the apt operations and the core unit's hardening,
// against the runner's own systemd and apt (setup.sh; the power operations
// are in power_test.go). Every restriction is shown two-sided.

// ---- Local apt repository ------------------------------------------------------

// aptRepo makes /srv/e2e-apt a flat repository holding exactly the given
// packages (built by setup.sh from invented control data): the .deb files,
// a Packages index and an unsigned Release file, which the source's
// [trusted=yes] accepts. No internet is involved.
func aptRepo(t *testing.T, debs ...string) {
	t.Helper()
	aptRepoAt(t, repoDir, debs...)
}

// aptRepoNext stages a repository in repoNextDir, which the test build's
// package hook moves into repoDir at its stage (armPkgHook).
func aptRepoNext(t *testing.T, debs ...string) {
	t.Helper()
	if err := os.MkdirAll(repoNextDir, 0o755); err != nil { //nolint:gosec // G301: read by apt's unprivileged methods
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(repoNextDir) })
	aptRepoAt(t, repoNextDir, debs...)
}

func aptRepoAt(t *testing.T, dir string, debs ...string) {
	t.Helper()
	// Each Release file's Date must be newer than the last one apt saw.
	time.Sleep(1100 * time.Millisecond)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	var index strings.Builder
	for _, d := range debs {
		src := filepath.Join(bin(), "debs", d)
		b, err := os.ReadFile(src) //nolint:gosec // G304: setup.sh's own packages
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, d), b, 0o644); err != nil { //nolint:gosec // G306: apt's unprivileged methods read the repository
			t.Fatal(err)
		}
		control := strings.TrimRight(run(t, "dpkg-deb", "-f", src), "\n")
		sum := sha256.Sum256(b)
		fmt.Fprintf(&index, "%s\nFilename: ./%s\nSize: %d\nSHA256: %s\n\n", control, d, len(b), hex.EncodeToString(sum[:]))
	}
	pkgs := []byte(index.String())
	if err := os.WriteFile(filepath.Join(dir, "Packages"), pkgs, 0o644); err != nil { //nolint:gosec // G306: read by apt
		t.Fatal(err)
	}
	sum := sha256.Sum256(pkgs)
	release := fmt.Sprintf("Origin: shell-mcp-e2e\nLabel: shell-mcp-e2e\nSuite: e2e\nCodename: e2e\nDate: %s\nArchitectures: all amd64 arm64\nSHA256:\n %s %d Packages\n",
		time.Now().UTC().Format(time.RFC1123), hex.EncodeToString(sum[:]), len(pkgs))
	if err := os.WriteFile(filepath.Join(dir, "Release"), []byte(release), 0o644); err != nil { //nolint:gosec // G306: read by apt
		t.Fatal(err)
	}
}

// installed returns dpkg's status and version of pkg ("" when unknown).
func installed(t *testing.T, pkg string) string {
	t.Helper()
	out, _ := exec.CommandContext(t.Context(), "dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", pkg).Output() //nolint:gosec // G204: fixed test package names
	return strings.TrimSpace(string(out))
}

// cleanupPackages removes the test packages directly with dpkg (outside
// the helper) when the test ends, first letting any slow or stuck
// maintainer script end (the fast flag) and finishing what dpkg left.
func cleanupPackages(t *testing.T) {
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = os.WriteFile("/run/shell-mcp-e2e-pkg-fast", nil, 0o600)
		_ = os.Remove(pkgFail)
		// dpkg refuses to remove a package that needs a reinstall without
		// this force (measured); only the tests' own cleanup uses it.
		_ = exec.CommandContext(ctx, "dpkg", "--force-remove-reinstreq", "--purge", "example-reinst").Run()
		_ = exec.CommandContext(ctx, "dpkg", "--configure", "-a").Run()
		_ = exec.CommandContext(ctx, "dpkg", "--purge", "example-hello", "example-extra", "example-other", "example-conf",
			"example-slow", "example-slow-b", "example-slow-a", "example-stuck", "example-blocked", "example-needs", "example-reinst").Run()
		_ = os.Remove("/run/shell-mcp-e2e-pkg-fast")
		_ = os.Remove(pkgRelease)
	})
}

type pkgEntry struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

type previewResult struct {
	Install       []pkgEntry `json:"install"`
	Upgrade       []pkgEntry `json:"upgrade"`
	Remove        []pkgEntry `json:"remove"`
	Complete      bool       `json:"complete"`
	Argv          []string   `json:"argv"`
	PreviewSHA256 string     `json:"preview_sha256"`
}

type pkgResult struct {
	ExitCode *int   `json:"exit_code"`
	Stderr   string `json:"stderr"`
	Applied  *struct {
		Install []pkgEntry `json:"install"`
		Upgrade []pkgEntry `json:"upgrade"`
		Remove  []pkgEntry `json:"remove"`
	} `json:"applied"`
}

// pkgPreview previews op (priv_pkg_<op>_preview) through the gate.
func pkgPreview(t *testing.T, op string, args map[string]any) previewResult {
	t.Helper()
	var p previewResult
	mustGate(t, "priv_pkg_"+op+"_preview", args, &p)
	return p
}

// withHash is args with the preview's hash as expected_preview_sha256.
func withHash(args map[string]any, hash string) map[string]any {
	out := map[string]any{"expected_preview_sha256": hash}
	for k, v := range args {
		out[k] = v
	}
	return out
}

// mustPkg previews op and runs it bound to that preview; it returns the
// result.
func mustPkg(t *testing.T, op string, args map[string]any) pkgResult {
	t.Helper()
	var hash string
	if op == "update_index" {
		var u struct {
			PreviewSHA256 string `json:"preview_sha256"`
		}
		mustGate(t, "priv_pkg_update_index_preview", map[string]any{}, &u)
		hash = u.PreviewSHA256
	} else {
		hash = pkgPreview(t, op, args).PreviewSHA256
	}
	var r pkgResult
	mustGate(t, "priv_pkg_"+op, withHash(args, hash), &r)
	if r.ExitCode == nil || *r.ExitCode != 0 {
		t.Logf("broad unit process status:\n%s", privExec(t, "probe-broad", "broad", "status"))
		t.Fatalf("%s: exit %v, stderr %q", op, r.ExitCode, r.Stderr)
	}
	return r
}

var helloArgs = map[string]any{"packages": []string{"example-hello"}}

// Update the index, preview then install an allow-listed package (without
// its Recommends), refuse the others, preview then remove it; upgrade is
// refused while allow_upgrade is false. Every operation is bound to its
// preview.
func TestPackages(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb", "example-other_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})

	p := pkgPreview(t, "install", helloArgs)
	if len(p.Install) != 1 || p.Install[0].Name != "example-hello" || p.Install[0].Version != "1.0" || len(p.Upgrade)+len(p.Remove) != 0 || !p.Complete ||
		len(p.PreviewSHA256) != 64 {
		t.Fatalf("install preview %+v", p)
	}
	// Control: apt's default installs the recommended package too; the
	// helper's --no-install-recommends does not.
	if out := run(t, "apt-get", "-s", "-o", "APT::Install-Recommends=true", "install", "example-hello"); !strings.Contains(out, "Inst example-extra") {
		t.Fatalf("control simulation without --no-install-recommends:\n%s", out)
	}
	if installed(t, "example-hello") != "" && !strings.HasPrefix(installed(t, "example-hello"), "not-installed") {
		t.Fatalf("the preview installed something: %q", installed(t, "example-hello"))
	}
	for _, name := range []string{"example-other", "example-extra"} {
		wantGate(t, svcShell, "priv_pkg_install", withHash(map[string]any{"packages": []string{name}}, p.PreviewSHA256), "policy_denied")
		wantGate(t, svcShell, "priv_pkg_install_preview", map[string]any{"packages": []string{name}}, "policy_denied")
	}
	wantGate(t, svcShell, "priv_pkg_install", helloArgs, "bad_request")
	r := mustPkg(t, "install", helloArgs)
	if r.Applied == nil || len(r.Applied.Install) != 1 || r.Applied.Install[0] != (pkgEntry{Name: "example-hello", Version: "1.0"}) {
		t.Fatalf("applied %+v", r.Applied)
	}
	if got := installed(t, "example-hello"); got != "installed 1.0" {
		t.Fatalf("example-hello: %q", got)
	}
	if got := installed(t, "example-extra"); strings.HasPrefix(got, "installed") {
		t.Fatalf("the recommended package was installed: %q", got)
	}
	if got := installed(t, "example-other"); strings.HasPrefix(got, "installed") {
		t.Fatalf("a package on no allow-list was installed: %q", got)
	}
	if b, err := os.ReadFile("/usr/share/example-hello/version"); err != nil || string(b) != "example-hello 1.0\n" {
		t.Fatalf("installed file: %q %v", b, err)
	}
	waitLine(t, "shell-mcp-privd", `"op":"priv_pkg_install"`, `"outcome":"ok"`, `"applied":`)

	wantGate(t, svcShell, "priv_pkg_upgrade", map[string]any{"expected_preview_sha256": p.PreviewSHA256}, "policy_denied")
	wantGate(t, svcShell, "priv_pkg_upgrade_preview", map[string]any{}, "policy_denied")

	p = pkgPreview(t, "remove", helloArgs)
	if len(p.Remove) != 1 || p.Remove[0].Name != "example-hello" || p.Remove[0].Version != "1.0" || len(p.Install) != 0 {
		t.Fatalf("remove preview %+v", p)
	}
	if got := installed(t, "example-hello"); got != "installed 1.0" {
		t.Fatalf("the remove preview removed something: %q", got)
	}
	mustPkg(t, "remove", helloArgs)
	if got := installed(t, "example-hello"); strings.HasPrefix(got, "installed") {
		t.Fatalf("example-hello still installed: %q", got)
	}
	if _, err := os.Stat("/usr/share/example-hello/version"); err == nil {
		t.Fatal("the removed package's file is still there")
	}
}

// TestPackageRemoveNeverPurges: a removed package keeps its configuration
// files (dpkg's config-files state).
func TestPackageRemoveNeverPurges(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-conf_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	conf := map[string]any{"packages": []string{"example-conf"}}
	mustPkg(t, "install", conf)
	mustPkg(t, "remove", conf)
	if got := installed(t, "example-conf"); got != "config-files 1.0" {
		t.Fatalf("after the removal: %q", got)
	}
	if _, err := os.Stat("/etc/example-conf/example-conf.conf"); err != nil {
		t.Fatalf("the configuration file was purged: %v", err)
	}
}

// With allow_upgrade: true and a newer version in the repository, the
// upgrade preview shows 1.0 → 1.1 and the upgrade installs it.
func TestPackageUpgrade(t *testing.T) {
	cleanupPackages(t)
	installPolicy(t, "privileged-upgrade.yaml")
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	mustPkg(t, "install", helloArgs)
	aptRepo(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	p := pkgPreview(t, "upgrade", map[string]any{})
	if len(p.Upgrade) != 1 || p.Upgrade[0].Name != "example-hello" || p.Upgrade[0].From != "1.0" || p.Upgrade[0].To != "1.1" {
		t.Fatalf("upgrade preview %+v", p)
	}
	if got := installed(t, "example-hello"); got != "installed 1.0" {
		t.Fatalf("the preview upgraded: %q", got)
	}
	mustPkg(t, "upgrade", map[string]any{})
	if got := installed(t, "example-hello"); got != "installed 1.1" {
		t.Fatalf("after the upgrade: %q", got)
	}
}

// TestPackageLock: a held dpkg frontend lock: a preview refuses at once,
// naming the holder; an install waits, bounded by half the request's
// timeout, and is refused naming the holder, nothing changed; once
// released, the same install (newly previewed) works.
func TestPackageLock(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	p := pkgPreview(t, "install", helloArgs)
	f, err := os.OpenFile("/var/lib/dpkg/lock-frontend", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatalf("taking the dpkg frontend lock: %v", err)
	}
	holder := fmt.Sprintf("(pid %d)", os.Getpid())
	if r, _ := gate(t, svcShell, "priv_pkg_install_preview", helloArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, holder) {
		t.Fatalf("preview with the lock held: %s %+v", r.code(), r.Error)
	}
	start := time.Now()
	r, _ := gate(t, svcShell, "priv_pkg_install", withHash(helloArgs, p.PreviewSHA256))
	if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, holder) || !strings.Contains(r.Error.Message, "nothing was changed") {
		t.Fatalf("with the lock held: %s %+v", r.code(), r.Error)
	}
	if d := time.Since(start); d > 25*time.Second {
		t.Fatalf("waited %v for the lock (request timeout 30 s, lock wait at most 15 s)", d)
	}
	if strings.HasPrefix(installed(t, "example-hello"), "installed") {
		t.Fatal("installed while the lock was held")
	}
	lk.Type = syscall.F_UNLCK
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	mustPkg(t, "install", helloArgs)
}

// ---- Network: broad yes, core no ------------------------------------------------

func listenTCP(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func privExec(t *testing.T, command, unit string, args ...string) string {
	t.Helper()
	a := map[string]any{"command_id": command, "args": args}
	if unit != "" {
		a["unit"] = unit
	}
	var ex struct {
		Stdout string `json:"stdout"`
	}
	mustGate(t, "priv_exec", a, &ex)
	return strings.TrimSpace(ex.Stdout)
}

// A command declared unit: broad reaches a local TCP listener; the same
// probe declared for the core unit cannot.
func TestBroadUnitNetwork(t *testing.T) {
	port := listenTCP(t)
	if out := strings.TrimSpace(run(t, probeBin, "connect", port)); out != "CONNECTED" {
		t.Fatalf("control: %s", out)
	}
	if got := privExec(t, "probe-broad", "broad", "connect", port); got != "CONNECTED" {
		t.Fatalf("broad command: %q, want CONNECTED", got)
	}
	if got := privExec(t, "probe-connect", "", "connect", port); got == "CONNECTED" || got == "" {
		t.Fatalf("core command: %q", got)
	}
}

// ---- /run and abstract sockets: hidden from the core unit ------------------------

// The core unit sees /run (and /var/run, a symlink to it) as an empty
// read-only tmpfs: the system bus and any socket under /run are
// unreachable from it, so root in the core unit cannot ask PID 1 or any
// other root service for anything. Its private network namespace hides the
// host's abstract sockets. The broad unit reaches all three.
func TestCoreUnitHidesRunAndAbstractSockets(t *testing.T) {
	const testSock = "/run/shell-mcp-e2e.sock"
	_ = os.Remove(testSock)
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", testSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close(); _ = os.Remove(testSock) })
	name := "shell-mcp-e2e-" + strconv.Itoa(os.Getpid())
	al, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	for _, ln := range []net.Listener{l, al} {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	for _, target := range [][]string{
		{"unix-connect", "/run/dbus/system_bus_socket"},
		{"unix-connect", "/var/run/dbus/system_bus_socket"},
		{"unix-connect", testSock},
		{"abstract-connect", name},
	} {
		if out := strings.TrimSpace(run(t, probeBin, target...)); out != "CONNECTED" {
			t.Fatalf("control %v: %s", target, out)
		}
		if got := privExec(t, "probe-broad", "broad", target...); got != "CONNECTED" {
			t.Fatalf("broad unit %v: %q, want CONNECTED", target, got)
		}
		if got := privExec(t, "probe-unix", "", target...); got == "CONNECTED" || got == "" {
			t.Fatalf("core unit %v: %q", target, got)
		}
	}
	if got := strings.TrimSpace(run(t, "systemctl", "show", "-p", "TemporaryFileSystem", "--value", "shell-mcp-privd@e2e.service")); !strings.Contains(got, "/run:ro") {
		t.Fatalf("core unit TemporaryFileSystem=%q", got)
	}
}

// ---- ProtectProc=, ProcSubset=, ProtectClock= -------------------------------------

func sleeperAs(t *testing.T, uid uint32) int {
	t.Helper()
	c := exec.CommandContext(t.Context(), "/usr/bin/sleep", "120")
	c.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, uid)}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	return c.Process.Pid
}

func show(t *testing.T, unit, prop string) string {
	t.Helper()
	return strings.TrimSpace(run(t, "systemctl", "show", "-p", prop, "--value", unit))
}

// ProtectProc=ptraceable hides from core-unit commands every process they
// may not ptrace. That is every process outside the helper's own Landlock
// domain: other users' processes (the unit has no CAP_SYS_PTRACE) and
// root-owned ones too, because Landlock refuses ptrace access in every mode,
// procfs's read mode included, to a process outside the caller's domain
// (hook_ptrace_access_check, security/landlock/task.c). A core-unit command
// declaring CAP_KILL turns it to default, and both are seen. (Not
// invisible: the kernel exempts procfs's gid= group, gid 0 by default, from
// that mode's check, and the helper is root:root.)
func TestCoreProtectProc(t *testing.T) {
	other := strconv.Itoa(sleeperAs(t, svcOther))
	root := strconv.Itoa(sleeperAs(t, 0))
	for _, pid := range []string{other, root} {
		if out := strings.TrimSpace(run(t, probeBin, "visible", pid)); out != "VISIBLE" {
			t.Fatalf("control %s: %s", pid, out)
		}
	}
	if got := show(t, "shell-mcp-privd@e2e.service", "ProtectProc"); got != "ptraceable" {
		t.Fatalf("ProtectProc=%s", got)
	}
	if got := show(t, "shell-mcp-privd@e2e.service", "ProcSubset"); got != "pid" {
		t.Fatalf("ProcSubset=%s", got)
	}
	for name, pid := range map[string]string{"another user's": other, "a root": root} {
		if got := privExec(t, "probe-visible", "", "visible", pid); got != "ENOENT" {
			t.Fatalf("%s process with ProtectProc=ptraceable: %q, want ENOENT", name, got)
		}
	}
	installPolicy(t, "privileged-cap-kill.yaml")
	if got := show(t, "shell-mcp-privd@e2e.service", "ProtectProc"); got != "default" {
		t.Fatalf("with CAP_KILL, ProtectProc=%s", got)
	}
	for name, pid := range map[string]string{"another user's": other, "a root": root} {
		if got := privExec(t, "probe-visible", "", "visible", pid); got != "VISIBLE" {
			t.Fatalf("%s process with CAP_KILL: %q, want VISIBLE", name, got)
		}
	}
}

// Another root process's environment stays out of reach of the core unit.
// With ProtectProc=ptraceable the process is not even visible (ENOENT);
// with ProtectProc=default (a core CAP_KILL) it is visible, and the core
// unit's Landlock ruleset — no /proc grant beyond the helper's own
// /proc/<pid> — refuses opening its environ (EACCES). priv_read_file refuses
// every /proc path in both cases, because no privileged root may be or be
// inside /proc. Outside the unit, root reads it (the control).
func TestCoreCannotReadProcessEnvironment(t *testing.T) {
	c := exec.CommandContext(t.Context(), "/usr/bin/sleep", "120")
	c.Env = []string{"E2E_ENV_CANARY=invented-e2e-value"}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	pid := strconv.Itoa(c.Process.Pid)
	if out := strings.TrimSpace(run(t, probeBin, "read-environ", pid)); !strings.HasPrefix(out, "READ:") || !strings.HasSuffix(out, " CANARY") {
		t.Fatalf("control: %s", out)
	}
	check := func(when, want string) {
		t.Helper()
		if got := privExec(t, "probe-environ", "", "read-environ", pid); got != want {
			t.Fatalf("%s: a core-unit command reading another root process's environment got %q, want %s", when, got, want)
		}
		for _, p := range []string{"/proc/" + pid + "/environ", "/proc/1/environ"} {
			wantGate(t, svcShell, "priv_read_file", map[string]any{"path": p}, "path_denied")
		}
	}
	check("ProtectProc=ptraceable", "ENOENT")
	installPolicy(t, "privileged-cap-kill.yaml")
	check("ProtectProc=default (Landlock alone)", "EACCES")
}

// A broad-unit command declaring CAP_SYS_TIME turns ProtectClock= off in
// the broad unit only; without it both units keep ProtectClock=yes.
func TestBroadProtectClock(t *testing.T) {
	broadUnit := "/etc/systemd/system/shell-mcp-privd-broad@.service"
	if !strings.Contains(readFile(t, broadUnit), "\nProtectClock=yes\n") || show(t, "shell-mcp-privd-broad@e2e.service", "ProtectClock") != "yes" {
		t.Fatal("control: the broad unit lacks ProtectClock=yes")
	}
	installPolicy(t, "privileged-sys-time.yaml")
	if strings.Contains(readFile(t, broadUnit), "ProtectClock") {
		t.Fatalf("the broad unit still sets ProtectClock:\n%s", readFile(t, broadUnit))
	}
	if got := show(t, "shell-mcp-privd-broad@e2e.service", "ProtectClock"); got != "no" {
		t.Fatalf("broad unit ProtectClock=%s", got)
	}
	if got := show(t, "shell-mcp-privd@e2e.service", "ProtectClock"); got != "yes" {
		t.Fatalf("core unit ProtectClock=%s", got)
	}
	if !strings.Contains(readFile(t, "/etc/systemd/system/shell-mcp-privd@.service"), "\nProtectClock=yes\n") {
		t.Fatal("the core unit lost ProtectClock=yes")
	}
}

// ---- Routing: each instance refuses the other unit's operations -------------------

// wrongUnit sends op to the helper at socket, requires helper_wrong_unit,
// and returns the request id.
func wrongUnit(t *testing.T, socket, op string, args any) string {
	t.Helper()
	a, _ := json.Marshal(args)
	id := newID()
	out := directTo(t, svcShell, socket, fmt.Sprintf(`{"v":2,"id":%q,"ceiling":"destructive","op":%q,"args":%s,"timeout_ms":30000}`+"\n", id, op, a))
	var r response
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.code() != "helper_wrong_unit" || r.ID != id {
		t.Fatalf("%s %s on %s: %q", op, a, socket, out)
	}
	return id
}

// A request that reaches the wrong helper instance — whatever sent it
// there — is refused with helper_wrong_unit and never executed.
func TestMisroutedRequestsRefused(t *testing.T) {
	statID := wrongUnit(t, broadSocket, "priv_stat", map[string]any{"path": "/etc/example-app"})
	wrongUnit(t, broadSocket, "priv_exec", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "core"}})
	updateID := wrongUnit(t, socketPath, "priv_pkg_update_index", map[string]any{})
	wrongUnit(t, socketPath, "priv_power", map[string]any{"action": "reboot"})
	wrongUnit(t, socketPath, "priv_exec", map[string]any{"command_id": "probe-broad", "args": []string{"echo", "broad"}})
	// Through the gate, a label that names the wrong unit sends the request
	// to the wrong socket, where it is refused.
	wantGate(t, svcShell, "priv_exec", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "x"}, "unit": "broad"}, "helper_wrong_unit")
	wantGate(t, svcShell, "priv_exec", map[string]any{"command_id": "probe-broad", "args": []string{"echo", "x"}}, "helper_wrong_unit")
	// Controls: routed right, both run.
	if got := privExec(t, "probe-echo", "", "echo", "core"); got != "core" {
		t.Fatalf("core exec %q", got)
	}
	if got := privExec(t, "probe-broad", "broad", "echo", "broad"); got != "broad" {
		t.Fatalf("broad exec %q", got)
	}
	e := waitLine(t, "shell-mcp-privd", `"id":"`+updateID+`"`, `"outcome":"helper_wrong_unit"`, `"op":"priv_pkg_update_index"`)
	if e.Priority != "5" || !strings.HasPrefix(e.Unit, "shell-mcp-privd@") {
		t.Fatalf("core refusal logged at %s by %s", e.Priority, e.Unit)
	}
	e = waitLine(t, "shell-mcp-privd", `"id":"`+statID+`"`, `"outcome":"helper_wrong_unit"`, `"op":"priv_stat"`)
	if e.Priority != "4" || !strings.HasPrefix(e.Unit, "shell-mcp-privd-broad@") {
		t.Fatalf("broad refusal logged at %s by %s", e.Priority, e.Unit)
	}
}

// TestHelperExecTrampoline: the helper starts root commands by re-executing
// its own binary inside the unit (internal/gate/execx's trampoline), in
// both units. The command has the child limits from its first instruction
// (core dumps off, open files bounded), keeps Pdeathsig=SIGKILL and its own
// process group, and holds no descriptor it was not given; in the core
// unit it is also under no_new_privs and the seccomp filters.
func TestHelperExecTrampoline(t *testing.T) {
	for _, c := range []struct{ command, unit string }{{"probe-attrs", ""}, {"probe-broad", "broad"}} {
		t.Run(c.command, func(t *testing.T) {
			lim := map[string]string{}
			for _, l := range strings.Split(privExec(t, c.command, c.unit, "rlimits"), "\n") {
				k, v, _ := strings.Cut(l, "=")
				lim[k] = v
			}
			if lim["core"] != "0/0" {
				t.Fatalf("core %q", lim["core"])
			}
			cur, maxv, _ := strings.Cut(lim["nofile"], "/")
			if n, err := strconv.Atoi(cur); err != nil || n > 1024 {
				t.Fatalf("nofile %q", lim["nofile"])
			}
			if n, err := strconv.Atoi(maxv); err != nil || n > 1024 {
				t.Fatalf("nofile %q", lim["nofile"])
			}
			a := map[string]string{}
			for _, l := range strings.Split(privExec(t, c.command, c.unit, "procattrs"), "\n") {
				k, v, _ := strings.Cut(l, "=")
				a[k] = v
			}
			if a["pdeathsig"] != "9" || a["pdeathsig_thread"] != "main" || a["pgid_is_pid"] != "true" {
				t.Fatalf("attributes %v", a)
			}
			if c.unit == "" && (a["nnp"] != "1" || a["seccomp"] != "2") {
				t.Fatalf("core command: attributes %v", a)
			}
			// The Go runtime keeps /sys/fs/cgroup/cpu.max open where it can
			// read it; nothing else may be open.
			if fds := a["fds"]; fds != "" && (strings.Contains(fds, ",") || !strings.HasPrefix(fds, "3:100000:/sys/fs/cgroup/")) {
				t.Fatalf("the command has descriptors it was not given: %s", fds)
			}
		})
	}
}

// ---- A command does not outlive the gate or the helper that started it ----------

// startGate starts the real gate as svc-shell with one request on stdin and
// returns it while it runs.
func startGate(t *testing.T, policy, principal, ceiling, op string, args any) *exec.Cmd {
	t.Helper()
	a, _ := json.Marshal(args)
	req := fmt.Sprintf(`{"v":2,"id":%q,"ceiling":%q,"op":%q,"args":%s,"timeout_ms":30000}`+"\n", newID(), ceiling, op, a)
	cmd := exec.CommandContext(t.Context(), gateBin, "serve", "--policy", policy, "--principal", principal) //nolint:gosec // G204: the installed gate; policy and principal are this file's constants
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.Stdin = strings.NewReader(req)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// timespan parses a systemd time span as systemctl show prints it
// ("1min 30s", "500ms", "infinity").
func timespan(t *testing.T, s string) time.Duration {
	t.Helper()
	if s == "infinity" {
		return time.Duration(1<<63 - 1)
	}
	var d time.Duration
	for _, f := range strings.Fields(s) {
		i := strings.IndexFunc(f, func(r rune) bool { return r < '0' || r > '9' })
		if i <= 0 {
			t.Fatalf("time span %q", s)
		}
		n, _ := strconv.Atoi(f[:i])
		unit, ok := map[string]time.Duration{"h": time.Hour, "min": time.Minute, "s": time.Second, "ms": time.Millisecond, "us": time.Microsecond}[f[i:]]
		if !ok {
			t.Fatalf("time span %q", s)
		}
		d += time.Duration(n) * unit
	}
	return d
}

// pdeathsigWindow is how soon a command must be gone after its starter is
// killed: the parent-death signal is delivered while the parent exits.
const pdeathsigWindow = 2 * time.Second

// helperStopTimeout is the helper units' TimeoutStopSec= (internal/privd/units).
const helperStopTimeout = 5 * time.Second

// helperOf returns the helper instance that started p and its unit, checked
// to be the core or the broad unit's.
func helperOf(t *testing.T, p gatetest.Proc, broad bool) (pid int, unit string) {
	t.Helper()
	pid = p.Parent()
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err != nil || !strings.HasPrefix(filepath.Base(exe), filepath.Base(privdBin)) {
		t.Fatalf("the command's parent %d is %q (%v), not the helper", pid, exe, err)
	}
	cg := strings.TrimSpace(readFile(t, fmt.Sprintf("/proc/%d/cgroup", pid)))
	unit = filepath.Base(cg[strings.LastIndexByte(cg, ':')+1:])
	wantPrefix := "shell-mcp-privd@"
	if broad {
		wantPrefix = "shell-mcp-privd-broad@"
	}
	if !strings.HasPrefix(unit, wantPrefix) || !strings.HasSuffix(unit, ".service") {
		t.Fatalf("the helper runs in %q (cgroup %q)", unit, cg)
	}
	return pid, unit
}

// TestCommandDiesWithGateOrHelper: killing the gate, or the helper in
// either unit, while a command runs kills the command at once. The command
// ignores SIGTERM and would sleep for 60 s; the request's own timeout is
// 30 s. The gate runs outside any unit, so nothing but the parent-death
// signal can end its command. When a helper instance dies, systemd stops
// its unit: it sends the unit's KillSignal (SIGTERM, checked) to what is
// left, with no SIGHUP (checked), and SIGKILL only after TimeoutStopSec
// (checked to be at least twice the window). Within the window, only the
// parent-death signal (SIGKILL) ends the command there too.
func TestCommandDiesWithGateOrHelper(t *testing.T) {
	sleepArgs := []string{"ignore-term", "60s"}
	t.Run("gate", func(t *testing.T) {
		g := startGate(t, "/etc/shell-mcp/gate-read.yaml", "e2e-read", "read", "exec", map[string]any{"command_id": "probe-sleep", "args": sleepArgs})
		p := gatetest.FindChild(t, g.Process.Pid, sleepArgs...)
		t.Cleanup(p.Kill)
		p.WaitIgnoring(t, syscall.SIGTERM)
		if err := g.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = g.Wait()
		if !p.WaitGone(pdeathsigWindow) {
			t.Fatalf("the command (pid %d) outlived the gate", p.Pid)
		}
	})
	for _, c := range []struct{ command, unit string }{{"probe-attrs", ""}, {"probe-broad", "broad"}} {
		t.Run("helper-"+c.command, func(t *testing.T) {
			a := map[string]any{"command_id": c.command, "args": sleepArgs}
			if c.unit != "" {
				a["unit"] = c.unit
			}
			g := startGate(t, gatePolicy, "e2e", "destructive", "priv_exec", a)
			p := gatetest.FindChild(t, 0, sleepArgs...)
			t.Cleanup(p.Kill)
			p.WaitIgnoring(t, syscall.SIGTERM)
			helper, unit := helperOf(t, p, c.unit == "broad")
			if got := show(t, unit, "KillSignal"); got != "15" {
				t.Fatalf("%s KillSignal=%s, want 15 (SIGTERM)", unit, got)
			}
			if got := show(t, unit, "SendSIGHUP"); got != "no" {
				t.Fatalf("%s SendSIGHUP=%s", unit, got)
			}
			if got := timespan(t, show(t, unit, "TimeoutStopUSec")); got < 2*pdeathsigWindow {
				t.Fatalf("%s TimeoutStopUSec=%v: systemd's own SIGKILL could end the command within the window", unit, got)
			}
			if err := syscall.Kill(helper, syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
			if !p.WaitGone(pdeathsigWindow) {
				t.Fatalf("the command (pid %d) outlived the helper in %s", p.Pid, unit)
			}
			_ = g.Wait()
		})
	}
}

// statusIDs returns the Uid: and Gid: lines of /proc/<pid>/status.
func statusIDs(t *testing.T, pid int) (uid, gid string) {
	t.Helper()
	for _, l := range strings.Split(readFile(t, fmt.Sprintf("/proc/%d/status", pid)), "\n") {
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			uid = strings.Join(strings.Fields(v), " ")
		}
		if v, ok := strings.CutPrefix(l, "Gid:"); ok {
			gid = strings.Join(strings.Fields(v), " ")
		}
	}
	return uid, gid
}

// TestHelperStopKillsUserSwitchedCommand: a helper command that switches to
// another user loses its parent-death signal (the kernel clears it on the
// credential change), so the helper's death no longer kills it; systemd's
// stop of the instance unit must. The command (broad unit, root with full
// capabilities) ignores SIGTERM, switches every id to an invented uid and
// sleeps for 60 s. Control: it is still running a moment after the helper
// is killed, so no parent-death signal reached it. Then it must be gone
// within the units' TimeoutStopSec (KillMode=control-group: SIGTERM, then
// SIGKILL to everything left in the cgroup), with a few seconds' slack.
func TestHelperStopKillsUserSwitchedCommand(t *testing.T) {
	args := []string{"drop-ignore-term", strconv.Itoa(exampleApp), "60s"}
	g := startGate(t, gatePolicy, "e2e", "destructive", "priv_exec", map[string]any{"command_id": "probe-broad", "args": args, "unit": "broad"})
	p := gatetest.FindChild(t, 0, args...)
	t.Cleanup(p.Kill)
	p.WaitIgnoring(t, syscall.SIGTERM)
	want := strings.Repeat(strconv.Itoa(exampleApp)+" ", 4)
	want = strings.TrimSpace(want)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		uid, gid := statusIDs(t, p.Pid)
		if uid == want && gid == want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the command did not switch user: Uid %q Gid %q", uid, gid)
		}
	}
	helper, unit := helperOf(t, p, true)
	if err := syscall.Kill(helper, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	killed := time.Now()
	time.Sleep(pdeathsigWindow / 2)
	if !p.Alive() {
		t.Fatalf("control: the command died with the helper; its parent-death signal survived the user switch")
	}
	if !p.WaitGone(helperStopTimeout + 3*time.Second - time.Since(killed)) {
		t.Fatalf("the user-switched command (pid %d) still runs %v after the helper in %s died (KillMode=%s, TimeoutStopUSec=%s)",
			p.Pid, time.Since(killed).Round(time.Second), unit, show(t, unit, "KillMode"), show(t, unit, "TimeoutStopUSec"))
	}
	t.Logf("gone %v after the helper died", time.Since(killed).Round(10*time.Millisecond))
	_ = g.Wait()
}
