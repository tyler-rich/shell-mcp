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
)

// The broad unit, the apt operations, the core unit's hardening and
// priv_power, against the runner's own systemd and apt (setup.sh). Every
// restriction is shown two-sided.

// ---- Local apt repository ------------------------------------------------------

// aptRepo makes /srv/e2e-apt a flat repository holding exactly the given
// packages (built by setup.sh from invented control data): the .deb files,
// a Packages index and an unsigned Release file, which the source's
// [trusted=yes] accepts. No internet is involved.
func aptRepo(t *testing.T, debs ...string) {
	t.Helper()
	// Each Release file's Date must be newer than the last one apt saw.
	time.Sleep(1100 * time.Millisecond)
	ents, err := os.ReadDir(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.Remove(filepath.Join(repoDir, e.Name())); err != nil {
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
		if err := os.WriteFile(filepath.Join(repoDir, d), b, 0o644); err != nil { //nolint:gosec // G306: apt's unprivileged methods read the repository
			t.Fatal(err)
		}
		control := strings.TrimRight(run(t, "dpkg-deb", "-f", src), "\n")
		sum := sha256.Sum256(b)
		fmt.Fprintf(&index, "%s\nFilename: ./%s\nSize: %d\nSHA256: %s\n\n", control, d, len(b), hex.EncodeToString(sum[:]))
	}
	pkgs := []byte(index.String())
	if err := os.WriteFile(filepath.Join(repoDir, "Packages"), pkgs, 0o644); err != nil { //nolint:gosec // G306: read by apt
		t.Fatal(err)
	}
	sum := sha256.Sum256(pkgs)
	release := fmt.Sprintf("Origin: shell-mcp-e2e\nLabel: shell-mcp-e2e\nSuite: e2e\nCodename: e2e\nDate: %s\nArchitectures: all amd64 arm64\nSHA256:\n %s %d Packages\n",
		time.Now().UTC().Format(time.RFC1123), hex.EncodeToString(sum[:]), len(pkgs))
	if err := os.WriteFile(filepath.Join(repoDir, "Release"), []byte(release), 0o644); err != nil { //nolint:gosec // G306: read by apt
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
// the helper) when the test ends.
func cleanupPackages(t *testing.T) {
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "dpkg", "--purge", "example-hello", "example-extra", "example-other").Run()
	})
}

type previewResult struct {
	Install []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"install"`
	Upgrade []struct {
		Name string `json:"name"`
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"upgrade"`
	Remove []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"remove"`
	Complete bool `json:"complete"`
}

type pkgResult struct {
	ExitCode *int   `json:"exit_code"`
	Stderr   string `json:"stderr"`
}

func mustPkg(t *testing.T, op string, args any) {
	t.Helper()
	var r pkgResult
	mustGate(t, op, args, &r)
	if r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("%s: exit %v, stderr %q", op, r.ExitCode, r.Stderr)
	}
}

// Update the index, preview then install an allow-listed package (without
// its Recommends), refuse the others, preview then remove it; upgrade is
// refused while allow_upgrade is false.
func TestPackages(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb", "example-other_1.0_all.deb")
	mustPkg(t, "priv_pkg_update_index", map[string]any{})

	var p previewResult
	mustGate(t, "priv_pkg_install_preview", map[string]any{"packages": []string{"example-hello"}}, &p)
	if len(p.Install) != 1 || p.Install[0].Name != "example-hello" || p.Install[0].Version != "1.0" || len(p.Upgrade)+len(p.Remove) != 0 || !p.Complete {
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
		wantGate(t, svcShell, "priv_pkg_install", map[string]any{"packages": []string{name}}, "policy_denied")
		wantGate(t, svcShell, "priv_pkg_install_preview", map[string]any{"packages": []string{name}}, "policy_denied")
	}
	mustPkg(t, "priv_pkg_install", map[string]any{"packages": []string{"example-hello"}})
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

	wantGate(t, svcShell, "priv_pkg_upgrade", map[string]any{}, "policy_denied")
	wantGate(t, svcShell, "priv_pkg_upgrade_preview", map[string]any{}, "policy_denied")

	mustGate(t, "priv_pkg_remove_preview", map[string]any{"packages": []string{"example-hello"}}, &p)
	if len(p.Remove) != 1 || p.Remove[0].Name != "example-hello" || p.Remove[0].Version != "1.0" || len(p.Install) != 0 {
		t.Fatalf("remove preview %+v", p)
	}
	if got := installed(t, "example-hello"); got != "installed 1.0" {
		t.Fatalf("the remove preview removed something: %q", got)
	}
	mustPkg(t, "priv_pkg_remove", map[string]any{"packages": []string{"example-hello"}})
	if got := installed(t, "example-hello"); strings.HasPrefix(got, "installed") {
		t.Fatalf("example-hello still installed: %q", got)
	}
	if _, err := os.Stat("/usr/share/example-hello/version"); err == nil {
		t.Fatal("the removed package's file is still there")
	}
}

// With allow_upgrade: true and a newer version in the repository, the
// upgrade preview shows 1.0 → 1.1 and the upgrade installs it.
func TestPackageUpgrade(t *testing.T) {
	cleanupPackages(t)
	installPolicy(t, "privileged-upgrade.yaml")
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "priv_pkg_update_index", map[string]any{})
	mustPkg(t, "priv_pkg_install", map[string]any{"packages": []string{"example-hello"}})
	aptRepo(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "priv_pkg_update_index", map[string]any{})
	var p previewResult
	mustGate(t, "priv_pkg_upgrade_preview", map[string]any{}, &p)
	if len(p.Upgrade) != 1 || p.Upgrade[0].Name != "example-hello" || p.Upgrade[0].From != "1.0" || p.Upgrade[0].To != "1.1" {
		t.Fatalf("upgrade preview %+v", p)
	}
	if got := installed(t, "example-hello"); got != "installed 1.0" {
		t.Fatalf("the preview upgraded: %q", got)
	}
	mustPkg(t, "priv_pkg_upgrade", map[string]any{})
	if got := installed(t, "example-hello"); got != "installed 1.1" {
		t.Fatalf("after the upgrade: %q", got)
	}
}

// A held dpkg frontend lock is waited for — bounded by half the request's
// timeout — and reported clearly; once released, the same install works.
func TestPackageLock(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "priv_pkg_update_index", map[string]any{})
	f, err := os.OpenFile("/var/lib/dpkg/lock-frontend", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatalf("taking the dpkg frontend lock: %v", err)
	}
	start := time.Now()
	r, _ := gate(t, svcShell, "priv_pkg_install", map[string]any{"packages": []string{"example-hello"}})
	if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "locked") {
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
	mustPkg(t, "priv_pkg_install", map[string]any{"packages": []string{"example-hello"}})
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

// ProtectProc=invisible hides other users' processes from core-unit
// commands (the helper is root but has no CAP_SYS_PTRACE); a core-unit
// command declaring CAP_KILL turns it to default, and the process is seen.
func TestCoreProtectProc(t *testing.T) {
	pid := strconv.Itoa(sleeperAs(t, svcOther))
	if out := strings.TrimSpace(run(t, probeBin, "visible", pid)); out != "VISIBLE" {
		t.Fatalf("control: %s", out)
	}
	if got := show(t, "shell-mcp-privd@e2e.service", "ProtectProc"); got != "invisible" {
		t.Fatalf("ProtectProc=%s", got)
	}
	if got := show(t, "shell-mcp-privd@e2e.service", "ProcSubset"); got != "pid" {
		t.Fatalf("ProcSubset=%s", got)
	}
	if got := privExec(t, "probe-visible", "", "visible", pid); got != "ENOENT" {
		t.Fatalf("with ProtectProc=invisible: %q, want ENOENT", got)
	}
	installPolicy(t, "privileged-cap-kill.yaml")
	if got := show(t, "shell-mcp-privd@e2e.service", "ProtectProc"); got != "default" {
		t.Fatalf("with CAP_KILL, ProtectProc=%s", got)
	}
	if got := privExec(t, "probe-visible", "", "visible", pid); got != "VISIBLE" {
		t.Fatalf("with CAP_KILL: %q, want VISIBLE", got)
	}
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

func wrongUnit(t *testing.T, socket, op string, args any) {
	t.Helper()
	a, _ := json.Marshal(args)
	id := newID()
	out := directTo(t, svcShell, socket, fmt.Sprintf(`{"v":1,"id":%q,"op":%q,"args":%s,"timeout_ms":30000}`+"\n", id, op, a))
	var r response
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.code() != "helper_wrong_unit" || r.ID != id {
		t.Fatalf("%s %s on %s: %q", op, a, socket, out)
	}
}

// A request that reaches the wrong helper instance — whatever sent it
// there — is refused with helper_wrong_unit and never executed.
func TestMisroutedRequestsRefused(t *testing.T) {
	start := time.Now()
	wrongUnit(t, broadSocket, "priv_stat", map[string]any{"path": "/etc/example-app"})
	wrongUnit(t, broadSocket, "priv_exec", map[string]any{"command_id": "probe-echo", "args": []string{"echo", "core"}})
	wrongUnit(t, socketPath, "priv_pkg_update_index", map[string]any{})
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
	e := findJournal(t, "shell-mcp-privd", start, `"outcome":"helper_wrong_unit"`, `"op":"priv_pkg_update_index"`)
	if e.Priority != "5" || !strings.HasPrefix(e.Unit, "shell-mcp-privd@") {
		t.Fatalf("core refusal logged at %s by %s", e.Priority, e.Unit)
	}
	e = findJournal(t, "shell-mcp-privd", start, `"outcome":"helper_wrong_unit"`, `"op":"priv_stat"`)
	if e.Priority != "4" || !strings.HasPrefix(e.Unit, "shell-mcp-privd-broad@") {
		t.Fatalf("broad refusal logged at %s by %s", e.Priority, e.Unit)
	}
}

// ---- priv_power ---------------------------------------------------------------------

// priv_power reaches systemd and is authorized, without rebooting the
// runner: reboot.target and poweroff.target are runtime-masked first (and
// the test refuses to go on unless systemd reports them masked), so
// systemd authorizes the StartUnit call — the caller is root — and then
// refuses it because the target is masked (the masked check comes after
// authorization: bus_unit_method_start_generic, then the transaction,
// systemd 257 and 259). An unprivileged caller making the same call is
// refused by the authorization itself, before the target is looked at.
func TestPowerReachesSystemd(t *testing.T) {
	run(t, "systemctl", "mask", "--runtime", "reboot.target", "poweroff.target")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "systemctl", "unmask", "--runtime", "reboot.target", "poweroff.target").Run()
	})
	for _, u := range []string{"reboot.target", "poweroff.target"} {
		if got := show(t, u, "LoadState"); got != "masked" {
			t.Fatalf("%s LoadState=%q after masking: refusing to call priv_power", u, got)
		}
	}
	start := time.Now()
	r, id := gate(t, svcShell, "priv_power", map[string]any{"action": "reboot"})
	if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "org.freedesktop.systemd1.UnitMasked") {
		t.Fatalf("priv_power: %s %+v, want exec_failed naming UnitMasked", r.code(), r.Error)
	}
	e := findJournal(t, "shell-mcp-privd", start, `"id":"`+id+`"`, `"op":"priv_power"`, `"action":"reboot"`)
	if e.Priority != "4" || !strings.HasPrefix(e.Unit, "shell-mcp-privd-broad@") {
		t.Fatalf("priv_power logged at %s by %s", e.Priority, e.Unit)
	}
	// poweroff is not in the policy's power.allowed.
	wantGate(t, svcShell, "priv_power", map[string]any{"action": "poweroff"}, "policy_denied")
	// Control: the same call from an unprivileged account is refused by
	// systemd's authorization, not by the masked target.
	c := exec.CommandContext(t.Context(), "busctl", "--system", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager", "StartUnit", "ss", "reboot.target", "replace-irreversibly")
	c.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcOther)}
	out, err := c.CombinedOutput()
	refused := strings.Contains(string(out), "ccess denied") || strings.Contains(string(out), "nteractive authentication required")
	if err == nil || strings.Contains(string(out), "masked") || !refused {
		t.Fatalf("unprivileged StartUnit: %v %q", err, out)
	}
}
