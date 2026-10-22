//go:build e2e && linux

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/test/e2e/runner"
)

// The package operations end to end (S4c-7): the real server with web
// approval and a simulated human, the real gate, the real helper in its
// broad unit, real apt and dpkg against the local repository of invented
// packages (setup.sh). No network to any mirror.

// TestPackageToolApproval: shell_priv_install_packages previews the
// transaction, is approved, and installs exactly it once; a second re-call
// is approval_invalid; the helper's journal line records what was applied.
func TestPackageToolApproval(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	srv, h := privWriteServer(t)
	args := map[string]any{"packages": []string{"example-hello"}}
	id := pendingID(t, srv.callTool(t, "shell_priv_install_packages", args))
	if strings.HasPrefix(installed(t, "example-hello"), "installed") {
		t.Fatal("installed before approval")
	}
	srv.decide(t, h, id, "approve")
	d := okDataAs(t, srv.callTool(t, "shell_priv_install_packages", withApproval(args, id)), "e2e-ssh")
	if fmt.Sprint(d["applied"]) == "<nil>" || installed(t, "example-hello") != "installed 1.0" {
		t.Fatalf("data %v, dpkg %q", d, installed(t, "example-hello"))
	}
	refusal(t, srv.callTool(t, "shell_priv_install_packages", withApproval(args, id)), "approval_invalid", "")
	j := waitLine(t, "shell-mcp-privd", `"op":"priv_pkg_install"`, `"outcome":"ok"`, `"applied":`, `"example-hello"`)
	if strings.Contains(j.Message, "expected_preview_sha256") || j.Priority != "4" {
		t.Fatalf("journal line %s at priority %s", j.Message, j.Priority)
	}
}

// TestPackageNewVersionAfterApproval: a new version published and indexed
// after approval changes the fresh preview: approval_invalid, nothing
// installed.
func TestPackageNewVersionAfterApproval(t *testing.T) {
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	srv, h := privWriteServer(t)
	args := map[string]any{"packages": []string{"example-hello"}}
	id := pendingID(t, srv.callTool(t, "shell_priv_install_packages", args))
	srv.decide(t, h, id, "approve")
	aptRepo(t, "example-hello_1.0_all.deb", "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
	run(t, "apt-get", "-q", "update")
	refusal(t, srv.callTool(t, "shell_priv_install_packages", withApproval(args, id)), "approval_invalid", "")
	if got := installed(t, "example-hello"); strings.HasPrefix(got, "installed") {
		t.Fatalf("installed after a changed preview: %q", got)
	}
}

// armPkgHook makes the e2e test build of the helper move the repository
// staged by aptRepoNext into place and update the package index (apt-get
// update, run by the helper itself) at stage of its next package operation: "before-pinned-sim" (after the preview's hash was
// recomputed) or "before-run" (after the pinned simulation, before the
// run). The release build has no such hook.
func armPkgHook(t *testing.T, stage string) {
	t.Helper()
	run(t, "install", "-o", "root", "-g", "root", "-m", "0755", filepath.Join(bin(), "shell-mcp-privd-bypass"), privdBin)
	t.Cleanup(func() {
		run(t, "install", "-o", "root", "-g", "root", "-m", "0755", filepath.Join(bin(), "shell-mcp-privd"), privdBin)
		_ = os.Remove(pkgHookFile)
	})
	if err := os.WriteFile(pkgHookFile, []byte(stage), 0o600); err != nil {
		t.Fatal(err)
	}
}

const pkgHookFile = "/run/shell-mcp-e2e-pkg-hook"

// TestPackageChangedBeforeRun: the repository changes after the operation
// recomputed its preview. Between that and the pinned simulation, the
// approved version disappears: exists, nothing installed. Between the
// pinned simulation and the run, a newer version appears: the pinned run
// installs exactly the approved version. Never a silent different
// transaction.
func TestPackageChangedBeforeRun(t *testing.T) {
	t.Run("before-pinned-sim", func(t *testing.T) {
		cleanupPackages(t)
		aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
		mustPkg(t, "update_index", map[string]any{})
		p := pkgPreview(t, "install", helloArgs)
		aptRepoNext(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
		armPkgHook(t, "before-pinned-sim")
		r, _ := gate(t, svcShell, "priv_pkg_install", withHash(helloArgs, p.PreviewSHA256))
		// Refused by the pinned simulation (the recompute still saw the
		// approved transaction): the approved version is gone.
		if r.code() != "exists" || !strings.Contains(r.Error.Message, "pinned") {
			t.Fatalf("answer %s %+v", r.code(), r.Error)
		}
		if got := installed(t, "example-hello"); strings.HasPrefix(got, "installed") {
			t.Fatalf("installed: %q", got)
		}
	})
	t.Run("before-run", func(t *testing.T) {
		cleanupPackages(t)
		aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
		mustPkg(t, "update_index", map[string]any{})
		p := pkgPreview(t, "install", helloArgs)
		aptRepoNext(t, "example-hello_1.0_all.deb", "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
		armPkgHook(t, "before-run")
		r, _ := gate(t, svcShell, "priv_pkg_install", withHash(helloArgs, p.PreviewSHA256))
		// 1.1 is the candidate when the run starts; the pinned run installs
		// the approved 1.0, exactly.
		if got := installed(t, "example-hello"); !r.OK || got != "installed 1.0" {
			t.Fatalf("answer %s %+v, dpkg %q: not the approved transaction", r.code(), r.Error, got)
		}
	})
}

// TestPackageUpgradeExactList: an upgrade installs exactly the approved
// list when more upgrades become available before the run.
func TestPackageUpgradeExactList(t *testing.T) {
	cleanupPackages(t)
	installPolicy(t, "privileged-upgrade.yaml")
	aptRepo(t, "example-hello_1.0_all.deb", "example-extra_1.0_all.deb", "example-conf_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	mustPkg(t, "install", helloArgs)
	mustPkg(t, "install", map[string]any{"packages": []string{"example-conf"}})
	aptRepo(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb", "example-conf_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	p := pkgPreview(t, "upgrade", map[string]any{})
	if len(p.Upgrade) != 1 || p.Upgrade[0].Name != "example-hello" {
		t.Fatalf("upgrade preview %+v", p)
	}
	aptRepoNext(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb", "example-conf_1.0_all.deb", "example-conf_1.1_all.deb")
	armPkgHook(t, "before-run")
	var r pkgResult
	mustGate(t, "priv_pkg_upgrade", map[string]any{"expected_preview_sha256": p.PreviewSHA256}, &r)
	if installed(t, "example-hello") != "installed 1.1" || installed(t, "example-conf") != "installed 1.0" {
		t.Fatalf("after the upgrade: hello %q conf %q", installed(t, "example-hello"), installed(t, "example-conf"))
	}
	if r.Applied == nil || len(r.Applied.Upgrade) != 1 || r.Applied.Upgrade[0].Name != "example-hello" {
		t.Fatalf("applied %+v", r.Applied)
	}
}

// lineClient sends one request to the broad helper as svc-shell and
// returns the first answer line and how long it took to arrive.
func lineClient(t *testing.T, line string) (string, time.Duration) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), self) //nolint:gosec // G204: this test binary itself, in client mode
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
	cmd.Env = append(runner.Env(), "E2E_CLIENT=line", "E2E_SOCKET="+broadSocket)
	cmd.Stdin = strings.NewReader(line)
	start := time.Now()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("client: %v %q", err, out)
	}
	return string(out), time.Since(start)
}

var untilRE = regexp.MustCompile(`may run until \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`)

// installRequest is a priv_pkg_install request line for the broad helper.
func installRequest(t *testing.T, args map[string]any, timeoutMS int) (line, id string) {
	t.Helper()
	b, _ := json.Marshal(args)
	id = newID()
	return fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"destructive","op":"priv_pkg_install","args":%s,"timeout_ms":%d}`+"\n", id, b, timeoutMS), id
}

// TestPackageStopPoints (the maintainer's decision on item 5), in the
// broad unit with max_timeout_s 24 (privileged-pkgstage.yaml: a 6 s stop
// allowance, so SIGINT at 18 s and the kill at 24 s):
//   - early: example-slow (an 8 s postinst): the request's deadline (6 s)
//     gets outcome_unknown at once, naming the request id and the time it
//     may run until; a preview says the operation is in progress; apt-get
//     finishes before the stop point; the journal line has the result;
//   - drop: a gate that goes away mid-run sends no signal: the package is
//     installed and the line records the hang-up;
//   - sigint: example-slow-a's 18 s postinst runs through the 18 s stop
//     point; apt stops before unpacking example-slow-b: a consistent,
//     partial result, verify_failed;
//   - kill: example-stuck's postinst never ends: killed at 24 s, dpkg left
//     unfinished, the next preview names the recovery.
func TestPackageStopPoints(t *testing.T) {
	installPolicy(t, "privileged-pkgstage.yaml")
	setup := func(t *testing.T, names ...string) previewResult {
		t.Helper()
		cleanupPackages(t)
		aptRepo(t, "example-slow_1.0_all.deb", "example-slow-a_1.0_all.deb", "example-slow-b_1.0_all.deb", "example-stuck_1.0_all.deb", "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
		mustPkg(t, "update_index", map[string]any{})
		return pkgPreview(t, "install", map[string]any{"packages": names})
	}
	t.Run("early", func(t *testing.T) {
		p := setup(t, "example-slow")
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-slow"}}, p.PreviewSHA256), 6000)
		out, took := lineClient(t, line)
		if !strings.Contains(out, `"code":"outcome_unknown"`) || !strings.Contains(out, id) || !untilRE.MatchString(out) || took > 10*time.Second {
			t.Fatalf("answer after %v: %s", took, out)
		}
		if r, _ := gate(t, svcShell, "priv_pkg_install_preview", helloArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "package operation in progress") ||
			!strings.Contains(r.Error.Message, id) {
			t.Fatalf("preview during the operation: %s %+v", r.code(), r.Error)
		}
		waitLineFor(t, `"id":"`+id+`"`, `"answered_early":true`, `"outcome":"ok"`, `"applied":`)
		if got := installed(t, "example-slow"); got != "installed 1.0" {
			t.Fatalf("dpkg %q", got)
		}
	})
	t.Run("drop", func(t *testing.T) {
		p := setup(t, "example-slow")
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-slow"}}, p.PreviewSHA256), 20000)
		// At 6 s apt-get is running example-slow's 8 s postinst (a hang-up
		// during the simulations before it would run nothing).
		cl, out := hangupClient(t, "drop", broadSocket, line, 6*time.Second)
		if err := cl.Wait(); err != nil {
			t.Fatalf("client: %v %q", err, out.String())
		}
		// The outcome, not only the journal line: the instance that served
		// this connection ended on its own after apt-get finished, the
		// package is fully installed, and the line has the result.
		inst := helperInstance(t, cl.Process.Pid)
		defer func() {
			if t.Failed() {
				dropDiagnostics(t, inst, id)
			}
		}()
		end, endAt := instanceEnd(t, inst, 45*time.Second)
		if strings.Contains(end, "code=killed") || strings.Contains(end, "code=dumped") || strings.Contains(end, "signal") {
			t.Errorf("the helper instance did not exit normally: %s", end)
		}
		if out := run(t, "dpkg", "--audit"); strings.TrimSpace(out) != "" {
			t.Errorf("dpkg --audit after the drop: %s", out)
		}
		if got := installed(t, "example-slow"); got != "installed 1.0" {
			t.Errorf("example-slow after the drop: %q, want installed 1.0", got)
		}
		if at, ok := dpkgInstalledAt("example-slow"); !ok || endAt.Truncate(time.Second).Before(at) {
			t.Errorf("the helper instance ended at %v, before dpkg recorded example-slow installed (%v, found %v)", endAt, at, ok)
		}
		if _, ok := findLine(id, `"hung_up":true`, `"answered_early":true`, `"outcome":"ok"`); !ok {
			t.Errorf("no helper journal line for %s with hung_up, answered_early and outcome ok", id)
		}
	})
	t.Run("sigint", func(t *testing.T) {
		p := setup(t, "example-slow-b")
		if len(p.Install) != 2 {
			t.Fatalf("preview %+v", p)
		}
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-slow-b"}}, p.PreviewSHA256), 6000)
		out, _ := lineClient(t, line)
		if !strings.Contains(out, `"code":"outcome_unknown"`) {
			t.Fatalf("answer %s", out)
		}
		j := waitLineFor(t, `"id":"`+id+`"`, `"stopped":"sigint"`, `"outcome":"verify_failed"`)
		if strings.Contains(j.Message, `"unfinished"`) {
			t.Fatalf("the graceful stop left dpkg unfinished: %s", j.Message)
		}
		if a, b := installed(t, "example-slow-a"), installed(t, "example-slow-b"); a != "installed 1.0" || strings.HasPrefix(b, "installed") {
			t.Fatalf("slow-a %q slow-b %q, want slow-a only", a, b)
		}
		if out := run(t, "dpkg", "--audit"); strings.TrimSpace(out) != "" {
			t.Fatalf("dpkg --audit: %s", out)
		}
	})
	t.Run("kill", func(t *testing.T) {
		p := setup(t, "example-stuck")
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-stuck"}}, p.PreviewSHA256), 6000)
		start := time.Now()
		lineClient(t, line)
		j := waitLineFor(t, `"id":"`+id+`"`, `"stopped":"killed"`, `"outcome":"verify_failed"`, `"unfinished":["example-stuck"]`)
		// The kill at 24 s, its 2 s grace and the reaping, well inside
		// RuntimeMaxSec (54 s): the instance ended on its own.
		if d := time.Since(start); d > 50*time.Second {
			t.Fatalf("the line came %v after the request", d)
		}
		if strings.Contains(j.Message, "Failed with result 'timeout'") {
			t.Fatalf("systemd stopped the instance: %s", j.Message)
		}
		if r, _ := gate(t, svcShell, "priv_pkg_install_preview", helloArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "dpkg --configure -a") {
			t.Fatalf("preview after the kill: %s %+v", r.code(), r.Error)
		}
	})
}

// waitLineFor is waitLine for the helper's journal with a longer bound (45 s):
// a package operation's line comes when it ends, up to its max_timeout_s
// and the kill after the request.
func waitLineFor(t *testing.T, want ...string) journalEntry {
	t.Helper()
	const d = 45 * time.Second
	deadline := time.Now().Add(d)
	for {
	entries:
		for _, e := range journal(t, "shell-mcp-privd", runStart) {
			for _, w := range want {
				if !strings.Contains(e.Message, w) {
					continue entries
				}
			}
			return e
		}
		if time.Now().After(deadline) {
			t.Fatalf("no shell-mcp-privd journal entry within %v containing %q", d, want)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// rawJournal returns every journal entry since the run started that
// matches the journalctl arguments, as field maps (a field that is not
// valid text, which journald writes as a byte array, is left out).
func rawJournal(t *testing.T, match ...string) []map[string]string {
	t.Helper()
	args := append([]string{"--no-pager", "-o", "json", "--since", "@" + strconv.FormatInt(runStart.Unix()-1, 10)}, match...)
	out, err := exec.CommandContext(t.Context(), "journalctl", args...).Output() //nolint:gosec // G204: fixed test command and matches
	if err != nil {
		t.Logf("journalctl %q: %v", match, err)
		return nil
	}
	var es []map[string]string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var raw map[string]any
		if json.Unmarshal(sc.Bytes(), &raw) != nil {
			continue
		}
		e := map[string]string{}
		for k, v := range raw {
			if s, ok := v.(string); ok {
				e[k] = s
			}
		}
		es = append(es, e)
	}
	return es
}

// helperInstance is the broad unit instance systemd started for the
// connection of the client with pid: Accept=yes names a per-connection
// instance <socket>@<n>-<peer pid>-<peer uid>.service.
func helperInstance(t *testing.T, pid int) string {
	t.Helper()
	re := regexp.MustCompile(`^shell-mcp-privd-broad@[0-9]+-` + strconv.Itoa(pid) + `-[0-9]+\.service$`)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range rawJournal(t, "-t", "shell-mcp-privd") {
			if re.MatchString(e["_SYSTEMD_UNIT"]) {
				return e["_SYSTEMD_UNIT"]
			}
		}
		for _, e := range rawJournal(t, "-t", "systemd") {
			if re.MatchString(e["UNIT"]) {
				return e["UNIT"]
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("no broad helper instance for client pid %d", pid)
	return ""
}

// instanceEnd waits up to d for systemd's record of how inst's main
// process ended, and returns its messages and when it ended.
func instanceEnd(t *testing.T, inst string, d time.Duration) (string, time.Time) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		var msgs []string
		var at time.Time
		done := false
		for _, e := range rawJournal(t, "UNIT="+inst) {
			m := e["MESSAGE"]
			if strings.Contains(m, "Main process exited") || strings.Contains(m, "Deactivated successfully") || strings.Contains(m, "Failed with result") {
				msgs = append(msgs, m)
				if us, err := strconv.ParseInt(e["__REALTIME_TIMESTAMP"], 10, 64); err == nil && at.IsZero() {
					at = time.UnixMicro(us)
				}
				done = true
			}
		}
		if done {
			return strings.Join(msgs, " | "), at
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s did not end within %v", inst, d)
	return "", time.Time{}
}

// dpkgInstalledAt is when /var/log/dpkg.log last recorded pkg installed.
func dpkgInstalledAt(pkg string) (time.Time, bool) {
	b, err := os.ReadFile("/var/log/dpkg.log")
	if err != nil {
		return time.Time{}, false
	}
	var at time.Time
	found := false
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 5 && f[2] == "status" && f[3] == "installed" && strings.HasPrefix(f[4], pkg+":") {
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", f[0]+" "+f[1], time.Local); err == nil {
				at, found = t, true
			}
		}
	}
	return at, found
}

// findLine looks for the helper's journal line of request id holding every
// string in want.
func findLine(id string, want ...string) (string, bool) {
	out, err := exec.Command("journalctl", "--no-pager", "-o", "cat", "-t", "shell-mcp-privd", //nolint:gosec,noctx // G204: fixed test command; a bounded local call
		"--since", "@"+strconv.FormatInt(runStart.Unix()-1, 10)).Output()
	if err != nil {
		return "", false
	}
lines:
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, `"id":"`+id+`"`) {
			continue
		}
		for _, w := range want {
			if !strings.Contains(l, w) {
				continue lines
			}
		}
		return l, true
	}
	return "", false
}

// dropDiagnostics prints what the drop test needs to explain a failure:
// every journal entry of the helper instance and of the request (not the
// last N lines), dpkg's view of example-slow and its log.
func dropDiagnostics(t *testing.T, inst, id string) {
	t.Helper()
	for _, match := range [][]string{{"_SYSTEMD_UNIT=" + inst}, {"UNIT=" + inst}} {
		for _, e := range rawJournal(t, match...) {
			t.Logf("journal %s %s pid=%s: %s", match[0], e["__REALTIME_TIMESTAMP"], e["_PID"], e["MESSAGE"])
		}
	}
	if l, ok := findLine(id); ok {
		t.Logf("helper line for %s: %s", id, l)
	} else {
		t.Logf("no helper line carries request id %s", id)
	}
	for _, args := range [][]string{{"dpkg", "-s", "example-slow"}, {"dpkg", "--audit"}} {
		out, err := exec.CommandContext(t.Context(), args[0], args[1:]...).CombinedOutput() //nolint:gosec // G204: fixed test commands
		t.Logf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	if b, err := os.ReadFile("/var/log/dpkg.log"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "example-slow") {
				t.Logf("dpkg.log: %s", l)
			}
		}
	}
}
