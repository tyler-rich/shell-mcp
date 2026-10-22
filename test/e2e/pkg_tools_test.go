//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// armPkgHook makes the e2e test build of the helper update the package
// index (apt-get update, run by the helper itself) at stage of its next
// package operation: "before-pinned-sim" (after the preview's hash was
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
		armPkgHook(t, "before-pinned-sim")
		aptRepo(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
		r, _ := gate(t, svcShell, "priv_pkg_install", withHash(helloArgs, p.PreviewSHA256))
		if r.code() != "exists" {
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
		armPkgHook(t, "before-run")
		aptRepo(t, "example-hello_1.0_all.deb", "example-hello_1.1_all.deb", "example-extra_1.0_all.deb")
		r, _ := gate(t, svcShell, "priv_pkg_install", withHash(helloArgs, p.PreviewSHA256))
		switch got := installed(t, "example-hello"); {
		case r.OK && got == "installed 1.0":
		case !r.OK && (r.code() == "exists" || r.code() == "verify_failed" || r.code() == "exec_failed") && !strings.HasPrefix(got, "installed 1.1"):
		default:
			t.Fatalf("answer %s %+v, dpkg %q: a different transaction ran", r.code(), r.Error, got)
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
	armPkgHook(t, "before-run")
	aptRepo(t, "example-hello_1.1_all.deb", "example-extra_1.0_all.deb", "example-conf_1.0_all.deb", "example-conf_1.1_all.deb")
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
//   - early: example-slow (an 8 s postinst): the request's deadline (3 s)
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
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-slow"}}, p.PreviewSHA256), 3000)
		out, took := lineClient(t, line)
		if !strings.Contains(out, `"code":"outcome_unknown"`) || !strings.Contains(out, id) || !untilRE.MatchString(out) || took > 8*time.Second {
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
		cl, out := hangupClient(t, "drop", broadSocket, line, 3*time.Second)
		if err := cl.Wait(); err != nil {
			t.Fatalf("client: %v %q", err, out.String())
		}
		waitLineFor(t, `"id":"`+id+`"`, `"hung_up":true`, `"answered_early":true`, `"outcome":"ok"`)
		if got := installed(t, "example-slow"); got != "installed 1.0" {
			t.Fatalf("dpkg %q", got)
		}
	})
	t.Run("sigint", func(t *testing.T) {
		p := setup(t, "example-slow-b")
		if len(p.Install) != 2 {
			t.Fatalf("preview %+v", p)
		}
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-slow-b"}}, p.PreviewSHA256), 3000)
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
		line, id := installRequest(t, withHash(map[string]any{"packages": []string{"example-stuck"}}, p.PreviewSHA256), 3000)
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
