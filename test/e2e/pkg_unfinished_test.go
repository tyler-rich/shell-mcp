//go:build e2e && linux

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// What the recovery leaves, end to end (handoff N-36, S7-7): real apt and
// dpkg in the broad unit under privileged-recover.yaml (max_timeout_s 24),
// with the invented packages of setup.sh: example-needs, whose dependency
// no repository has, left unpacked; and example-reinst, whose preinst and
// postrm fail while pkgFail exists, left half-installed and flagged
// reinstreq (measured on Debian 13 and Ubuntu 26.04).

// pkgFail makes example-reinst's preinst and postrm fail.
const pkgFail = "/run/shell-mcp-e2e-pkg-fail"

// reinstreqOnHost leaves example-reinst half-installed and reinstreq, as
// an install whose preinst and cleanup both failed does (dpkg -i on the
// runner, outside the helper).
func reinstreqOnHost(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(pkgFail, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dpkg", "-i", filepath.Join(bin(), "debs", "example-reinst_1.0_all.deb")).CombinedOutput() //nolint:gosec // G204: setup.sh's own package
	_ = os.Remove(pkgFail)
	if err == nil {
		t.Fatalf("dpkg -i example-reinst succeeded with its preinst failing:\n%s", out)
	}
	if got := status(t, "example-reinst"); got != "install reinstreq half-installed 1.0" {
		t.Fatalf("example-reinst %q after the failed install:\n%s", got, out)
	}
}

// status is dpkg's full status (want, flag, state) and version of pkg.
func status(t *testing.T, pkg string) string {
	t.Helper()
	out, _ := exec.CommandContext(t.Context(), "dpkg-query", "-W", "-f=${Status} ${Version}", pkg).Output() //nolint:gosec // G204: fixed test package names
	return strings.TrimSpace(string(out))
}

type unfinishedEntry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	State          string   `json:"state"`
	Flag           string   `json:"flag"`
	MissingDepends []string `json:"missing_depends"`
}

type unfinishedPreviewResult struct {
	previewResult
	Unfinished []unfinishedEntry `json:"unfinished"`
}

type reinstallPreviewResult struct {
	Op            string            `json:"op"`
	Reinstall     []unfinishedEntry `json:"reinstall"`
	Argv          []string          `json:"argv"`
	PreviewSHA256 string            `json:"preview_sha256"`
}

var (
	needsArgs  = map[string]any{"packages": []string{"example-needs"}}
	reinstArgs = map[string]any{"packages": []string{"example-reinst"}}
)

func auditClean(t *testing.T) {
	t.Helper()
	if out := run(t, "dpkg", "--audit"); strings.TrimSpace(out) != "" {
		t.Fatalf("dpkg --audit: %s", out)
	}
}

// TestPackageRemoveMissingDependency (U1, M2): a package whose dependency
// no repository has is removed through shell_priv_remove_packages naming
// exactly it. The preview shows its version and state; the approval page
// does too; the approved removal runs once; dpkg's database is clean; a
// second re-call is approval_invalid.
func TestPackageRemoveMissingDependency(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	unpackOnHost(t, "example-needs_1.0_all.deb")
	var p unfinishedPreviewResult
	mustGate(t, "priv_pkg_remove_preview", needsArgs, &p)
	if len(p.Remove) != 1 || p.Remove[0].Name != "example-needs" || p.Remove[0].Version != "1.0" || len(p.Unfinished) != 1 ||
		p.Unfinished[0].State != "unpacked" || p.Unfinished[0].Version != "1.0" || !slices.Equal(p.Unfinished[0].MissingDepends, []string{"example-absent"}) {
		t.Fatalf("preview %+v", p)
	}
	srv, h := privWriteServer(t)
	id := pendingID(t, srv.callTool(t, "shell_priv_remove_packages", needsArgs))
	if got := status(t, "example-needs"); got != "install ok unpacked 1.0" {
		t.Fatalf("example-needs %q before approval", got)
	}
	srv.decide(t, h, id, "approve")
	d := okDataAs(t, srv.callTool(t, "shell_priv_remove_packages", withApproval(needsArgs, id)), "e2e-ssh")
	if a, _ := d["applied"].(map[string]any); a == nil || fmt.Sprint(a["remove"]) != "[map[name:example-needs version:1.0]]" {
		t.Fatalf("data %v", d)
	}
	if got := installed(t, "example-needs"); strings.HasPrefix(got, "installed") || strings.HasPrefix(got, "unpacked") {
		t.Fatalf("example-needs %q after the removal", got)
	}
	auditClean(t)
	refusal(t, srv.callTool(t, "shell_priv_remove_packages", withApproval(needsArgs, id)), "approval_invalid", "")
	waitLine(t, "shell-mcp-privd", `"op":"priv_pkg_remove"`, `"outcome":"ok"`, `"example-needs"`)
}

// TestPackageRemoveUnfinishedExactSet: with another package to configure
// also unfinished, a removal of example-needs alone is refused at the
// preview, naming both and what each needs; nothing changes.
func TestPackageRemoveUnfinishedExactSet(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	unpackOnHost(t, "example-needs_1.0_all.deb")
	unpackOnHost(t, "example-hello_1.0_all.deb")
	r, _ := gate(t, svcShell, "priv_pkg_remove_preview", needsArgs)
	if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "exactly") || !strings.Contains(r.Error.Message, "example-hello") ||
		!strings.Contains(r.Error.Message, "priv_pkg_recover") {
		t.Fatalf("preview %s %+v", r.code(), r.Error)
	}
	if got := status(t, "example-needs"); got != "install ok unpacked 1.0" {
		t.Fatalf("example-needs %q", got)
	}
}

// TestPackageRemoveUnfinishedStateChanged: the unfinished package is deselected
// on the host between the preview and the run (its want becomes deinstall;
// a hold would make apt refuse the removal instead, measured): the
// removal is exists, and nothing runs.
func TestPackageRemoveUnfinishedStateChanged(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	unpackOnHost(t, "example-needs_1.0_all.deb")
	p := pkgPreview(t, "remove", needsArgs)
	setSelection(t, "example-needs", "deinstall")
	r, id := gateAt(t, svcShell, "destructive", "priv_pkg_remove", withHash(needsArgs, p.PreviewSHA256))
	if r.code() != "exists" || !strings.Contains(r.Error.Message, "nothing was run") {
		t.Fatalf("answer %s %+v", r.code(), r.Error)
	}
	waitLine(t, "shell-mcp-privd", `"id":"`+id+`"`, `"outcome":"exists"`)
	if got := status(t, "example-needs"); got != "deinstall ok unpacked 1.0" {
		t.Fatalf("example-needs %q", got)
	}
}

// setSelection sets a package's want on the host (dpkg --set-selections).
func setSelection(t *testing.T, pkg, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "dpkg", "--set-selections") //nolint:gosec // G204: fixed test command
	c.Stdin = strings.NewReader(pkg + " " + want + "\n")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("dpkg --set-selections: %v\n%s", err, out)
	}
}

// TestPackageRemoveLeavesReinstall (M1): with example-reinst needing a
// reinstall (its archive in the index) and example-needs missing its
// dependency, a removal of example-needs alone runs and leaves
// example-reinst as it was, which is not a verify_failed; the reinstall
// then finishes it.
func TestPackageRemoveLeavesReinstall(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	aptRepo(t, "example-reinst_1.0_all.deb", "example-hello_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	reinstreqOnHost(t)
	unpackOnHost(t, "example-needs_1.0_all.deb")
	var p unfinishedPreviewResult
	mustGate(t, "priv_pkg_remove_preview", needsArgs, &p)
	if len(p.Unfinished) != 2 || len(p.Remove) != 1 {
		t.Fatalf("preview %+v", p)
	}
	r, _ := gateAt(t, svcShell, "destructive", "priv_pkg_remove", withHash(needsArgs, p.PreviewSHA256))
	if !r.OK {
		t.Fatalf("removal %s %+v", r.code(), r.Error)
	}
	if got := status(t, "example-reinst"); got != "install reinstreq half-installed 1.0" {
		t.Fatalf("example-reinst %q after the removal", got)
	}
	released(t)
	var rp reinstallPreviewResult
	mustGate(t, "priv_pkg_reinstall_preview", reinstArgs, &rp)
	if r, _ := gateAt(t, svcShell, "operator", "priv_pkg_reinstall", withHash(reinstArgs, rp.PreviewSHA256)); !r.OK {
		t.Fatalf("reinstall %s %+v", r.code(), r.Error)
	}
	if got := status(t, "example-reinst"); got != "install ok installed 1.0" {
		t.Fatalf("example-reinst %q after the reinstall", got)
	}
	auditClean(t)
}

// TestPackageReinstall: a half-installed, reinstreq package: the install
// preview's refusal names the reinstall; shell_priv_reinstall_packages
// previews it pinned to its version, is approved, reinstalls it once and
// answers from dpkg's state; a second re-call is approval_invalid.
func TestPackageReinstall(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	aptRepo(t, "example-reinst_1.0_all.deb", "example-hello_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	reinstreqOnHost(t)
	released(t)
	if r, _ := gate(t, svcShell, "priv_pkg_install_preview", helloArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "priv_pkg_reinstall") ||
		strings.Contains(r.Error.Message, "or removes them") {
		t.Fatalf("install preview: %s %+v", r.code(), r.Error)
	}
	var p reinstallPreviewResult
	mustGate(t, "priv_pkg_reinstall_preview", reinstArgs, &p)
	if p.Op != "reinstall" || len(p.Reinstall) != 1 || p.Reinstall[0].State != "half-installed" || p.Reinstall[0].Flag != "reinstreq" ||
		!slices.Contains(p.Argv, "--reinstall") || p.Argv[len(p.Argv)-1] != "example-reinst=1.0" {
		t.Fatalf("preview %+v", p)
	}
	srv, h := privWriteServer(t)
	id := pendingID(t, srv.callTool(t, "shell_priv_reinstall_packages", reinstArgs))
	if got := status(t, "example-reinst"); got != "install reinstreq half-installed 1.0" {
		t.Fatalf("reinstalled before approval: %q", got)
	}
	srv.decide(t, h, id, "approve")
	d := okDataAs(t, srv.callTool(t, "shell_priv_reinstall_packages", withApproval(reinstArgs, id)), "e2e-ssh")
	if re, _ := d["reinstalled"].([]any); len(re) != 1 || fmt.Sprint(re[0].(map[string]any)["name"]) != "example-reinst" {
		t.Fatalf("data %v", d)
	}
	if got := status(t, "example-reinst"); got != "install ok installed 1.0" {
		t.Fatalf("example-reinst %q after the reinstall", got)
	}
	auditClean(t)
	refusal(t, srv.callTool(t, "shell_priv_reinstall_packages", withApproval(reinstArgs, id)), "approval_invalid", "")
	j := waitLine(t, "shell-mcp-privd", `"op":"priv_pkg_reinstall"`, `"outcome":"ok"`, `"reinstalled":["example-reinst"]`)
	if strings.Contains(j.Message, "expected_preview_sha256") || j.Priority != "4" {
		t.Fatalf("journal line %s at priority %s", j.Message, j.Priority)
	}
}

// TestPackageReinstallNoArchive: with no archive of the version in the
// index, the preview is refused (apt: "can't find an archive"), and the
// tool answers that with no approval requested.
func TestPackageReinstallNoArchive(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	aptRepo(t, "example-hello_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	reinstreqOnHost(t)
	r, _ := gate(t, svcShell, "priv_pkg_reinstall_preview", reinstArgs)
	if r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "find an archive") {
		t.Fatalf("preview %s %+v", r.code(), r.Error)
	}
	srv, _ := privWriteServer(t)
	env := srv.callTool(t, "shell_priv_reinstall_packages", reinstArgs)
	if env["approval"] != nil {
		t.Fatalf("an approval was requested: %v", env)
	}
	refusal(t, env, "exec_failed", "find an archive")
}

// TestPackageReinstallStateChanged: after approval the package is deselected
// on the host: the re-call is approval_invalid; sent straight to
// the gate with the old hash it is exists; nothing runs either way.
func TestPackageReinstallStateChanged(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	aptRepo(t, "example-reinst_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	reinstreqOnHost(t)
	released(t)
	var p reinstallPreviewResult
	mustGate(t, "priv_pkg_reinstall_preview", reinstArgs, &p)
	srv, h := privWriteServer(t)
	id := pendingID(t, srv.callTool(t, "shell_priv_reinstall_packages", reinstArgs))
	srv.decide(t, h, id, "approve")
	setSelection(t, "example-reinst", "deinstall")
	refusal(t, srv.callTool(t, "shell_priv_reinstall_packages", withApproval(reinstArgs, id)), "approval_invalid", "")
	r, rid := gateAt(t, svcShell, "operator", "priv_pkg_reinstall", withHash(reinstArgs, p.PreviewSHA256))
	if r.code() != "exists" || !strings.Contains(r.Error.Message, "nothing was run") {
		t.Fatalf("answer %s %+v", r.code(), r.Error)
	}
	waitLine(t, "shell-mcp-privd", `"id":"`+rid+`"`, `"outcome":"exists"`)
	if got := status(t, "example-reinst"); got != "deinstall reinstreq half-installed 1.0" {
		t.Fatalf("example-reinst %q", got)
	}
}

// reinstallRequest is a priv_pkg_reinstall request line for the broad
// helper.
func reinstallRequest(hash string, timeoutMS int) (line, id string) {
	b, _ := json.Marshal(withHash(reinstArgs, hash))
	id = newID()
	return fmt.Sprintf(`{"v":2,"id":%q,"ceiling":"operator","op":"priv_pkg_reinstall","args":%s,"timeout_ms":%d}`+"\n", id, b, timeoutMS), id
}

// TestPackageReinstallStopPoints: a reinstall whose postinst does not end
// gets the early answer at the request's deadline (6 s) naming apt-get and
// the time it may run until; a preview meanwhile says a package operation
// is in progress; SIGINT goes to apt-get alone at the stop point (18 s)
// and the process group is killed at max_timeout_s (24 s); the journal
// line has the result from dpkg's state.
func TestPackageReinstallStopPoints(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	aptRepo(t, "example-reinst_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	reinstreqOnHost(t)
	var p reinstallPreviewResult
	mustGate(t, "priv_pkg_reinstall_preview", reinstArgs, &p)
	line, id := reinstallRequest(p.PreviewSHA256, 6000)
	start := time.Now()
	out, took := lineClient(t, line)
	if !strings.Contains(out, `"code":"outcome_unknown"`) || !strings.Contains(out, id) || !untilRE.MatchString(out) || !strings.Contains(out, "apt-get") || took > 10*time.Second {
		t.Fatalf("answer after %v: %s", took, out)
	}
	if r, _ := gate(t, svcShell, "priv_pkg_reinstall_preview", reinstArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "package operation in progress") {
		t.Fatalf("preview during the reinstall: %s %+v", r.code(), r.Error)
	}
	waitLineFor(t, `"id":"`+id+`"`, `"stopped":"killed"`, `"answered_early":true`, `"outcome":"verify_failed"`, `"unfinished":["example-reinst"]`)
	if d := time.Since(start); d < 23*time.Second || d > 50*time.Second {
		t.Fatalf("the line came %v after the request, want just after the 24 s kill", d)
	}
}
