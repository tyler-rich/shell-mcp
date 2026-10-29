//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The recovery of an unfinished dpkg database end to end (handoff N-14,
// S7-4): real dpkg in the broad unit, under privileged-recover.yaml
// (max_timeout_s 24, packages.allow_recover), with the invented packages
// of setup.sh: example-blocked, whose postinst waits for pkgRelease, and
// example-needs, whose dependency no repository has.

// pkgRelease lets example-blocked's postinst finish.
const pkgRelease = "/run/shell-mcp-e2e-pkg-release"

type recoverEntry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	State          string   `json:"state"`
	Flag           string   `json:"flag"`
	MissingDepends []string `json:"missing_depends"`
}

type recoverPreviewResult struct {
	Op             string         `json:"op"`
	Unfinished     []recoverEntry `json:"unfinished"`
	NeedsReinstall []recoverEntry `json:"needs_reinstall"`
	JournalEntries int            `json:"journal_entries"`
	Argv           []string       `json:"argv"`
	PreviewSHA256  string         `json:"preview_sha256"`
}

func recoverPreview(t *testing.T) recoverPreviewResult {
	t.Helper()
	var p recoverPreviewResult
	mustGate(t, "priv_pkg_recover_preview", map[string]any{}, &p)
	return p
}

func entryNames(l []recoverEntry) []string {
	out := []string{}
	for _, e := range l {
		out = append(out, e.Name)
	}
	return out
}

// recoverRequest is a priv_pkg_recover request line for the broad helper.
func recoverRequest(hash string, timeoutMS int) (line, id string) {
	b, _ := json.Marshal(map[string]any{"expected_preview_sha256": hash})
	id = newID()
	return fmt.Sprintf(`{"v":2,"id":%q,"ceiling":"operator","op":"priv_pkg_recover","args":%s,"timeout_ms":%d}`+"\n", id, b, timeoutMS), id
}

// unpackOnHost leaves a package unpacked and not configured, as an
// install interrupted before its configuration does (dpkg --unpack on the
// runner, outside the helper).
func unpackOnHost(t *testing.T, deb string) {
	t.Helper()
	run(t, "dpkg", "--unpack", filepath.Join(bin(), "debs", deb))
}

func released(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(pkgRelease, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestPackageRecoverInterrupted: an install of example-blocked killed at
// the helper's limit leaves dpkg unfinished, and the next install preview
// says how to recover; once the postinst can finish,
// shell_priv_recover_packages previews the unfinished package, is
// approved, runs once, and answers from dpkg's state; a second re-call is
// approval_invalid; dpkg --audit is clean.
func TestPackageRecoverInterrupted(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	aptRepo(t, "example-blocked_1.0_all.deb", "example-hello_1.0_all.deb", "example-extra_1.0_all.deb")
	mustPkg(t, "update_index", map[string]any{})
	args := map[string]any{"packages": []string{"example-blocked"}}
	p := pkgPreview(t, "install", args)
	line, id := installRequest(t, withHash(args, p.PreviewSHA256), 6000)
	lineClient(t, line)
	waitLineFor(t, `"id":"`+id+`"`, `"stopped":"killed"`, `"outcome":"verify_failed"`, `"unfinished":["example-blocked"]`)
	if got := installed(t, "example-blocked"); strings.HasPrefix(got, "installed") {
		t.Fatalf("example-blocked %q after the kill", got)
	}
	if r, _ := gate(t, svcShell, "priv_pkg_install_preview", helloArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "to configure") ||
		!strings.Contains(r.Error.Message, "example-blocked") {
		t.Fatalf("install preview after the kill: %s %+v", r.code(), r.Error)
	}
	released(t)
	srv, h := privWriteServer(t)
	aid := pendingID(t, srv.callTool(t, "shell_priv_recover_packages", map[string]any{}))
	if got := installed(t, "example-blocked"); strings.HasPrefix(got, "installed") {
		t.Fatal("recovered before approval")
	}
	srv.decide(t, h, aid, "approve")
	d := okDataAs(t, srv.callTool(t, "shell_priv_recover_packages", withApproval(map[string]any{}, aid)), "e2e-ssh")
	conf, _ := d["configured"].([]any)
	if d["ran"] != true || len(conf) != 1 || fmt.Sprint(conf[0].(map[string]any)["name"]) != "example-blocked" {
		t.Fatalf("data %v", d)
	}
	if got := installed(t, "example-blocked"); got != "installed 1.0" {
		t.Fatalf("example-blocked %q after the recovery", got)
	}
	if out := run(t, "dpkg", "--audit"); strings.TrimSpace(out) != "" {
		t.Fatalf("dpkg --audit after the recovery: %s", out)
	}
	refusal(t, srv.callTool(t, "shell_priv_recover_packages", withApproval(map[string]any{}, aid)), "approval_invalid", "")
	j := waitLine(t, "shell-mcp-privd", `"op":"priv_pkg_recover"`, `"outcome":"ok"`, `"configured":["example-blocked"]`)
	if strings.Contains(j.Message, "expected_preview_sha256") || j.Priority != "4" {
		t.Fatalf("journal line %s at priority %s", j.Message, j.Priority)
	}
}

// TestPackageRecoverNothing: with nothing unfinished the preview's lists
// are empty and the tool answers at once, with no approval and nothing run.
func TestPackageRecoverNothing(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	p := recoverPreview(t)
	if len(p.Unfinished)+len(p.NeedsReinstall) != 0 || p.Op != "recover" || !slices.Equal(p.Argv, []string{"--force-confold", "--configure", "--pending"}) {
		t.Fatalf("preview %+v", p)
	}
	srv, _ := privWriteServer(t)
	env := srv.callTool(t, "shell_priv_recover_packages", map[string]any{})
	d, _ := env["data"].(map[string]any)
	if env["ok"] != true || env["approval"] != nil || d["ran"] != false {
		t.Fatalf("envelope %v", env)
	}
}

// TestPackageRecoverStateChanged: the unfinished package is configured on
// the host between the preview and the run: the recovery is refused and
// runs nothing.
func TestPackageRecoverStateChanged(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	unpackOnHost(t, "example-blocked_1.0_all.deb")
	p := recoverPreview(t)
	if !slices.Equal(entryNames(p.Unfinished), []string{"example-blocked"}) || p.Unfinished[0].State != "unpacked" {
		t.Fatalf("preview %+v", p)
	}
	released(t)
	run(t, "dpkg", "--configure", "example-blocked")
	r, id := gateAt(t, svcShell, "operator", "priv_pkg_recover", map[string]any{"expected_preview_sha256": p.PreviewSHA256})
	if r.code() != "exists" || !strings.Contains(r.Error.Message, "nothing was run") {
		t.Fatalf("answer %s %+v", r.code(), r.Error)
	}
	waitLine(t, "shell-mcp-privd", `"id":"`+id+`"`, `"outcome":"exists"`)
}

// TestPackageRecoverStopPoints: a recovery whose postinst does not end
// gets the early answer at the request's deadline (6 s), naming dpkg and
// the time it may run until; a preview meanwhile says a package operation
// is in progress; nothing is sent at the stop point (18 s), since SIGINT
// gives dpkg no graceful stop; the process group is killed at
// max_timeout_s (24 s), and the journal line has the result from dpkg's
// state.
func TestPackageRecoverStopPoints(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	unpackOnHost(t, "example-blocked_1.0_all.deb")
	p := recoverPreview(t)
	line, id := recoverRequest(p.PreviewSHA256, 6000)
	start := time.Now()
	out, took := lineClient(t, line)
	if !strings.Contains(out, `"code":"outcome_unknown"`) || !strings.Contains(out, id) || !untilRE.MatchString(out) || !strings.Contains(out, "dpkg") || took > 10*time.Second {
		t.Fatalf("answer after %v: %s", took, out)
	}
	if r, _ := gate(t, svcShell, "priv_pkg_recover_preview", map[string]any{}); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "package operation in progress") {
		t.Fatalf("preview during the recovery: %s %+v", r.code(), r.Error)
	}
	j := waitLineFor(t, `"id":"`+id+`"`, `"stopped":"killed"`, `"answered_early":true`, `"outcome":"verify_failed"`, `"unfinished":["example-blocked"]`)
	if strings.Contains(j.Message, "sigint") {
		t.Fatalf("SIGINT was sent: %s", j.Message)
	}
	if d := time.Since(start); d < 23*time.Second || d > 50*time.Second {
		t.Fatalf("the line came %v after the request, want just after the 24 s kill", d)
	}
}

// TestPackageRecoverMissingDependency: a package whose dependency nothing
// provides: the install preview's refusal names it, the recovery preview
// lists it with the missing dependency, and the recovery leaves it as it
// was: verify_failed naming the dependency.
func TestPackageRecoverMissingDependency(t *testing.T) {
	installPolicy(t, "privileged-recover.yaml")
	cleanupPackages(t)
	unpackOnHost(t, "example-needs_1.0_all.deb")
	if r, _ := gate(t, svcShell, "priv_pkg_install_preview", helloArgs); r.code() != "exec_failed" || !strings.Contains(r.Error.Message, "missing dependency") ||
		!strings.Contains(r.Error.Message, "example-absent") {
		t.Fatalf("install preview: %s %+v", r.code(), r.Error)
	}
	p := recoverPreview(t)
	if len(p.Unfinished) != 1 || p.Unfinished[0].Name != "example-needs" || !slices.Equal(p.Unfinished[0].MissingDepends, []string{"example-absent"}) {
		t.Fatalf("preview %+v", p)
	}
	r, _ := gateAt(t, svcShell, "operator", "priv_pkg_recover", map[string]any{"expected_preview_sha256": p.PreviewSHA256})
	if r.code() != "exec_failed" && r.code() != "verify_failed" || !strings.Contains(r.Error.Message, "example-absent") {
		t.Fatalf("answer %s %+v", r.code(), r.Error)
	}
	if got := installed(t, "example-needs"); strings.HasPrefix(got, "installed") {
		t.Fatalf("example-needs %q", got)
	}
}
