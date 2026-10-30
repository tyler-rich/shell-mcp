package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// What the recovery leaves (handoff N-36, S7-7; docs/TOOLS.md):
// shell_priv_reinstall_packages, approval-gated at operator, whose preview
// is the helper's priv_pkg_reinstall_preview (also reachable through
// shell_priv_preview_packages as the reinstall operation); and the
// unfinished packages the install and remove previews now carry, which the
// approval page of a removal shows. Every name and hash is invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_reinstall_packages")
}

func fakeReinstallPreview(sha string) string {
	return `{"op":"reinstall","packages":["example-bad"],"reinstall":[{"name":"example-bad","version":"1.0","state":"half-installed","flag":"reinstreq","missing_depends":[]}],` +
		`"argv":["-q","-s","install","--reinstall","--","example-bad=1.0"],"exit_code":0,"signal":null,"stderr":"","stderr_truncated":false,"duration_ms":40,` +
		`"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

const fakeReinstallResult = `{"op":"reinstall","packages":["example-bad"],"reinstalled":[{"name":"example-bad","version":"1.0","from_state":"half-installed"}],` +
	`"exit_code":0,"signal":null,"timed_out":false,"stdout":"Setting up example-bad (1.0) ...\n","stderr":"","stdout_truncated":false,"stderr_truncated":false,` +
	`"attempts":1,"lock_wait_ms":0,"duration_ms":800}`

// fakeUnfinishedRemovePreview is a removal of a package whose dependency
// nothing provides, which worked at an older version before (M2).
func fakeUnfinishedRemovePreview(sha string) string {
	return `{"op":"remove","packages":["example-needs"],"install":[],"upgrade":[],"remove":[{"name":"example-needs","version":"2.0","purge":false}],` +
		`"unfinished":[{"name":"example-needs","version":"2.0","state":"unpacked","flag":"ok","missing_depends":["example-absent"]}],` +
		`"complete":true,"argv":["-q","-s","remove","--","example-needs"],"exit_code":0,"signal":null,"stderr":"","stderr_truncated":false,"duration_ms":40,` +
		`"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

var reinstallArgs = map[string]any{"packages": []string{"example-bad"}}

func newReinstallHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_pkg_reinstall_preview", gateReply{data: fakeReinstallPreview(shaPK)})
	a.g.set("priv_pkg_reinstall", gateReply{data: fakeReinstallResult})
	return a
}

func TestPrivReinstallRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		if slices.Contains(names(reg.ToolsForProfile(p, nil)), "shell_priv_reinstall_packages") {
			t.Fatalf("registered in the %s profile", p)
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == "shell_priv_reinstall_packages" })
	if i < 0 {
		t.Fatal("not registered in admin")
	}
	r := admin[i]
	a := r.Tool.Def.Annotations
	if r.Tier != TierOperator || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint ||
		r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
		t.Fatalf("tier %s annotations %+v meta %v description %q", r.Tier, a, r.Tool.Def.Meta, r.Tool.Def.Description)
	}
	s := schemaOf(t, r)
	for _, want := range []string{"target", "packages", "timeout_seconds", "approval_id"} {
		if s.Properties[want] == nil {
			t.Fatalf("no %s in %s", want, jsonOf(t, s))
		}
	}
	if len(s.Properties) != 4 {
		t.Fatalf("the client passes more than the target, names and timeout: %s", jsonOf(t, s))
	}
}

// TestPrivReinstallApprovalFlow: the first call sends only the preview and
// requests an approval showing each package with its version and state;
// the approved re-call previews again and sends priv_pkg_reinstall once at
// ceiling operator with the names and the fresh preview's hash; a second
// re-call is approval_invalid.
func TestPrivReinstallApprovalFlow(t *testing.T) {
	a := newReinstallHarness(t, approval.MethodWeb)
	id := a.pending("shell_priv_reinstall_packages", reinstallArgs)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_pkg_reinstall_preview"}) {
		t.Fatalf("first call sent %v", ops)
	}
	pm := previewMap(t, a, id)
	if pm["preview_sha256"] != shaPK || pm["reinstall[0].name"] != "example-bad" || pm["reinstall[0].version"] != "1.0" || pm["reinstall[0].state"] != "half-installed" ||
		pm["reinstall[0].flag"] != "reinstreq" || pm["op"] != "reinstall" {
		t.Fatalf("preview %v", pm)
	}
	if rec, _ := a.store.Get(id); rec.Description != "As root, reinstall 1 package on app-host" {
		t.Fatalf("description %q", rec.Description)
	}
	a.approve(id)
	env, _ := a.call("shell_priv_reinstall_packages", withID(reinstallArgs, id))
	d := data(t, env)
	if re, _ := d["reinstalled"].([]any); len(re) != 1 || re[0].(map[string]any)["from_state"] != "half-installed" {
		t.Fatalf("data %v", d)
	}
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_pkg_reinstall_preview", "priv_pkg_reinstall_preview", "priv_pkg_reinstall"}) {
		t.Fatalf("ops %v", ops)
	}
	if reqs := a.g.requests(); reqs[2].Ceiling != "operator" {
		t.Fatalf("priv_pkg_reinstall at ceiling %s", reqs[2].Ceiling)
	}
	if oa := a.g.args(t, "priv_pkg_reinstall"); oa["expected_preview_sha256"] != shaPK || len(oa) != 2 {
		t.Fatalf("op args %v", oa)
	}
	if env, _ := a.call("shell_priv_reinstall_packages", withID(reinstallArgs, id)); errCode(env) != "approval_invalid" || a.count("priv_pkg_reinstall") != 1 {
		t.Fatalf("second re-call %v", env)
	}
	if strings.Contains(a.logs.String(), shaPK) {
		t.Fatal("the preview hash reached the server's logs")
	}
}

// TestPrivReinstallChangedAfterApproval: the state (the preview's hash)
// or either policy changed after approval: approval_invalid, nothing runs.
func TestPrivReinstallChangedAfterApproval(t *testing.T) {
	for name, change := range map[string]func(a *approvalHarness){
		"state": func(a *approvalHarness) {
			a.g.set("priv_pkg_reinstall_preview", gateReply{data: fakeReinstallPreview(shaPK2)})
		},
		"helper": func(a *approvalHarness) { a.g.setHelperSHA("f00d") },
		"gate":   func(a *approvalHarness) { a.g.setSHA("f00d") },
	} {
		t.Run(name, func(t *testing.T) {
			a := newReinstallHarness(t, approval.MethodWeb)
			id := a.pending("shell_priv_reinstall_packages", reinstallArgs)
			a.approve(id)
			change(a)
			if env, _ := a.call("shell_priv_reinstall_packages", withID(reinstallArgs, id)); errCode(env) != "approval_invalid" || a.count("priv_pkg_reinstall") != 0 {
				t.Fatalf("env %v, ops %v", env, a.g.ops())
			}
		})
	}
}

// TestPrivReinstallRefusals: approval_unavailable under none; the
// preview's refusal (no archive of that version) is the result with no
// approval requested; invalid names never reach the gate; the helper's
// early answer is outcome_unknown, the approval used.
func TestPrivReinstallRefusals(t *testing.T) {
	a := newReinstallHarness(t, approval.MethodNone)
	if env, _ := a.call("shell_priv_reinstall_packages", reinstallArgs); errCode(env) != "approval_unavailable" || a.count("priv_pkg_reinstall") != 0 {
		t.Fatalf("under none: %v", env)
	}
	b := newReinstallHarness(t, approval.MethodWeb)
	b.g.set("priv_pkg_reinstall_preview", gateReply{code: "exec_failed", msg: "the simulation was incomplete (exit code 100, 0 line(s) not understood; apt-get said: E: The package example-bad needs to be reinstalled, but I can't find an archive for it.); nothing was requested"})
	if env, _ := b.call("shell_priv_reinstall_packages", reinstallArgs); errCode(env) != "exec_failed" || env["approval"] != nil || b.count("priv_pkg_reinstall") != 0 {
		t.Fatalf("preview refusal: %v", env)
	}
	for _, args := range []map[string]any{{}, {"packages": []string{}}, {"packages": []string{"example-bad-"}}, {"packages": []string{"example-bad=1.0"}},
		{"packages": []string{"example-bad", "example-bad"}}, {"packages": []string{"-s"}}} {
		if env, _ := b.call("shell_priv_reinstall_packages", args); errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", args, env)
		}
	}
	c := newReinstallHarness(t, approval.MethodWeb)
	id := c.pending("shell_priv_reinstall_packages", reinstallArgs)
	c.approve(id)
	c.g.set("priv_pkg_reinstall", gateReply{code: "outcome_unknown", msg: "apt-get is still running (request id 0b5c0000-0000-4000-8000-000000000043); it may run until 2026-10-30T12:15:00Z"})
	env, _ := c.call("shell_priv_reinstall_packages", withID(reinstallArgs, id))
	if errCode(env) != "outcome_unknown" || !strings.Contains(errMessage(env), "2026-10-30T12:15:00Z") {
		t.Fatalf("early answer: %v", env)
	}
	if ap, _ := env["approval"].(map[string]any); ap["status"] != "used" {
		t.Fatalf("approval %v", env["approval"])
	}
}

// TestPrivPreviewPackagesReinstall: the read-tier preview tool previews a
// reinstall at ceiling read, with the names, and returns each package to
// reinstall; the install, upgrade and remove previews carry unfinished.
func TestPrivPreviewPackagesReinstall(t *testing.T) {
	a := newReinstallHarness(t, approval.MethodNone)
	env, _ := a.call("shell_priv_preview_packages", map[string]any{"operation": "reinstall", "packages": []string{"example-bad"}})
	d := data(t, env)
	re, _ := d["reinstall"].([]any)
	if d["op"] != "reinstall" || d["preview_sha256"] != shaPK || len(re) != 1 || re[0].(map[string]any)["state"] != "half-installed" {
		t.Fatalf("data %v", d)
	}
	if u, ok := d["unfinished"].([]any); !ok || len(u) != 0 {
		t.Fatalf("unfinished %v", d["unfinished"])
	}
	if reqs := a.g.requests(); len(reqs) != 1 || reqs[0].Op != "priv_pkg_reinstall_preview" || reqs[0].Ceiling != "read" {
		t.Fatalf("requests %+v", reqs)
	}
	if pa := a.g.args(t, "priv_pkg_reinstall_preview"); pa["packages"] == nil {
		t.Fatalf("preview args %v", pa)
	}
	if bad, _ := a.call("shell_priv_preview_packages", map[string]any{"operation": "reinstall"}); errCode(bad) != "validation_error" {
		t.Fatalf("reinstall without names: %v", bad)
	}
	b := newPrivPkgHarness(t, approval.MethodNone)
	b.g.set("priv_pkg_remove_preview", gateReply{data: fakeUnfinishedRemovePreview(shaPK)})
	env, _ = b.call("shell_priv_preview_packages", map[string]any{"operation": "remove", "packages": []string{"example-needs"}})
	d = data(t, env)
	u, _ := d["unfinished"].([]any)
	if len(u) != 1 || u[0].(map[string]any)["version"] != "2.0" || u[0].(map[string]any)["state"] != "unpacked" {
		t.Fatalf("unfinished %v", d["unfinished"])
	}
	if r, _ := d["reinstall"].([]any); r == nil || len(r) != 0 {
		t.Fatalf("reinstall %v", d["reinstall"])
	}
}

// TestPrivRemoveUnfinishedApproval: the approval page of a removal in the
// unfinished mode shows each unfinished package with its version, state
// and missing dependency (M2: a package that worked at an older version is
// visibly being removed at the version dpkg unpacked).
func TestPrivRemoveUnfinishedApproval(t *testing.T) {
	a := newPrivPkgHarness(t, approval.MethodWeb)
	a.g.set("priv_pkg_remove_preview", gateReply{data: fakeUnfinishedRemovePreview(shaPK)})
	id := a.pending("shell_priv_remove_packages", map[string]any{"packages": []string{"example-needs"}})
	pm := previewMap(t, a, id)
	if pm["unfinished[0].name"] != "example-needs" || pm["unfinished[0].version"] != "2.0" || pm["unfinished[0].state"] != "unpacked" ||
		pm["unfinished[0].missing_depends[0]"] != "example-absent" || pm["remove[0].version"] != "2.0" {
		t.Fatalf("preview %v", pm)
	}
}
