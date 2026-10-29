package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// shell_priv_recover_packages (handoff N-14, S7-4; docs/TOOLS.md): its
// preview is the helper's report of the unfinished packages; with nothing
// unfinished it answers at once, with no approval and nothing run;
// otherwise it is approval-gated, and the approved re-call sends
// priv_pkg_recover with the fresh preview's hash. Every name and hash is
// invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_recover_packages")
}

func fakeRecoverPreview(sha string, unfinished bool) string {
	u, j := `[]`, 0
	if unfinished {
		u = `[{"name":"example-a","version":"1.0","state":"unpacked","flag":"ok","missing_depends":[]},` +
			`{"name":"example-b","version":"1.0","state":"half-configured","flag":"ok","missing_depends":[]}]`
		j = 1
	}
	return `{"op":"recover","unfinished":` + u + `,"needs_reinstall":[],"journal_entries":` + string(rune('0'+j)) +
		`,"argv":["--force-confold","--configure","--pending"],"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

const fakeRecoverResult = `{"op":"recover","ran":true,"configured":[{"name":"example-a","version":"1.0","from_state":"unpacked"},` +
	`{"name":"example-b","version":"1.0","from_state":"half-configured"}],"exit_code":0,"signal":null,"timed_out":false,` +
	`"stdout":"Setting up example-a (1.0) ...\n","stderr":"","stdout_truncated":false,"stderr_truncated":false,"attempts":1,"lock_wait_ms":0,"duration_ms":700}`

func newRecoverHarness(t *testing.T, method approval.Method, unfinished bool) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_pkg_recover_preview", gateReply{data: fakeRecoverPreview(shaPK, unfinished)})
	a.g.set("priv_pkg_recover", gateReply{data: fakeRecoverResult})
	return a
}

func TestPrivRecoverRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		if slices.Contains(names(reg.ToolsForProfile(p, nil)), "shell_priv_recover_packages") {
			t.Fatalf("registered in the %s profile", p)
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == "shell_priv_recover_packages" })
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
	for _, want := range []string{"target", "timeout_seconds", "approval_id"} {
		if s.Properties[want] == nil {
			t.Fatalf("no %s in %s", want, jsonOf(t, s))
		}
	}
	if s.Properties["packages"] != nil || len(s.Properties) != 3 {
		t.Fatalf("the client passes more than the target and timeout: %s", jsonOf(t, s))
	}
}

// TestPrivRecoverNothing: with nothing unfinished the tool answers at
// once: no approval, nothing but the preview sent, under any approval
// method.
func TestPrivRecoverNothing(t *testing.T) {
	for _, m := range []approval.Method{approval.MethodWeb, approval.MethodNone} {
		a := newRecoverHarness(t, m, false)
		env, res := a.call("shell_priv_recover_packages", map[string]any{})
		d := data(t, env)
		if d["ran"] != false || env["approval"] != nil || !slices.Equal(a.g.ops(), []string{"priv_pkg_recover_preview"}) {
			t.Fatalf("%s: env %v ops %v", m, env, a.g.ops())
		}
		if c, ok := d["configured"].([]any); !ok || len(c) != 0 {
			t.Fatalf("%s: configured %v", m, d["configured"])
		}
		if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "nothing to recover") {
			t.Fatalf("%s: text %q", m, text)
		}
	}
}

// TestPrivRecoverApprovalFlow: unfinished packages need an approval; the
// approval page shows them; the approved re-call sends priv_pkg_recover at
// ceiling operator with the fresh preview's hash, once; a second re-call is
// approval_invalid.
func TestPrivRecoverApprovalFlow(t *testing.T) {
	a := newRecoverHarness(t, approval.MethodWeb, true)
	id := a.pending("shell_priv_recover_packages", map[string]any{})
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_pkg_recover_preview"}) {
		t.Fatalf("first call sent %v", ops)
	}
	pm := previewMap(t, a, id)
	if pm["preview_sha256"] != shaPK || pm["unfinished[0].name"] != "example-a" || pm["unfinished[1].state"] != "half-configured" {
		t.Fatalf("preview %v", pm)
	}
	if rec, _ := a.store.Get(id); rec.Description != "As root, finish 2 unfinished packages on app-host" {
		t.Fatalf("description %q", rec.Description)
	}
	a.approve(id)
	env, _ := a.call("shell_priv_recover_packages", withID(map[string]any{}, id))
	d := data(t, env)
	if d["ran"] != true || len(d["configured"].([]any)) != 2 {
		t.Fatalf("data %v", d)
	}
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_pkg_recover_preview", "priv_pkg_recover_preview", "priv_pkg_recover"}) {
		t.Fatalf("ops %v", ops)
	}
	if reqs := a.g.requests(); reqs[2].Ceiling != "operator" {
		t.Fatalf("priv_pkg_recover at ceiling %s", reqs[2].Ceiling)
	}
	if oa := a.g.args(t, "priv_pkg_recover"); oa["expected_preview_sha256"] != shaPK || len(oa) != 1 {
		t.Fatalf("op args %v", oa)
	}
	if env, _ := a.call("shell_priv_recover_packages", withID(map[string]any{}, id)); errCode(env) != "approval_invalid" || a.count("priv_pkg_recover") != 1 {
		t.Fatalf("second re-call %v", env)
	}
	if strings.Contains(a.logs.String(), shaPK) {
		t.Fatal("the preview hash reached the server's logs")
	}
}

// TestPrivRecoverChangedAfterApproval: the unfinished packages (their
// hash), or either policy, changed after approval: approval_invalid and
// nothing runs; the same once nothing is unfinished any more.
func TestPrivRecoverChangedAfterApproval(t *testing.T) {
	for name, change := range map[string]func(a *approvalHarness){
		"state": func(a *approvalHarness) {
			a.g.set("priv_pkg_recover_preview", gateReply{data: fakeRecoverPreview(shaPK2, true)})
		},
		"recovered": func(a *approvalHarness) {
			a.g.set("priv_pkg_recover_preview", gateReply{data: fakeRecoverPreview(shaPK2, false)})
		},
		"helper": func(a *approvalHarness) { a.g.setHelperSHA("f00d") },
		"gate":   func(a *approvalHarness) { a.g.setSHA("f00d") },
	} {
		t.Run(name, func(t *testing.T) {
			a := newRecoverHarness(t, approval.MethodWeb, true)
			id := a.pending("shell_priv_recover_packages", map[string]any{})
			a.approve(id)
			change(a)
			if env, _ := a.call("shell_priv_recover_packages", withID(map[string]any{}, id)); errCode(env) != "approval_invalid" || a.count("priv_pkg_recover") != 0 {
				t.Fatalf("env %v, ops %v", env, a.g.ops())
			}
		})
	}
}

// TestPrivRecoverRefusals: under SHELL_MCP_APPROVAL_METHOD=none unfinished
// packages are approval_unavailable; the preview's refusal (only packages
// that need a reinstall, an operation in progress) is the result with no
// approval requested; the helper's early answer is outcome_unknown, the
// approval used.
func TestPrivRecoverRefusals(t *testing.T) {
	a := newRecoverHarness(t, approval.MethodNone, true)
	if env, _ := a.call("shell_priv_recover_packages", map[string]any{}); errCode(env) != "approval_unavailable" || a.count("priv_pkg_recover") != 0 {
		t.Fatalf("under none: %v", env)
	}
	b := newRecoverHarness(t, approval.MethodWeb, true)
	b.g.set("priv_pkg_recover_preview", gateReply{code: "exec_failed", msg: "dpkg left 1 package to reinstall (example-c): configuring does not fix it"})
	if env, _ := b.call("shell_priv_recover_packages", map[string]any{}); errCode(env) != "exec_failed" || env["approval"] != nil || b.count("priv_pkg_recover") != 0 {
		t.Fatalf("preview refusal: %v", env)
	}
	c := newRecoverHarness(t, approval.MethodWeb, true)
	id := c.pending("shell_priv_recover_packages", map[string]any{})
	c.approve(id)
	c.g.set("priv_pkg_recover", gateReply{code: "outcome_unknown", msg: "dpkg is still running (request id 0b5c0000-0000-4000-8000-000000000042); it may run until 2026-10-21T12:15:00Z"})
	env, _ := c.call("shell_priv_recover_packages", withID(map[string]any{}, id))
	if errCode(env) != "outcome_unknown" || !strings.Contains(errMessage(env), "2026-10-21T12:15:00Z") {
		t.Fatalf("early answer: %v", env)
	}
	if ap, _ := env["approval"].(map[string]any); ap["status"] != "used" {
		t.Fatalf("approval %v", env["approval"])
	}
}
