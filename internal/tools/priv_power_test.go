package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// The power tools (S4c-8; docs/TOOLS.md, privileged tier: power; handoff
// P-2f, P-3, P-13): shell_priv_reboot_host is always approval-gated, its
// approval preview is the helper's priv_power_preview bound with both
// policies' hashes, and the approved re-call sends priv_power with the
// fresh preview's hash; shell_priv_cancel_power is read tier, never gated,
// and sends priv_power_cancel. Every time and hash is invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_reboot_host")
	ceilingCallArgs["shell_priv_reboot_host"] = map[string]any{"action": "reboot"}
}

const (
	shaPW  = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
	shaPW2 = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
)

func fakePowerPreview(action, sha string) string {
	return `{"action":"` + action + `","target":"` + action + `.target","delay_s":60,"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

func fakePowerResult(action string) string {
	return `{"action":"` + action + `","target":"` + action + `.target","scheduled_at":"2026-10-22T12:01:00Z","delay_s":60,` +
		`"cancel":"send priv_power_cancel before 2026-10-22T12:01:00Z"}`
}

func newPrivPowerHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_power_preview", gateReply{data: fakePowerPreview("reboot", shaPW)})
	a.g.set("priv_power", gateReply{data: fakePowerResult("reboot")})
	a.g.set("priv_power_cancel", gateReply{data: `{"cancelled":true,"request_id":"0b5c0000-0000-4000-8000-000000000042","action":"reboot","scheduled_at":"2026-10-22T12:01:00Z"}`})
	return a
}

func TestPrivPowerToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, n := range names(reg.ToolsForProfile(p, nil)) {
			if n == "shell_priv_reboot_host" || n == "shell_priv_cancel_power" {
				t.Fatalf("%s is registered in the %s profile", n, p)
			}
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	find := func(name string) Registration {
		i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == name })
		if i < 0 {
			t.Fatalf("%s is not registered in admin", name)
		}
		return admin[i]
	}
	r := find("shell_priv_reboot_host")
	a := r.Tool.Def.Annotations
	if r.Tier != TierDestructive || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint ||
		r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
		t.Fatalf("reboot tool: tier %s annotations %+v meta %v description %q", r.Tier, a, r.Tool.Def.Meta, r.Tool.Def.Description)
	}
	s := schemaOf(t, r)
	for _, want := range []string{"target", "action", "approval_id"} {
		if s.Properties[want] == nil {
			t.Fatalf("reboot tool: no %s in %s", want, jsonOf(t, s))
		}
	}
	if e := s.Properties["action"].Enum; len(e) != 2 || e[0] != "reboot" || e[1] != "poweroff" {
		t.Fatalf("action enum %v", e)
	}
	for _, never := range []string{"expected_preview_sha256", "delay", "delay_seconds", "unit", "force", "flags"} {
		if s.Properties[never] != nil {
			t.Fatalf("reboot tool: %s is an input", never)
		}
	}
	r = find("shell_priv_cancel_power")
	a = r.Tool.Def.Annotations
	if r.Tier != TierRead || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint ||
		r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != nil || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
		t.Fatalf("cancel tool: tier %s annotations %+v meta %v description %q", r.Tier, a, r.Tool.Def.Meta, r.Tool.Def.Description)
	}
	if s := schemaOf(t, r); len(s.Properties) != 1 || s.Properties["target"] == nil {
		t.Fatalf("cancel schema %s", jsonOf(t, s))
	}
}

// TestPrivRebootApprovalFlow: the first call sends only the preview and
// requests an approval showing the action, the unit and the delay; the
// approved re-call previews again and sends priv_power once, at ceiling
// destructive, with the fresh preview's hash; the result says when the
// action will be requested and how to cancel it; a second re-call is
// approval_invalid.
func TestPrivRebootApprovalFlow(t *testing.T) {
	for _, action := range []string{"reboot", "poweroff"} {
		t.Run(action, func(t *testing.T) {
			a := newPrivPowerHarness(t, approval.MethodWeb)
			a.g.set("priv_power_preview", gateReply{data: fakePowerPreview(action, shaPW)})
			a.g.set("priv_power", gateReply{data: fakePowerResult(action)})
			args := map[string]any{"action": action}
			id := a.pending("shell_priv_reboot_host", args)
			if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_power_preview"}) {
				t.Fatalf("first call sent %v", ops)
			}
			if pa := a.g.args(t, "priv_power_preview"); pa["action"] != action || len(pa) != 1 {
				t.Fatalf("preview args %v", pa)
			}
			pm := previewMap(t, a, id)
			if pm["action"] != action || pm["target_unit"] != action+".target" || pm["delay_seconds"] != "60" || pm["preview_sha256"] != shaPW {
				t.Fatalf("preview %v", pm)
			}
			rec, _ := a.store.Get(id)
			verb := map[string]string{"reboot": "reboot", "poweroff": "power off"}[action]
			if want := "As root, " + verb + " app-host 60 s after the call"; rec.Description != want {
				t.Fatalf("description %q, want %q", rec.Description, want)
			}
			a.approve(id)
			env, _ := a.call("shell_priv_reboot_host", withID(args, id))
			d := data(t, env)
			if d["action"] != action || d["target_unit"] != action+".target" || d["scheduled_at"] != "2026-10-22T12:01:00Z" || d["delay_seconds"] != float64(60) ||
				!strings.Contains(d["cancel"].(string), "priv_power_cancel") {
				t.Fatalf("data %v", d)
			}
			if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_power_preview", "priv_power_preview", "priv_power"}) {
				t.Fatalf("ops %v", ops)
			}
			if reqs := a.g.requests(); reqs[2].Ceiling != "destructive" {
				t.Fatalf("priv_power at ceiling %s", reqs[2].Ceiling)
			}
			if oa := a.g.args(t, "priv_power"); oa["action"] != action || oa["expected_preview_sha256"] != shaPW || len(oa) != 2 {
				t.Fatalf("op args %v", oa)
			}
			if env, _ := a.call("shell_priv_reboot_host", withID(args, id)); errCode(env) != "approval_invalid" || a.count("priv_power") != 1 {
				t.Fatalf("second re-call %v", env)
			}
			if strings.Contains(a.logs.String(), shaPW) {
				t.Fatal("the preview hash reached the server's logs")
			}
		})
	}
}

func TestPrivRebootGatedUnderNone(t *testing.T) {
	a := newPrivPowerHarness(t, approval.MethodNone)
	if env, _ := a.call("shell_priv_reboot_host", map[string]any{"action": "reboot"}); errCode(env) != "approval_unavailable" || len(a.g.requests()) != 0 {
		t.Fatalf("env %v ops %v", env, a.g.ops())
	}
}

// TestPrivRebootChangedAfterApproval: another preview (action, delay or a
// blocker gone and back), the privileged policy or the gate policy changed
// after approval is approval_invalid, and nothing is sent.
func TestPrivRebootChangedAfterApproval(t *testing.T) {
	for name, change := range map[string]func(a *approvalHarness){
		"preview": func(a *approvalHarness) {
			a.g.set("priv_power_preview", gateReply{data: fakePowerPreview("reboot", shaPW2)})
		},
		"helper": func(a *approvalHarness) { a.g.setHelperSHA("f00d") },
		"gate":   func(a *approvalHarness) { a.g.setSHA("f00d") },
	} {
		t.Run(name, func(t *testing.T) {
			a := newPrivPowerHarness(t, approval.MethodWeb)
			args := map[string]any{"action": "reboot"}
			id := a.pending("shell_priv_reboot_host", args)
			a.approve(id)
			change(a)
			if env, _ := a.call("shell_priv_reboot_host", withID(args, id)); errCode(env) != "approval_invalid" || a.count("priv_power") != 0 {
				t.Fatalf("env %v, ops %v", env, a.g.ops())
			}
		})
	}
}

// TestPrivRebootPreviewRefusals: the preview's refusals (a blocker, an
// action the policy does not list) are the result; no approval is
// requested and nothing is scheduled. A preview without a valid hash, or
// whose action is not the one asked for, is internal.
func TestPrivRebootPreviewRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		reply gateReply
		code  string
	}{
		"blocked":      {gateReply{code: "exec_failed", msg: "a shutdown inhibitor lock is held by example-backup (nightly copy), uid 1001, pid 4242"}, "exec_failed"},
		"not listed":   {gateReply{code: "policy_denied", msg: "the privileged policy's power section does not allow poweroff"}, "policy_denied"},
		"no hash":      {gateReply{data: fakePowerPreview("reboot", "nothash")}, "internal"},
		"other action": {gateReply{data: fakePowerPreview("poweroff", shaPW)}, "internal"},
	} {
		t.Run(name, func(t *testing.T) {
			a := newPrivPowerHarness(t, approval.MethodWeb)
			a.g.set("priv_power_preview", c.reply)
			env, _ := a.call("shell_priv_reboot_host", map[string]any{"action": "reboot"})
			if errCode(env) != c.code || env["approval"] != nil || a.count("priv_power") != 0 {
				t.Fatalf("env %v ops %v", env, a.g.ops())
			}
		})
	}
}

// TestPrivRebootOutcomeUnknown: a lost answer is outcome_unknown, with the
// approval used.
func TestPrivRebootOutcomeUnknown(t *testing.T) {
	a := newPrivPowerHarness(t, approval.MethodWeb)
	args := map[string]any{"action": "reboot"}
	id := a.pending("shell_priv_reboot_host", args)
	a.approve(id)
	a.g.set("priv_power", gateReply{silent: true})
	env, _ := a.call("shell_priv_reboot_host", withID(args, id))
	if errCode(env) != "outcome_unknown" || env["data"] != nil {
		t.Fatalf("env %v", env)
	}
	if ap, _ := env["approval"].(map[string]any); ap["status"] != "used" {
		t.Fatalf("approval %v", env["approval"])
	}
}

func TestPrivPowerValidation(t *testing.T) {
	a := newPrivPowerHarness(t, approval.MethodWeb)
	for name, args := range map[string]map[string]any{
		"shell_priv_reboot_host":  {"action": "halt"},
		"shell_priv_cancel_power": {"request_id": "0b5c0000-0000-4000-8000-000000000042"},
	} {
		if env, _ := a.call(name, args); errCode(env) != "validation_error" {
			t.Fatalf("%s %v: %v", name, args, env)
		}
	}
	for _, args := range []map[string]any{{}, {"action": "kexec"}, {"action": "reboot", "delay_seconds": 1}, {"action": "reboot", "expected_preview_sha256": shaPW}} {
		if env, _ := a.call("shell_priv_reboot_host", args); errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", args, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivCancelPower: the cancel is never gated, under every approval
// method: it sends priv_power_cancel once, at ceiling read, with no
// arguments; the helper's answer (cancelled, or nothing scheduled) is the
// result.
func TestPrivCancelPower(t *testing.T) {
	for _, method := range []approval.Method{approval.MethodNone, approval.MethodWeb} {
		a := newPrivPowerHarness(t, method)
		env, _ := a.call("shell_priv_cancel_power", map[string]any{})
		d := data(t, env)
		if d["cancelled"] != true || d["request_id"] != "0b5c0000-0000-4000-8000-000000000042" || d["action"] != "reboot" || d["scheduled_at"] != "2026-10-22T12:01:00Z" || env["approval"] != nil {
			t.Fatalf("%s: %v", method, env)
		}
		reqs := a.g.requests()
		if len(reqs) != 1 || reqs[0].Op != "priv_power_cancel" || reqs[0].Ceiling != "read" {
			t.Fatalf("%s: requests %+v", method, reqs)
		}
		if ca := a.g.args(t, "priv_power_cancel"); len(ca) != 0 {
			t.Fatalf("cancel args %v", ca)
		}
	}
	a := newPrivPowerHarness(t, approval.MethodWeb)
	a.g.set("priv_power_cancel", gateReply{code: "not_found", msg: "no power action is scheduled"})
	if env, _ := a.call("shell_priv_cancel_power", map[string]any{}); errCode(env) != "not_found" {
		t.Fatalf("env %v", env)
	}
	a.g.set("priv_power_cancel", gateReply{silent: true})
	if env, _ := a.call("shell_priv_cancel_power", map[string]any{}); errCode(env) != "outcome_unknown" {
		t.Fatalf("lost cancel answer: %v", env)
	}
}
