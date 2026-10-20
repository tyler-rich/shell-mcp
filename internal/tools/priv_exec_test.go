package tools

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// shell_priv_run_command (S4c-6; docs/TOOLS.md, privileged tier; handoff
// docs/handoff/S4C-PRIVILEGED.md D6, D9, P-2d, P-3, Q5, Q11, Q14, and
// must-fix (b)): the helper's priv_exec_preview first, at the tool's
// ceiling; a read command then runs unapproved at ceiling read, an
// operator or destructive command only after approval, at its own tier;
// priv_exec goes to the unit the fresh preview reported, with its hash,
// and a refusal is never retried elsewhere. Every name, path and hash is
// invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_run_command")
}

const (
	shaPX  = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
	shaPX2 = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
)

var privRunArgs = map[string]any{"command_id": "app-renew", "args": []string{"--all"}}

func fakePrivExecPreview(sha, tier, unit string) string {
	return `{"command_id":"app-renew","tier":"` + tier + `","unit":"` + unit + `","description":"Renew the certificates","root_equivalent":false,` +
		`"capabilities":[],"template":["--all"],"argv":["/usr/local/bin/example-renew","--all"],"cwd":"/","policy_sha256":"` +
		strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

func fakePrivExec(timedOut bool) string {
	return fmt.Sprintf(`{"command_id":"app-renew","argv":["/usr/local/bin/example-renew","--all"],"exit_code":0,"signal":null,
"timed_out":%v,"stdout":"renewed\n","stderr":"","stdout_truncated":false,"stderr_truncated":false,"duration_ms":7}`, timedOut)
}

func newPrivExecHarness(t *testing.T, method approval.Method, tier, unit string) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_exec_preview", gateReply{data: fakePrivExecPreview(shaPX, tier, unit)})
	a.g.set("priv_exec", gateReply{data: fakePrivExec(false)})
	return a
}

func (a *approvalHarness) privExecs() int {
	n := 0
	for _, op := range a.g.ops() {
		if op == "priv_exec" {
			n++
		}
	}
	return n
}

func TestPrivRunCommandRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		if slices.Contains(names(reg.ToolsForProfile(p, nil)), "shell_priv_run_command") {
			t.Fatalf("shell_priv_run_command is registered in the %s profile", p)
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == "shell_priv_run_command" })
	if i < 0 {
		t.Fatal("shell_priv_run_command is not registered in admin")
	}
	r := admin[i]
	a := r.Tool.Def.Annotations
	if r.Tier != TierDestructive || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint ||
		r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
		t.Fatalf("tier %s privileged %v annotations %+v meta %v description %q", r.Tier, r.Privileged, a, r.Tool.Def.Meta, r.Tool.Def.Description)
	}
	s := schemaOf(t, r)
	for _, want := range []string{"target", "command_id", "args", "cwd", "timeout_seconds", "max_output_bytes", "approval_id"} {
		if s.Properties[want] == nil {
			t.Fatalf("no %s in %s", want, jsonOf(t, s))
		}
	}
	// No stdin (Q11), and neither the routing label nor the precondition is
	// an input.
	for _, never := range []string{"stdin", "unit", "expected_preview_sha256"} {
		if s.Properties[never] != nil {
			t.Fatalf("%s is an input: %s", never, jsonOf(t, s))
		}
	}
}

// TestPrivRunCommandReadUnapproved: a read command runs without approval,
// under every method: its preview at the tool's ceiling, then priv_exec at
// ceiling read, to the unit the preview reported, with its hash.
func TestPrivRunCommandReadUnapproved(t *testing.T) {
	for _, method := range []approval.Method{approval.MethodNone, approval.MethodWeb} {
		for _, unit := range []string{"core", "broad"} {
			t.Run(string(method)+"/"+unit, func(t *testing.T) {
				a := newPrivExecHarness(t, method, "read", unit)
				env, _ := a.call("shell_priv_run_command", privRunArgs)
				if d := data(t, env); d["stdout"] != "renewed\n" || env["approval"] != nil {
					t.Fatalf("env %v", env)
				}
				reqs := a.g.requests()
				if len(reqs) != 2 || reqs[0].Op != "priv_exec_preview" || reqs[0].Ceiling != "destructive" || reqs[1].Op != "priv_exec" || reqs[1].Ceiling != "read" {
					t.Fatalf("requests %+v", reqs)
				}
				pa := a.g.args(t, "priv_exec_preview")
				if len(pa) != 3 || pa["command_id"] != "app-renew" || pa["cwd"] != "" || fmt.Sprint(pa["args"]) != "[--all]" {
					t.Fatalf("preview args %v", pa)
				}
				ea := a.g.args(t, "priv_exec")
				if ea["expected_preview_sha256"] != shaPX || ea["unit"] != unit || ea["command_id"] != "app-renew" || ea["stdin_b64"] != nil {
					t.Fatalf("exec args %v", ea)
				}
			})
		}
	}
}

func TestPrivRunCommandGatedUnderNone(t *testing.T) {
	for _, tier := range []string{"operator", "destructive"} {
		a := newPrivExecHarness(t, approval.MethodNone, tier, "core")
		if env, _ := a.call("shell_priv_run_command", privRunArgs); errCode(env) != "approval_unavailable" {
			t.Fatalf("%s: %v", tier, env)
		}
		if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_exec_preview"}) {
			t.Fatalf("%s: sent %v", tier, ops)
		}
	}
}

// TestPrivRunCommandApprovalFlow: an operator or destructive command, in
// either unit: the first call sends only the preview and shows the unit;
// the approved re-call previews again and sends priv_exec once, to that
// unit, at the command's tier, with the fresh preview's hash; a second
// re-call is approval_invalid.
func TestPrivRunCommandApprovalFlow(t *testing.T) {
	for _, tier := range []string{"operator", "destructive"} {
		for _, unit := range []string{"core", "broad"} {
			t.Run(tier+"/"+unit, func(t *testing.T) {
				a := newPrivExecHarness(t, approval.MethodWeb, tier, unit)
				name := "shell_priv_run_command"
				id := a.pending(name, privRunArgs)
				if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_exec_preview"}) {
					t.Fatalf("first call sent %v", ops)
				}
				pm := previewMap(t, a, id)
				for k, v := range map[string]string{"command_id": "app-renew", "tier": tier, "unit": unit, "argv[0]": "/usr/local/bin/example-renew",
					"argv[1]": "--all", "template[0]": "--all", "cwd": "/", "description": "Renew the certificates", "preview_sha256": shaPX} {
					if pm[k] != v {
						t.Fatalf("preview %s = %q, want %q (all %v)", k, pm[k], v, pm)
					}
				}
				rec, _ := a.store.Get(id)
				if want := "As root, run command app-renew with 1 argument in the " + unit + " unit on app-host"; rec.Description != want {
					t.Fatalf("description %q, want %q", rec.Description, want)
				}
				a.approve(id)
				env, _ := a.call(name, withID(privRunArgs, id))
				if d := data(t, env); d["stdout"] != "renewed\n" {
					t.Fatalf("data %v", d)
				}
				if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_exec_preview", "priv_exec_preview", "priv_exec"}) {
					t.Fatalf("ops %v", ops)
				}
				reqs := a.g.requests()
				if reqs[2].Ceiling != tier {
					t.Fatalf("priv_exec at ceiling %s", reqs[2].Ceiling)
				}
				if ea := a.g.args(t, "priv_exec"); ea["expected_preview_sha256"] != shaPX || ea["unit"] != unit {
					t.Fatalf("exec args %v", ea)
				}
				env, _ = a.call(name, withID(privRunArgs, id))
				if errCode(env) != "approval_invalid" || a.privExecs() != 1 {
					t.Fatalf("second re-call %v, %d execs", env, a.privExecs())
				}
				if strings.Contains(a.logs.String(), shaPX) {
					t.Fatal("the preview hash reached the server's logs")
				}
			})
		}
	}
}

// TestPrivRunCommandNoRetryOnWrongUnit (Q5): the instance's
// helper_wrong_unit is the tool's result; nothing is sent to the other
// unit.
func TestPrivRunCommandNoRetryOnWrongUnit(t *testing.T) {
	wrong := gateReply{code: "helper_wrong_unit", msg: "this operation runs in the broad unit; this is the core unit's helper, so it was not executed"}
	a := newPrivExecHarness(t, approval.MethodWeb, "operator", "core")
	id := a.pending("shell_priv_run_command", privRunArgs)
	a.approve(id)
	a.g.set("priv_exec", wrong)
	if env, _ := a.call("shell_priv_run_command", withID(privRunArgs, id)); errCode(env) != "helper_wrong_unit" || a.privExecs() != 1 {
		t.Fatalf("env %v, %d execs (ops %v)", env, a.privExecs(), a.g.ops())
	}
	r := newPrivExecHarness(t, approval.MethodNone, "read", "core")
	r.g.set("priv_exec", wrong)
	if env, _ := r.call("shell_priv_run_command", privRunArgs); errCode(env) != "helper_wrong_unit" || r.privExecs() != 1 {
		t.Fatalf("read: env %v, %d execs", env, r.privExecs())
	}
	if ea := r.g.args(t, "priv_exec"); ea["unit"] != "core" {
		t.Fatalf("exec args %v", ea)
	}
}

// TestPrivRunCommandChangedAfterApproval: the preview's hash, the unit, the
// tier, the privileged policy or the gate policy changed after approval is
// approval_invalid, and nothing runs.
func TestPrivRunCommandChangedAfterApproval(t *testing.T) {
	for name, change := range map[string]func(a *approvalHarness){
		"hash":   func(a *approvalHarness) { a.g.set("priv_exec_preview", gateReply{data: fakePrivExecPreview(shaPX2, "operator", "core")}) },
		"unit":   func(a *approvalHarness) { a.g.set("priv_exec_preview", gateReply{data: fakePrivExecPreview(shaPX, "operator", "broad")}) },
		"tier":   func(a *approvalHarness) { a.g.set("priv_exec_preview", gateReply{data: fakePrivExecPreview(shaPX, "destructive", "core")}) },
		"helper": func(a *approvalHarness) { a.g.setHelperSHA("f00d") },
		"gate":   func(a *approvalHarness) { a.g.setSHA("f00d") },
	} {
		t.Run(name, func(t *testing.T) {
			a := newPrivExecHarness(t, approval.MethodWeb, "operator", "core")
			id := a.pending("shell_priv_run_command", privRunArgs)
			a.approve(id)
			change(a)
			if env, _ := a.call("shell_priv_run_command", withID(privRunArgs, id)); errCode(env) != "approval_invalid" || a.privExecs() != 0 {
				t.Fatalf("env %v, %d execs", env, a.privExecs())
			}
		})
	}
}

// TestPrivRunCommandRaisedAfterPreview: an unapproved read command is sent
// at ceiling read, so one raised to operator after its preview is refused
// by the helper's tier check, which is the result.
func TestPrivRunCommandRaisedAfterPreview(t *testing.T) {
	a := newPrivExecHarness(t, approval.MethodWeb, "read", "core")
	a.g.set("priv_exec", gateReply{code: "tier_denied", msg: "command tier operator exceeds the request's ceiling read"})
	if env, _ := a.call("shell_priv_run_command", privRunArgs); errCode(env) != "tier_denied" {
		t.Fatalf("env %v", env)
	}
	if reqs := a.g.requests(); len(reqs) != 2 || reqs[1].Ceiling != "read" {
		t.Fatalf("requests %+v", reqs)
	}
}

// TestPrivRunCommandPreviewRefusals: the preview's refusals are the result,
// with no approval requested and nothing run; a preview without the helper
// block, or naming no known unit or tier, is internal.
func TestPrivRunCommandPreviewRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		reply gateReply
		code  string
	}{
		"undeclared":   {gateReply{code: "policy_denied", msg: "command_id is not declared in the privileged policy"}, "policy_denied"},
		"no template":  {gateReply{code: "template_mismatch", msg: "arguments match no template of this command"}, "template_mismatch"},
		"tier":         {gateReply{code: "tier_denied", msg: "command tier destructive exceeds the privileged policy's max_tier operator"}, "tier_denied"},
		"path":         {gateReply{code: "path_denied", msg: "path argument: outside the roots"}, "path_denied"},
		"no helper":    {gateReply{data: fakePrivExecPreview(shaPX, "operator", "core"), noHelper: true}, "internal"},
		"no unit":      {gateReply{data: fakePrivExecPreview(shaPX, "operator", "sideways")}, "internal"},
		"no tier":      {gateReply{data: fakePrivExecPreview(shaPX, "admin", "core")}, "internal"},
		"invalid hash": {gateReply{data: fakePrivExecPreview("zz", "operator", "core")}, "internal"},
	} {
		t.Run(name, func(t *testing.T) {
			a := newPrivExecHarness(t, approval.MethodWeb, "operator", "core")
			a.g.set("priv_exec_preview", c.reply)
			env, _ := a.call("shell_priv_run_command", privRunArgs)
			if errCode(env) != c.code || env["approval"] != nil || a.privExecs() != 0 {
				t.Fatalf("env %v, %d execs", env, a.privExecs())
			}
		})
	}
}

// TestPrivRunCommandOutcomeUnknown (must-fix (b)): a timeout, or an answer
// lost after the request was sent, on an approved command (and on every
// other privileged operation that can change the host) is a timeout whose
// message says the outcome is unknown and the approval was used; on a read
// command or a read operation it stays what it was.
func TestPrivRunCommandOutcomeUnknown(t *testing.T) {
	timeout := gateReply{code: "timeout", msg: "the privileged helper did not answer in time"}
	for name, reply := range map[string]gateReply{"timeout": timeout, "lost": {silent: true}} {
		t.Run(name, func(t *testing.T) {
			a := newPrivExecHarness(t, approval.MethodWeb, "operator", "core")
			id := a.pending("shell_priv_run_command", privRunArgs)
			a.approve(id)
			a.g.set("priv_exec", reply)
			env, _ := a.call("shell_priv_run_command", withID(privRunArgs, id))
			msg := jsonOf(t, env["error"])
			if errCode(env) != "timeout" || !strings.Contains(msg, "Outcome unknown") || !strings.Contains(msg, "approval was used") {
				t.Fatalf("env %v", env)
			}
			if ap, _ := env["approval"].(map[string]any); ap["status"] != "used" {
				t.Fatalf("approval %v", env["approval"])
			}
			if env, _ := a.call("shell_priv_run_command", withID(privRunArgs, id)); errCode(env) != "approval_invalid" || a.privExecs() != 1 {
				t.Fatalf("re-call %v", env)
			}
		})
	}
	t.Run("an earlier tool", func(t *testing.T) {
		a := newPrivDeleteHarness(t, approval.MethodWeb)
		id := a.pending("shell_priv_delete_path", privDelArgs)
		a.approve(id)
		a.g.set("priv_delete", gateReply{silent: true})
		env, _ := a.call("shell_priv_delete_path", withID(privDelArgs, id))
		if errCode(env) != "timeout" || !strings.Contains(jsonOf(t, env["error"]), "Outcome unknown") {
			t.Fatalf("env %v", env)
		}
	})
	t.Run("read command", func(t *testing.T) {
		a := newPrivExecHarness(t, approval.MethodWeb, "read", "core")
		a.g.set("priv_exec", timeout)
		env, _ := a.call("shell_priv_run_command", privRunArgs)
		if errCode(env) != "timeout" || strings.Contains(jsonOf(t, env["error"]), "Outcome unknown") {
			t.Fatalf("env %v", env)
		}
	})
	t.Run("read operation", func(t *testing.T) {
		a := newPrivExecHarness(t, approval.MethodWeb, "read", "core")
		a.g.set("priv_read_file", gateReply{silent: true})
		env, _ := a.call("shell_priv_read_file", map[string]any{"path": "/etc/example-app/app.conf"})
		if errCode(env) != "gate_unavailable" {
			t.Fatalf("env %v", env)
		}
	})
}

// TestPrivRunCommandTimedOutWarns: an approved command stopped at its
// timeout is a result with exec.timed_out and a warning that what it
// changed is unknown; a read command's carries no such warning.
func TestPrivRunCommandTimedOutWarns(t *testing.T) {
	a := newPrivExecHarness(t, approval.MethodWeb, "operator", "core")
	a.g.set("priv_exec", gateReply{data: fakePrivExec(true)})
	id := a.pending("shell_priv_run_command", privRunArgs)
	a.approve(id)
	env, _ := a.call("shell_priv_run_command", withID(privRunArgs, id))
	ex, _ := env["exec"].(map[string]any)
	if env["ok"] != true || ex["timed_out"] != true || !strings.Contains(jsonOf(t, env["warnings"]), "unknown") {
		t.Fatalf("env %v", env)
	}
	r := newPrivExecHarness(t, approval.MethodNone, "read", "core")
	r.g.set("priv_exec", gateReply{data: fakePrivExec(true)})
	env, _ = r.call("shell_priv_run_command", privRunArgs)
	if env["ok"] != true || strings.Contains(jsonOf(t, env["warnings"]), "unknown") {
		t.Fatalf("read env %v", env)
	}
}

func TestPrivRunCommandValidation(t *testing.T) {
	a := newPrivExecHarness(t, approval.MethodWeb, "read", "core")
	for _, args := range []map[string]any{
		{"command_id": "app-renew", "args": []string{"--all"}, "stdin": "yes\n"},
		{"command_id": "app-renew", "args": []string{"--all"}, "unit": "broad"},
		{"command_id": "app-renew", "args": []string{"--all"}, "expected_preview_sha256": shaPX},
		{"command_id": "Bad Id", "args": []string{}},
		{"command_id": "app-renew", "args": []string{"a\nb"}},
		{"command_id": "app-renew", "cwd": "relative"},
	} {
		if env, _ := a.call("shell_priv_run_command", args); errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", args, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}
