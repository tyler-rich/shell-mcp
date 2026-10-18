package tools

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// shell_run_command's two registrations (docs/TOOLS.md): at operator in the
// operator profile, at destructive (always approval-gated) in the admin
// profile; and its approval preview, the gate's exec_preview, whose hash the
// re-call sends to exec as expected_preview_sha256. Commands, paths and
// hashes are invented.

const (
	shaExec  = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
	shaExec2 = "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"
)

func fakeExecPreview(sha, tier string) string {
	return fmt.Sprintf(`{"command_id":"app-restart","tier":%q,"description":"Restart the application","root_equivalent":false,`+
		`"template":["restart"],"argv":["/usr/local/bin/example-app","restart"],"cwd":"/","policy_sha256":"ab12","preview_sha256":%q}`, tier, sha)
}

func runCommandReplies(tier string) map[string]gateReply {
	r := approvalReplies()
	r["exec_preview"] = gateReply{data: fakeExecPreview(shaExec, tier)}
	r["exec"] = gateReply{data: fakeExec("restarted\n", 0)}
	return r
}

func runCommandOf(t *testing.T, p Profile) Registration {
	t.Helper()
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	regs := reg.ToolsForProfile(p, nil)
	i := slices.IndexFunc(regs, func(r Registration) bool { return r.Tool.Def.Name == "shell_run_command" })
	if i < 0 {
		t.Fatalf("shell_run_command not in %s: %v", p, names(regs))
	}
	return regs[i]
}

func TestRunCommandRegistrations(t *testing.T) {
	if reg, _ := Catalogue(&Deps{}); slices.Contains(names(reg.ToolsForProfile(ProfileReadOnly, nil)), "shell_run_command") {
		t.Fatal("shell_run_command is in the read-only profile")
	}
	op := runCommandOf(t, ProfileOperator)
	if op.Tier != TierOperator || op.Tool.Tier != TierOperator || op.Tool.Def.Annotations.DestructiveHint == nil || *op.Tool.Def.Annotations.DestructiveHint ||
		op.Tool.Def.Meta != nil {
		t.Fatalf("operator registration: tier %s annotations %+v meta %v", op.Tier, op.Tool.Def.Annotations, op.Tool.Def.Meta)
	}
	ad := runCommandOf(t, ProfileAdmin)
	a := ad.Tool.Def.Annotations
	if ad.Tier != TierDestructive || ad.Tool.Tier != TierDestructive || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint ||
		a.IdempotentHint || ad.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || ad.Privileged {
		t.Fatalf("admin registration: tier %s annotations %+v meta %v", ad.Tier, a, ad.Tool.Def.Meta)
	}
	if ad.Tool.Def.Title != op.Tool.Def.Title || ad.Tool.Def.Description == op.Tool.Def.Description ||
		!strings.Contains(ad.Tool.Def.Description, "destructive") || strings.Contains(op.Tool.Def.Description, "destructive") {
		t.Fatalf("descriptions:\n operator %q\n admin %q", op.Tool.Def.Description, ad.Tool.Def.Description)
	}
	// Both take the same inputs; neither takes the precondition.
	for _, r := range []Registration{op, ad} {
		s := schemaOf(t, r)
		if s.Properties["approval_id"] == nil || s.Properties["expected_preview_sha256"] != nil || s.Properties["stdin"] == nil {
			t.Fatalf("%s schema %s", r.Tier, jsonOf(t, s))
		}
	}
}

// operatorHarness serves the operator profile, with operator tools gated.
func operatorApprovalHarness(t *testing.T, g *recordingGate) *approvalHarness {
	t.Helper()
	tg, c := sshTarget(t, g.exec)
	a := newApprovalHarnessOn(t, g, approval.MethodWeb, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, ProfileOperator)
	return a
}

func TestRunCommandAdminApproval(t *testing.T) {
	// Without an approval method the admin registration sends nothing.
	g := newRecordingGate(runCommandReplies("destructive"))
	h := readHarness(t, g)
	if env, _ := h.call("shell_run_command", map[string]any{"command_id": "app-restart", "args": []string{"restart"}}); errCode(env) != "approval_unavailable" ||
		len(g.requests()) != 0 {
		t.Fatalf("method none: %v %v", env, g.ops())
	}

	a := newApprovalHarness(t, approval.MethodWeb)
	for op, r := range runCommandReplies("destructive") {
		a.g.set(op, r)
	}
	args := map[string]any{"command_id": "app-restart", "args": []string{"restart"}, "stdin": "yes\n"}
	id := a.pending("shell_run_command", args)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"exec_preview"}) {
		t.Fatalf("first call sent %v", ops)
	}
	pa := a.g.args(t, "exec_preview")
	if len(pa) != 3 || pa["command_id"] != "app-restart" || pa["cwd"] != "" || fmt.Sprint(pa["args"]) != "[restart]" {
		t.Fatalf("exec_preview args %v", pa)
	}
	pm := previewMap(t, a, id)
	for k, v := range map[string]string{"command_id": "app-restart", "tier": "destructive", "argv[0]": "/usr/local/bin/example-app", "argv[1]": "restart",
		"cwd": "/", "template[0]": "restart", "preview_sha256": shaExec, "root_equivalent": "false", "description": "Restart the application"} {
		if pm[k] != v {
			t.Fatalf("preview %s = %q, want %q (all %v)", k, pm[k], v, pm)
		}
	}
	a.approve(id)
	env, _ := a.call("shell_run_command", withID(args, id))
	if d := data(t, env); d["stdout"] != "restarted\n" {
		t.Fatalf("data %v", d)
	}
	if ops := a.g.ops(); !slices.Equal(ops, []string{"exec_preview", "exec_preview", "exec"}) {
		t.Fatalf("ops %v", ops)
	}
	ea := a.g.args(t, "exec")
	if ea["expected_preview_sha256"] != shaExec || ea["command_id"] != "app-restart" || ea["stdin_b64"] != "eWVzCg==" {
		t.Fatalf("exec args %v", ea)
	}
	for _, q := range a.g.requests() {
		if q.Ceiling != "destructive" {
			t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
		}
	}
	// Run once: a second re-call is invalid and runs nothing.
	env, _ = a.call("shell_run_command", withID(args, id))
	if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 1 {
		t.Fatalf("second re-call %v, mutating %v", env, a.mutatingOps())
	}
	// A changed resolution after approval (another binary, path or policy):
	// approval_invalid and nothing runs.
	id = a.pending("shell_run_command", args)
	a.approve(id)
	a.g.set("exec_preview", gateReply{data: fakeExecPreview(shaExec2, "destructive")})
	env, _ = a.call("shell_run_command", withID(args, id))
	if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 1 {
		t.Fatalf("changed after approval %v, mutating %v", env, a.mutatingOps())
	}
	// The gate's refusal of a stale hash at exec is the result.
	a.g.set("exec_preview", gateReply{data: fakeExecPreview(shaExec, "destructive")})
	id = a.pending("shell_run_command", args)
	a.approve(id)
	a.g.set("exec", gateReply{code: "exists", msg: "the command resolves differently than its preview (preview_sha256 differs); nothing was run"})
	if env, _ = a.call("shell_run_command", withID(args, id)); errCode(env) != "exists" {
		t.Fatalf("stale at exec %v", env)
	}
}

func TestRunCommandOperatorPreviewIsExecPreview(t *testing.T) {
	g := newRecordingGate(runCommandReplies("operator"))
	a := operatorApprovalHarness(t, g)
	args := map[string]any{"command_id": "app-restart", "args": []string{"restart"}}
	id := a.pending("shell_run_command", args)
	a.approve(id)
	if env, _ := a.call("shell_run_command", withID(args, id)); env["ok"] != true {
		t.Fatalf("approved re-call %v", env)
	}
	if ops := a.g.ops(); !slices.Equal(ops, []string{"exec_preview", "exec_preview", "exec"}) {
		t.Fatalf("ops %v", ops)
	}
	for _, q := range a.g.requests() {
		if q.Ceiling != "operator" {
			t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
		}
	}
	if ea := a.g.args(t, "exec"); ea["expected_preview_sha256"] != shaExec {
		t.Fatalf("exec args %v", ea)
	}
	// A destructive command is refused by the gate at ceiling operator; the
	// refusal is the result and no approval is requested.
	a.g.set("exec_preview", gateReply{code: "tier_denied", msg: "command tier destructive exceeds the request's ceiling operator"})
	env, _ := a.call("shell_run_command", map[string]any{"command_id": "app-wipe"})
	if errCode(env) != "tier_denied" || env["approval"] != nil || len(a.mutatingOps()) != 1 {
		t.Fatalf("destructive in operator %v", env)
	}
}

// TestRunCommandUngatedSendsNoPrecondition: in the operator profile with
// the default approval tiers, the call is not gated and exec carries no
// expected hash (the bytes sent are unchanged).
func TestRunCommandUngatedSendsNoPrecondition(t *testing.T) {
	g := newRecordingGate(runCommandReplies("operator"))
	tg, c := sshTarget(t, g.exec)
	h := newHarnessWith(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "", func(d *Deps) { d.Principal.Profile = string(ProfileOperator) })
	env, _ := h.call("shell_run_command", map[string]any{"command_id": "app-restart", "args": []string{"restart"}})
	if env["ok"] != true || !slices.Equal(g.ops(), []string{"exec"}) {
		t.Fatalf("env %v ops %v", env, g.ops())
	}
	if ea := g.args(t, "exec"); len(ea) != 5 || ea["expected_preview_sha256"] != nil {
		t.Fatalf("exec args %v", ea)
	}
}

func schemaOf(t *testing.T, r Registration) *jsonschema.Schema {
	t.Helper()
	s, ok := r.Tool.Def.InputSchema.(*jsonschema.Schema)
	if !ok {
		t.Fatalf("%s: input schema %T", r.Tool.Def.Name, r.Tool.Def.InputSchema)
	}
	return s
}
