package tools

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// The privileged delete tools (S4c-4; docs/TOOLS.md, privileged tier;
// handoff docs/handoff/S4C-PRIVILEGED.md D9, D10, P-2a, P-3, Q7):
// shell_priv_preview_delete (read) and shell_priv_delete_path
// (destructive, admin only, always approval-gated), whose preview is the
// helper's priv_delete_preview and whose re-call sends that fresh
// preview's hash as expected_preview_sha256. Every path, name and hash is
// invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_delete_path")
	ceilingCallArgs["shell_priv_preview_delete"] = map[string]any{"path": "/etc/example-app/old.d", "recursive": true}
}

const (
	privDelTree = "/etc/example-app/old.d"
	shaDel      = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
	shaDel2     = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
	privDeleted = `{"path":"` + privDelTree + `","type":"dir","entries":3,"bytes":12,"first":["` + privDelTree + `","` + privDelTree + `/a.conf","` +
		privDelTree + `/b.conf"],"deleted":true,"backup_ids":["20261019T120000Z-0123456789abcdef"]}`
)

func fakeDeletePreview(sha string) string {
	return `{"path":"` + privDelTree + `","type":"dir","entries":3,"bytes":12,"first":["` + privDelTree + `","` + privDelTree + `/a.conf","` +
		privDelTree + `/b.conf"],"truncated":false,"backup":{"written":true,"kind":"tree","bytes":3584},"policy_sha256":"` + strings.Repeat("c", 64) +
		`","preview_sha256":"` + sha + `"}`
}

var privDelArgs = map[string]any{"path": privDelTree, "recursive": true}

func newPrivDeleteHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_delete_preview", gateReply{data: fakeDeletePreview(shaDel)})
	a.g.set("priv_delete", gateReply{data: privDeleted})
	return a
}

func TestPrivDeleteToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	both := []string{"shell_priv_preview_delete", "shell_priv_delete_path"}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, n := range names(reg.ToolsForProfile(p, nil)) {
			if slices.Contains(both, n) {
				t.Fatalf("%s is registered in the %s profile", n, p)
			}
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	for _, want := range both {
		i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == want })
		if i < 0 {
			t.Fatalf("%s is not registered in admin", want)
		}
		r := admin[i]
		a := r.Tool.Def.Annotations
		s := schemaOf(t, r)
		if !r.Privileged || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
			t.Fatalf("%s: privileged %v description %q", want, r.Privileged, r.Tool.Def.Description)
		}
		if p := s.Properties["recursive"]; p == nil || p.Type != "boolean" || s.Properties["expected_preview_sha256"] != nil {
			t.Fatalf("%s: schema %+v", want, s.Properties)
		}
		switch want {
		case "shell_priv_preview_delete":
			if r.Tier != TierRead || !a.ReadOnlyHint || s.Properties["approval_id"] != nil || r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != nil {
				t.Fatalf("%s: tier %s annotations %+v", want, r.Tier, a)
			}
		default:
			if r.Tier != TierDestructive || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint ||
				r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || s.Properties["approval_id"] == nil {
				t.Fatalf("%s: tier %s annotations %+v meta %v", want, r.Tier, a, r.Tool.Def.Meta)
			}
		}
	}
}

// TestPrivPreviewDeleteTool: one priv_delete_preview at ceiling read, never
// gated (also under none), whose result carries the backup and the hash.
func TestPrivPreviewDeleteTool(t *testing.T) {
	a := newPrivDeleteHarness(t, approval.MethodNone)
	env, _ := a.call("shell_priv_preview_delete", privDelArgs)
	d := data(t, env)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_delete_preview"}) {
		t.Fatalf("sent %v", ops)
	}
	q := a.g.requests()[0]
	if q.Ceiling != "read" {
		t.Fatalf("ceiling %s", q.Ceiling)
	}
	if w := a.g.args(t, "priv_delete_preview"); w["path"] != privDelTree || w["recursive"] != true || w["expected_preview_sha256"] != nil {
		t.Fatalf("args %v", w)
	}
	b, _ := d["backup"].(map[string]any)
	if d["path"] != privDelTree || d["entries"] != 3.0 || d["bytes"] != 12.0 || d["preview_sha256"] != shaDel || d["truncated"] != false ||
		b["written"] != true || b["kind"] != "tree" || b["bytes"] != 3584.0 {
		t.Fatalf("data %v", d)
	}
	if first, _ := d["first"].([]any); len(first) != 3 {
		t.Fatalf("first %v", d["first"])
	}
}

func TestPrivDeletePathUnderNone(t *testing.T) {
	a := newPrivDeleteHarness(t, approval.MethodNone)
	if env, _ := a.call("shell_priv_delete_path", privDelArgs); errCode(env) != "approval_unavailable" {
		t.Fatalf("%v", env)
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivDeletePathApprovalFlow: the first call sends only the helper's
// preview, at ceiling destructive, and shows the backup; the approved
// re-call previews again and sends priv_delete once with that preview's
// hash; a second re-call is approval_invalid.
func TestPrivDeletePathApprovalFlow(t *testing.T) {
	a := newPrivDeleteHarness(t, approval.MethodWeb)
	name := "shell_priv_delete_path"
	id := a.pending(name, privDelArgs)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_delete_preview"}) {
		t.Fatalf("first call sent %v", ops)
	}
	pm := previewMap(t, a, id)
	if pm["backup.kind"] != "tree" || pm["backup.written"] != "true" || pm["backup.bytes"] != "3584" || pm["preview_sha256"] != shaDel ||
		pm["entries"] != "3" || pm["first[1]"] != privDelTree+"/a.conf" || pm["recursive"] != "true" {
		t.Fatalf("approval preview %v", pm)
	}
	a.approve(id)
	env, _ := a.call(name, withID(privDelArgs, id))
	d := data(t, env)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_delete_preview", "priv_delete_preview", "priv_delete"}) {
		t.Fatalf("ops %v", ops)
	}
	for _, q := range a.g.requests() {
		if q.Ceiling != "destructive" {
			t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
		}
	}
	w := a.g.args(t, "priv_delete")
	if w["expected_preview_sha256"] != shaDel || w["recursive"] != true || w["path"] != privDelTree {
		t.Fatalf("priv_delete args %v", w)
	}
	ids, _ := d["backup_ids"].([]any)
	if d["path"] != privDelTree || d["deleted"] != true || d["entries"] != 3.0 || len(ids) != 1 {
		t.Fatalf("data %v", d)
	}
	if env, _ := a.call(name, withID(privDelArgs, id)); errCode(env) != "approval_invalid" {
		t.Fatalf("second re-call: %v", env)
	}
	if m := a.privMutatingOps(); len(m) != 1 {
		t.Fatalf("mutating %v", m)
	}
	if logs := a.logs.String(); strings.Contains(logs, shaDel) || !strings.Contains(logs, `"recursive":true`) {
		t.Fatalf("logs: %s", logs)
	}
}

// TestPrivDeletePathChangedAfterApproval: the tree (its preview's hash) or
// either policy changing after approval is approval_invalid, and nothing is
// deleted.
func TestPrivDeletePathChangedAfterApproval(t *testing.T) {
	for what, edit := range map[string]func(g *recordingGate){
		"tree":              func(g *recordingGate) { g.set("priv_delete_preview", gateReply{data: fakeDeletePreview(shaDel2)}) },
		"privileged policy": func(g *recordingGate) { g.setHelperSHA("beef") },
		"gate policy":       func(g *recordingGate) { g.setSHA("ef56") },
	} {
		t.Run(what, func(t *testing.T) {
			a := newPrivDeleteHarness(t, approval.MethodWeb)
			id := a.pending("shell_priv_delete_path", privDelArgs)
			a.approve(id)
			edit(a.g)
			env, _ := a.call("shell_priv_delete_path", withID(privDelArgs, id))
			if errCode(env) != "approval_invalid" || len(a.privMutatingOps()) != 0 {
				t.Fatalf("after the %s changed: %v, sent %v", what, env, a.g.ops())
			}
		})
	}
}

// TestPrivDeletePreviewRefusals: a helper refusal of the preview is the
// result, and no approval is requested; a preview without a helper block
// requests none either.
func TestPrivDeletePreviewRefusals(t *testing.T) {
	for _, code := range []string{"path_denied", "backup_failed", "too_large"} {
		a := newPrivDeleteHarness(t, approval.MethodWeb)
		a.g.set("priv_delete_preview", gateReply{code: code, msg: "refused"})
		env, _ := a.call("shell_priv_delete_path", privDelArgs)
		if errCode(env) != code || env["approval"] != nil || len(a.privMutatingOps()) != 0 {
			t.Fatalf("%s: %v", code, env)
		}
		env, _ = a.call("shell_priv_preview_delete", privDelArgs)
		if errCode(env) != code {
			t.Fatalf("preview tool, %s: %v", code, env)
		}
	}
	a := newPrivDeleteHarness(t, approval.MethodWeb)
	a.g.setHelperSHA("")
	if env, _ := a.call("shell_priv_delete_path", privDelArgs); errCode(env) != "internal" || env["approval"] != nil {
		t.Fatalf("no helper block: %v", env)
	}
}

// TestPrivDeletePathIncomplete: a helper answer without deleted: true is
// internal, never a success.
func TestPrivDeletePathIncomplete(t *testing.T) {
	a := newPrivDeleteHarness(t, approval.MethodWeb)
	a.g.set("priv_delete", gateReply{data: strings.Replace(privDeleted, `"deleted":true`, `"deleted":false`, 1)})
	id := a.pending("shell_priv_delete_path", privDelArgs)
	a.approve(id)
	if env, _ := a.call("shell_priv_delete_path", withID(privDelArgs, id)); errCode(env) != "internal" {
		t.Fatalf("%v", env)
	}
}

func TestPrivDeleteValidation(t *testing.T) {
	a := newPrivDeleteHarness(t, approval.MethodWeb)
	for _, args := range []map[string]any{
		{"path": "relative"},
		{"path": privDelTree, "expected_preview_sha256": shaDel},
		{"path": privDelTree, "recursive": "yes"},
	} {
		for _, name := range []string{"shell_priv_preview_delete", "shell_priv_delete_path"} {
			if env, _ := a.call(name, args); errCode(env) != "validation_error" {
				t.Fatalf("%s %v: %v", name, args, env)
			}
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivDeletePreconditionIsTheHelpersHash: the hash sent back is the
// helper's, never touched by the server's redaction.
func TestPrivDeletePreconditionIsTheHelpersHash(t *testing.T) {
	a := newPrivDeleteHarness(t, approval.MethodWeb)
	a.deps.Redactor = redact.New([]*regexp.Regexp{regexp.MustCompile(`[0-9a-f]{64}`)})
	id := a.pending("shell_priv_delete_path", privDelArgs)
	a.approve(id)
	env, _ := a.call("shell_priv_delete_path", withID(privDelArgs, id))
	data(t, env)
	if got := a.g.args(t, "priv_delete")["expected_preview_sha256"]; got != shaDel {
		t.Fatalf("expected_preview_sha256 %v", got)
	}
}

func TestPrivDeleteDescriptions(t *testing.T) {
	for _, c := range []struct {
		args map[string]any
		want string
	}{
		{privDelArgs, "As root, delete " + privDelTree + " and everything under it on app-host"},
		{map[string]any{"path": privDelTree + "/a.conf"}, "As root, delete " + privDelTree + "/a.conf on app-host"},
		{map[string]any{"path": "/etc/example-app/a b"}, "As root, delete a path shown in the arguments on app-host"},
	} {
		a := newPrivDeleteHarness(t, approval.MethodWeb)
		id := a.pending("shell_priv_delete_path", c.args)
		rec, ok := a.store.Get(id)
		if !ok || rec.Description != c.want {
			t.Fatalf("%v: %q, want %q", c.args, rec.Description, c.want)
		}
	}
}
