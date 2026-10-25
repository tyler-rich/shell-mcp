package tools

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// The privileged restore tool (S4c-5; docs/TOOLS.md, privileged tier;
// handoff docs/handoff/S4C-PRIVILEGED.md D3, P-2c, P-3, P-10):
// shell_priv_restore_backup (operator, admin only, always approval-gated),
// whose preview is the helper's priv_restore_preview and whose re-call
// sends that fresh preview's hash as expected_preview_sha256. Every path,
// id and hash is invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_restore_backup")
}

const (
	restoreID    = "20261019T120000Z-0123456789abcdef"
	restorePath  = "/etc/example-app/app.conf"
	shaRes       = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
	shaRes2      = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
	shaBackup    = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
	shaCurrent   = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	privRestored = `{"id":"` + restoreID + `","path":"` + restorePath + `","kind":"file","sha256":"` + shaBackup +
		`","verified":true,"backup_ids":["20261019T120001Z-fedcba9876543210"],"mode":"0600","recorded_mode":"0644","narrowed":1,"first":[],"truncated":false}`
)

func fakeRestorePreview(sha string) string {
	return `{"id":"` + restoreID + `","kind":"file","path":"` + restorePath + `","backup":{"size":11,"sha256":"` + shaBackup +
		`","entries":0,"uid":0,"gid":4200004,"owner":"root","group":"example-app","mode":"0644","created":"2026-10-19T12:00:00Z","op":"priv_write_file"},` +
		`"current":{"state":"file","size":7,"mode":"0600","uid":0,"gid":4200004,"owner":"root","group":"example-app","sha256":"` + shaCurrent + `"},` +
		`"restore":{"uid":0,"gid":4200004,"mode":"0600","recorded_mode":"0644","narrowed":1,"first":[],"truncated":false},` +
		`"current_backup":{"written":true,"bytes":7},"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

var privRestoreArgs = map[string]any{"backup_id": restoreID}

func newPrivRestoreHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_restore_preview", gateReply{data: fakeRestorePreview(shaRes)})
	a.g.set("priv_restore_backup", gateReply{data: privRestored})
	return a
}

func TestPrivRestoreToolRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	const name = "shell_priv_restore_backup"
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		if slices.Contains(names(reg.ToolsForProfile(p, nil)), name) {
			t.Fatalf("%s is registered in the %s profile", name, p)
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == name })
	if i < 0 {
		t.Fatalf("%s is not registered in admin", name)
	}
	r := admin[i]
	a := r.Tool.Def.Annotations
	s := schemaOf(t, r)
	if !r.Privileged || r.Tier != TierOperator || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
		t.Fatalf("privileged %v tier %s description %q", r.Privileged, r.Tier, r.Tool.Def.Description)
	}
	if a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint ||
		r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || s.Properties["approval_id"] == nil {
		t.Fatalf("annotations %+v meta %v", a, r.Tool.Def.Meta)
	}
	if p := s.Properties["backup_id"]; p == nil || p.Type != "string" || p.Pattern == "" || s.Properties["expected_preview_sha256"] != nil || s.Properties["path"] != nil {
		t.Fatalf("schema %+v", s.Properties)
	}
}

func TestPrivRestoreUnderNone(t *testing.T) {
	a := newPrivRestoreHarness(t, approval.MethodNone)
	if env, _ := a.call("shell_priv_restore_backup", privRestoreArgs); errCode(env) != "approval_unavailable" {
		t.Fatalf("%v", env)
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivRestoreApprovalFlow: the first call sends only the helper's
// preview, at ceiling operator, and shows the backup, the current file and
// both modes; the approved re-call previews again and sends the restore
// once with that preview's hash; a second re-call is approval_invalid.
func TestPrivRestoreApprovalFlow(t *testing.T) {
	a := newPrivRestoreHarness(t, approval.MethodWeb)
	name := "shell_priv_restore_backup"
	id := a.pending(name, privRestoreArgs)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_restore_preview"}) {
		t.Fatalf("first call sent %v", ops)
	}
	pm := previewMap(t, a, id)
	if pm["backup.sha256"] != shaBackup || pm["backup.mode"] != "0644" || pm["current.sha256"] != shaCurrent || pm["current.state"] != "file" ||
		pm["restore.mode"] != "0600" || pm["restore.recorded_mode"] != "0644" || pm["restore.narrowed"] != "1" || pm["current_backup.written"] != "true" ||
		pm["path"] != restorePath || pm["preview_sha256"] != shaRes {
		t.Fatalf("approval preview %v", pm)
	}
	a.approve(id)
	env, _ := a.call(name, withID(privRestoreArgs, id))
	d := data(t, env)
	if ops := a.g.ops(); !slices.Equal(ops, []string{"priv_restore_preview", "priv_restore_preview", "priv_restore_backup"}) {
		t.Fatalf("ops %v", ops)
	}
	for _, q := range a.g.requests() {
		if q.Ceiling != "operator" {
			t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
		}
	}
	if w := a.g.args(t, "priv_restore_backup"); w["id"] != restoreID || w["expected_preview_sha256"] != shaRes || len(w) != 2 {
		t.Fatalf("priv_restore_backup args %v", w)
	}
	ids, _ := d["backup_ids"].([]any)
	if d["path"] != restorePath || d["kind"] != "file" || d["mode"] != "0600" || d["recorded_mode"] != "0644" || d["narrowed"] != 1.0 || len(ids) != 1 {
		t.Fatalf("data %v", d)
	}
	if env["verified"] != true {
		t.Fatalf("envelope verified %v", env["verified"])
	}
	if env, _ := a.call(name, withID(privRestoreArgs, id)); errCode(env) != "approval_invalid" {
		t.Fatalf("second re-call: %v", env)
	}
	if m := a.privMutatingOps(); len(m) != 1 {
		t.Fatalf("mutating %v", m)
	}
	if logs := a.logs.String(); strings.Contains(logs, shaRes) || !strings.Contains(logs, restoreID) {
		t.Fatalf("logs: %s", logs)
	}
}

// TestPrivRestoreChangedAfterApproval: the backup or the current file (the
// preview's hash), or either policy, changing after approval is
// approval_invalid, and nothing is restored.
func TestPrivRestoreChangedAfterApproval(t *testing.T) {
	for what, edit := range map[string]func(g *recordingGate){
		"backup or current file": func(g *recordingGate) { g.set("priv_restore_preview", gateReply{data: fakeRestorePreview(shaRes2)}) },
		"privileged policy":      func(g *recordingGate) { g.setHelperSHA("beef") },
		"gate policy":            func(g *recordingGate) { g.setSHA("ef56") },
	} {
		t.Run(what, func(t *testing.T) {
			a := newPrivRestoreHarness(t, approval.MethodWeb)
			id := a.pending("shell_priv_restore_backup", privRestoreArgs)
			a.approve(id)
			edit(a.g)
			env, _ := a.call("shell_priv_restore_backup", withID(privRestoreArgs, id))
			if errCode(env) != "approval_invalid" || len(a.privMutatingOps()) != 0 {
				t.Fatalf("after the %s changed: %v, sent %v", what, env, a.g.ops())
			}
		})
	}
}

// TestPrivRestorePreviewRefusals: a helper refusal of the preview is the
// result, and no approval is requested; a preview without a helper block
// requests none either.
func TestPrivRestorePreviewRefusals(t *testing.T) {
	for _, code := range []string{"verify_failed", "path_denied", "exists", "backup_failed", "not_found", "too_large"} {
		a := newPrivRestoreHarness(t, approval.MethodWeb)
		a.g.set("priv_restore_preview", gateReply{code: code, msg: "refused"})
		env, _ := a.call("shell_priv_restore_backup", privRestoreArgs)
		if errCode(env) != code || env["approval"] != nil || len(a.privMutatingOps()) != 0 {
			t.Fatalf("%s: %v", code, env)
		}
	}
	a := newPrivRestoreHarness(t, approval.MethodWeb)
	a.g.setHelperSHA("")
	if env, _ := a.call("shell_priv_restore_backup", privRestoreArgs); errCode(env) != "internal" || env["approval"] != nil {
		t.Fatalf("no helper block: %v", env)
	}
}

// TestPrivRestoreUnverified: a helper answer without verified: true is
// verify_failed, never a success.
func TestPrivRestoreUnverified(t *testing.T) {
	a := newPrivRestoreHarness(t, approval.MethodWeb)
	a.g.set("priv_restore_backup", gateReply{data: strings.Replace(privRestored, `"verified":true`, `"verified":false`, 1)})
	id := a.pending("shell_priv_restore_backup", privRestoreArgs)
	a.approve(id)
	if env, _ := a.call("shell_priv_restore_backup", withID(privRestoreArgs, id)); errCode(env) != "verify_failed" {
		t.Fatalf("%v", env)
	}
}

func TestPrivRestoreValidation(t *testing.T) {
	a := newPrivRestoreHarness(t, approval.MethodWeb)
	for _, args := range []map[string]any{
		{},
		{"backup_id": "../etc"},
		{"backup_id": strings.ToUpper(restoreID)},
		{"backup_id": restoreID, "expected_preview_sha256": shaRes},
		{"backup_id": restoreID, "path": restorePath},
	} {
		if env, _ := a.call("shell_priv_restore_backup", args); errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", args, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivRestorePreconditionIsTheHelpersHash: the hash sent back is the
// helper's, never touched by the server's redaction.
func TestPrivRestorePreconditionIsTheHelpersHash(t *testing.T) {
	a := newPrivRestoreHarness(t, approval.MethodWeb)
	a.deps.Redactor = redact.New([]*regexp.Regexp{regexp.MustCompile(`[0-9a-f]{64}`)})
	id := a.pending("shell_priv_restore_backup", privRestoreArgs)
	a.approve(id)
	env, _ := a.call("shell_priv_restore_backup", withID(privRestoreArgs, id))
	data(t, env)
	if got := a.g.args(t, "priv_restore_backup")["expected_preview_sha256"]; got != shaRes {
		t.Fatalf("expected_preview_sha256 %v", got)
	}
}

func TestPrivRestoreDescription(t *testing.T) {
	a := newPrivRestoreHarness(t, approval.MethodWeb)
	id := a.pending("shell_priv_restore_backup", privRestoreArgs)
	rec, ok := a.store.Get(id)
	if want := "As root, restore backup " + restoreID + " on app-host"; !ok || rec.Description != want {
		t.Fatalf("%q, want %q", rec.Description, want)
	}
}
