package tools

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// The privileged chown and chmod tools (S4c-3; docs/TOOLS.md, privileged
// tier; handoff docs/handoff/S4C-PRIVILEGED.md D2, D4, D9, P-2b, P-3, P-4):
// shell_priv_change_owner and shell_priv_set_permissions, admin only and
// always approval-gated, whose preview is the helper's priv_chown_preview
// or priv_chmod_preview and whose re-call sends that fresh preview's hash
// as expected_preview_sha256. Every path, name and hash is invented.

var privMetaTools = []string{"shell_priv_change_owner", "shell_priv_set_permissions"}

func init() { alwaysGated = append(alwaysGated, privMetaTools...) }

const (
	privTree  = "/etc/example-app/conf.d"
	shaMeta   = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
	shaMeta2  = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
	privOwned = `{"path":"` + privTree + `","old_uid":0,"old_gid":0,"uid":1001,"gid":1001}`
	privModed = `{"path":"` + privTree + `","old_mode":"0755","mode":"0750"}`
)

func fakeMetaPreview(sha string) string {
	return `{"path":"` + privTree + `","type":"dir","entries":3,"changes":2,"first":[` +
		`{"path":"` + privTree + `","type":"dir","uid":0,"gid":0,"owner":"root","group":"root","mode":"0755","new_uid":1001,"new_gid":1001,"new_owner":"example-app","new_group":"example-app","new_mode":"0750"},` +
		`{"path":"` + privTree + `/a.conf","type":"file","uid":0,"gid":0,"owner":"root","group":"root","mode":"0640","new_uid":1001,"new_gid":1001,"new_owner":"example-app","new_group":"example-app","new_mode":"0750"},` +
		`{"path":"` + privTree + `/link","type":"symlink","uid":0,"gid":0,"owner":"root","group":"root","mode":"0777","new_uid":0,"new_gid":0,"new_owner":"root","new_group":"root","new_mode":"0777"}],` +
		`"truncated":false,"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

var privMetaArgs = map[string]map[string]any{
	"shell_priv_change_owner":    {"path": privTree, "owner": "example-app", "group": "example-app", "recursive": true},
	"shell_priv_set_permissions": {"path": privTree, "mode": "0750", "recursive": true},
}

var privMetaOp = map[string]string{"shell_priv_change_owner": "priv_chown", "shell_priv_set_permissions": "priv_chmod"}

func newPrivMetaHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	a.g.set("priv_chown_preview", gateReply{data: fakeMetaPreview(shaMeta)})
	a.g.set("priv_chmod_preview", gateReply{data: fakeMetaPreview(shaMeta)})
	a.g.set("priv_chown", gateReply{data: privOwned})
	a.g.set("priv_chmod", gateReply{data: privModed})
	return a
}

func TestPrivMetaToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, n := range names(reg.ToolsForProfile(p, nil)) {
			if slices.Contains(privMetaTools, n) {
				t.Fatalf("%s is registered in the %s profile", n, p)
			}
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	for _, want := range privMetaTools {
		i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == want })
		if i < 0 {
			t.Fatalf("%s is not registered in admin", want)
		}
		r := admin[i]
		a := r.Tool.Def.Annotations
		if r.Tier != TierOperator || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || !a.IdempotentHint {
			t.Fatalf("%s: tier %s privileged %v annotations %+v", want, r.Tier, r.Privileged, a)
		}
		s := schemaOf(t, r)
		if r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || s.Properties["approval_id"] == nil {
			t.Fatalf("%s: not gated in the catalogue", want)
		}
		if !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
			t.Fatalf("%s: %q", want, r.Tool.Def.Description)
		}
		if p := s.Properties["recursive"]; p == nil || p.Type != "boolean" {
			t.Fatalf("%s: recursive %+v", want, p)
		}
		if s.Properties["expected_preview_sha256"] != nil {
			t.Fatalf("%s takes the preview hash as an input", want)
		}
	}
}

func TestPrivMetaToolsUnderNone(t *testing.T) {
	a := newPrivMetaHarness(t, approval.MethodNone)
	for _, name := range privMetaTools {
		if env, _ := a.call(name, privMetaArgs[name]); errCode(env) != "approval_unavailable" {
			t.Fatalf("%s: %v", name, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivMetaToolsApprovalFlow: the first call sends only the helper's
// preview, at ceiling operator; the approved re-call previews again and
// sends the operation once with that preview's hash; a second re-call is
// approval_invalid.
func TestPrivMetaToolsApprovalFlow(t *testing.T) {
	for _, name := range privMetaTools {
		t.Run(name, func(t *testing.T) {
			a := newPrivMetaHarness(t, approval.MethodWeb)
			op := privMetaOp[name]
			id := a.pending(name, privMetaArgs[name])
			if ops := a.g.ops(); !slices.Equal(ops, []string{op + "_preview"}) {
				t.Fatalf("first call sent %v", ops)
			}
			a.approve(id)
			env, _ := a.call(name, withID(privMetaArgs[name], id))
			d := data(t, env)
			if ops := a.g.ops(); !slices.Equal(ops, []string{op + "_preview", op + "_preview", op}) {
				t.Fatalf("ops %v", ops)
			}
			for _, q := range a.g.requests() {
				if q.Ceiling != "operator" {
					t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
				}
			}
			w := a.g.args(t, op)
			if w["expected_preview_sha256"] != shaMeta || w["recursive"] != true || w["path"] != privTree {
				t.Fatalf("%s args %v", op, w)
			}
			pa := a.g.args(t, op+"_preview")
			if pa["expected_preview_sha256"] != nil || pa["recursive"] != true {
				t.Fatalf("preview args %v", pa)
			}
			if d["path"] != privTree || d["recursive"] != true || d["entries"] != 3.0 || d["changed"] != 2.0 {
				t.Fatalf("data %v", d)
			}
			switch name {
			case "shell_priv_change_owner":
				if w["owner"] != "example-app" || w["group"] != "example-app" || d["uid"] != 1001.0 || d["owner"] != "example-app" {
					t.Fatalf("chown %v %v", w, d)
				}
			default:
				if w["mode"] != "0750" || d["mode"] != "0750" || d["old_mode"] != "0755" {
					t.Fatalf("chmod %v %v", w, d)
				}
			}
			if env, _ := a.call(name, withID(privMetaArgs[name], id)); errCode(env) != "approval_invalid" {
				t.Fatalf("second re-call: %v", env)
			}
			if m := a.privMutatingOps(); len(m) != 1 {
				t.Fatalf("mutating %v", m)
			}
			logs := a.logs.String()
			if strings.Contains(logs, shaMeta) || !strings.Contains(logs, `"recursive":true`) {
				t.Fatalf("logs: %s", logs)
			}
		})
	}
}

// TestPrivMetaChangedAfterApproval: the tree (its preview's hash) or either
// policy changing after approval is approval_invalid, and nothing is sent
// that changes anything.
func TestPrivMetaChangedAfterApproval(t *testing.T) {
	edits := map[string]func(g *recordingGate, op string){
		"tree":              func(g *recordingGate, op string) { g.set(op+"_preview", gateReply{data: fakeMetaPreview(shaMeta2)}) },
		"privileged policy": func(g *recordingGate, _ string) { g.setHelperSHA("beef") },
		"gate policy":       func(g *recordingGate, _ string) { g.setSHA("ef56") },
	}
	for _, name := range privMetaTools {
		for what, edit := range edits {
			t.Run(name+"/"+what, func(t *testing.T) {
				a := newPrivMetaHarness(t, approval.MethodWeb)
				id := a.pending(name, privMetaArgs[name])
				a.approve(id)
				edit(a.g, privMetaOp[name])
				env, _ := a.call(name, withID(privMetaArgs[name], id))
				if errCode(env) != "approval_invalid" || len(a.privMutatingOps()) != 0 {
					t.Fatalf("after the %s changed: %v, sent %v", what, env, a.g.ops())
				}
			})
		}
	}
}

// TestPrivMetaPreviewRefusals: a helper refusal of the preview is the
// result, and no approval is requested.
func TestPrivMetaPreviewRefusals(t *testing.T) {
	for _, name := range privMetaTools {
		a := newPrivMetaHarness(t, approval.MethodWeb)
		a.g.set(privMetaOp[name]+"_preview", gateReply{code: "path_denied", msg: "the directory on its path is world-writable"})
		env, _ := a.call(name, privMetaArgs[name])
		if errCode(env) != "path_denied" || env["approval"] != nil || len(a.privMutatingOps()) != 0 {
			t.Fatalf("%s: %v", name, env)
		}
	}
}

func TestPrivMetaValidation(t *testing.T) {
	a := newPrivMetaHarness(t, approval.MethodWeb)
	for _, c := range []struct {
		name string
		args map[string]any
	}{
		{"shell_priv_change_owner", map[string]any{"path": privTree}},
		{"shell_priv_change_owner", map[string]any{"path": privTree, "owner": "Not A Name"}},
		{"shell_priv_change_owner", map[string]any{"path": "relative", "owner": "root"}},
		{"shell_priv_set_permissions", map[string]any{"path": privTree}},
		{"shell_priv_set_permissions", map[string]any{"path": privTree, "mode": "12345"}},
		{"shell_priv_set_permissions", map[string]any{"path": privTree, "mode": "0750", "expected_preview_sha256": shaMeta}},
	} {
		if env, _ := a.call(c.name, c.args); errCode(env) != "validation_error" {
			t.Fatalf("%s %v: %v", c.name, c.args, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivMetaPreconditionIsTheHelpersHash: the hash sent back is the
// helper's, never touched by the server's redaction.
func TestPrivMetaPreconditionIsTheHelpersHash(t *testing.T) {
	a := newPrivMetaHarness(t, approval.MethodWeb)
	a.deps.Redactor = redact.New([]*regexp.Regexp{regexp.MustCompile(`[0-9a-f]{64}`)})
	name := "shell_priv_set_permissions"
	id := a.pending(name, privMetaArgs[name])
	a.approve(id)
	env, _ := a.call(name, withID(privMetaArgs[name], id))
	data(t, env)
	if got := a.g.args(t, "priv_chmod")["expected_preview_sha256"]; got != shaMeta {
		t.Fatalf("expected_preview_sha256 %v", got)
	}
}

func TestPrivMetaDescriptions(t *testing.T) {
	for _, c := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"shell_priv_change_owner", map[string]any{"path": privTree, "owner": "example-app", "group": "example-app", "recursive": true},
			"As root, change the owner and group of " + privTree + " and everything under it to example-app:example-app on app-host"},
		{"shell_priv_change_owner", map[string]any{"path": privTree, "group": "example-app"},
			"As root, change the group of " + privTree + " to example-app on app-host"},
		{"shell_priv_change_owner", map[string]any{"path": privTree, "owner": "root"},
			"As root, change the owner of " + privTree + " to root on app-host"},
		{"shell_priv_set_permissions", map[string]any{"path": privTree, "mode": "0750", "recursive": true},
			"As root, set the mode of " + privTree + " and everything under it to 0750 on app-host"},
		{"shell_priv_set_permissions", map[string]any{"path": "/etc/example-app/a b", "mode": "0640"},
			"As root, set the mode of a path shown in the arguments to 0640 on app-host"},
	} {
		a := newPrivMetaHarness(t, approval.MethodWeb)
		id := a.pending(c.name, c.args)
		rec, ok := a.store.Get(id)
		if !ok || rec.Description != c.want {
			t.Fatalf("%s %v: %q, want %q", c.name, c.args, rec.Description, c.want)
		}
	}
}
