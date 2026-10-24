package tools

import (
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// shell_priv_copy_path's owner and group (handoff
// docs/handoff/S4C-PRIVILEGED.md N-19, P-15): optional, validated as
// shell_priv_write_file's; the preview shows them as what will be set, and
// rule R's verdict (P-14) refuses before an approval is requested a copy
// whose owner may not be left there; the approval binds them; the helper
// gets them only when given. Every path, name and value is invented.

func withArgs(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// TestPrivCopyOwnerRule: the copy's own cases of rule R in the preview.
func TestPrivCopyOwnerRule(t *testing.T) {
	newCopy := map[string]any{"source": privSrc, "destination": privConf}
	overCopy := map[string]any{"source": privSrc, "destination": privConf, "overwrite": true}
	app := map[string]any{"owner": "example-app", "group": "example-app"}
	for _, c := range []struct {
		name   string
		args   map[string]any
		absent bool
		stat   string
		rule   string
		code   string // "" when an approval is requested
		msg    string
	}{
		{"only the account: a new copy given that account", withArgs(newCopy, app), true, "", ruleOnlyApp, "", ""},
		{"only the account: a new copy given only that owner", withArgs(newCopy, map[string]any{"owner": "example-app"}), true, "", ruleOnlyApp, "", ""},
		{"only the account: a new copy given owner root", withArgs(newCopy, map[string]any{"owner": "root", "group": "root"}), true, "", ruleOnlyApp, "path_denied", "example-app"},
		{"only the account: a new copy given only a group", withArgs(newCopy, map[string]any{"group": "example-app"}), true, "", ruleOnlyApp, "path_denied", "example-app"},
		{"only the account: over root's file, given that account", withArgs(overCopy, app), false, "", ruleOnlyApp, "", ""},
		{"only the account: over root's file, given only the owner", withArgs(overCopy, map[string]any{"owner": "example-app"}), false, "", ruleOnlyApp, "path_denied", "group"},
		{"only the account: over its own file, given owner root", withArgs(overCopy, map[string]any{"owner": "root", "group": "root"}), false, privAppStat, ruleOnlyApp, "path_denied", "example-app"},
		{"none: a new copy given any owner", withArgs(newCopy, app), true, "", ruleNone, "path_denied", "/etc/example-app"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newPrivWriteHarness(t, approval.MethodWeb)
			if c.absent {
				privAbsent(a.g, privConf)
			}
			if c.stat != "" {
				a.g.setPath("priv_stat", privConf, gateReply{data: c.stat})
			}
			a.g.set("priv_backup_check", backupCheckWith(c.rule))
			a.g.setPath("priv_backup_check", privConf, backupCheckWith(c.rule))
			env, _ := a.call("shell_priv_copy_path", c.args)
			if c.code == "" {
				if errCode(env) != "approval_pending" {
					t.Fatalf("%v, want an approval requested", env)
				}
				return
			}
			e, _ := env["error"].(map[string]any)
			msg, _ := e["message"].(string)
			if errCode(env) != c.code || !strings.Contains(msg, c.msg) || env["approval"] != nil {
				t.Fatalf("%v, want %s (%q) and no approval", env, c.code, c.msg)
			}
			if m := a.privMutatingOps(); len(m) != 0 {
				t.Fatalf("sent %v", m)
			}
		})
	}
}

// TestPrivCopyOwnerPreview: the approver sees the owner and group given as
// what will be set, for a new copy and over a file; without them, root's
// and kept, as before.
func TestPrivCopyOwnerPreview(t *testing.T) {
	for _, absent := range []bool{true, false} {
		a := newPrivWriteHarness(t, approval.MethodWeb)
		if absent {
			privAbsent(a.g, privConf)
		}
		id := a.pending("shell_priv_copy_path", withArgs(privWriteArgs["shell_priv_copy_path"], map[string]any{"owner": "example-app", "group": "example-app"}))
		p := previewMap(t, a, id)
		if p["set.owner"] != "example-app" || p["set.group"] != "example-app" {
			t.Fatalf("absent %v: preview %v", absent, p)
		}
	}
	b := newPrivWriteHarness(t, approval.MethodWeb)
	privAbsent(b.g, privConf)
	id := b.pending("shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"])
	if p := previewMap(t, b, id); !strings.HasPrefix(p["set.owner"], "root") || !strings.HasPrefix(p["set.group"], "root") {
		t.Fatalf("a new copy without an owner: %v", p)
	}
}

// TestPrivCopyOwnerWireAndBinding: the approved re-call sends the owner and
// group to the helper; a copy without them sends neither key (an older
// helper refuses unknown keys); a re-call with another owner than the one
// approved is approval_invalid and sends nothing.
func TestPrivCopyOwnerWireAndBinding(t *testing.T) {
	owned := withArgs(privWriteArgs["shell_priv_copy_path"], map[string]any{"owner": "example-app", "group": "example-app"})
	a := newPrivWriteHarness(t, approval.MethodWeb)
	id := a.pending("shell_priv_copy_path", owned)
	a.approve(id)
	if env, _ := a.call("shell_priv_copy_path", withID(owned, id)); env["ok"] != true {
		t.Fatalf("approved re-call: %v", env)
	}
	if w := a.g.args(t, "priv_copy"); w["owner"] != "example-app" || w["group"] != "example-app" {
		t.Fatalf("sent %v", w)
	}
	b := newPrivWriteHarness(t, approval.MethodWeb)
	id = b.pending("shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"])
	b.approve(id)
	if env, _ := b.call("shell_priv_copy_path", withID(privWriteArgs["shell_priv_copy_path"], id)); env["ok"] != true {
		t.Fatalf("approved re-call: %v", env)
	}
	w := b.g.args(t, "priv_copy")
	_, ho := w["owner"]
	_, hg := w["group"]
	if ho || hg {
		t.Fatalf("a copy without an owner sent %v", w)
	}
	c := newPrivWriteHarness(t, approval.MethodWeb)
	id = c.pending("shell_priv_copy_path", owned)
	c.approve(id)
	other := withArgs(owned, map[string]any{"owner": "root"})
	if env, _ := c.call("shell_priv_copy_path", withID(other, id)); errCode(env) != "approval_invalid" {
		t.Fatalf("a re-call with another owner: %v", env)
	}
	if m := c.privMutatingOps(); len(m) != 0 {
		t.Fatalf("sent %v", m)
	}
}

// TestPrivCopyOwnerValidated: an owner or group that is not a user or group
// name is validation_error, as for a write, and nothing is sent.
func TestPrivCopyOwnerValidated(t *testing.T) {
	for _, extra := range []map[string]any{{"owner": "Root"}, {"group": "a b"}, {"owner": strings.Repeat("a", 33)}} {
		a := newPrivWriteHarness(t, approval.MethodWeb)
		env, _ := a.call("shell_priv_copy_path", withArgs(privWriteArgs["shell_priv_copy_path"], extra))
		if errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", extra, env)
		}
		if ops := a.g.ops(); len(ops) != 0 {
			t.Fatalf("%v: sent %v", extra, ops)
		}
	}
}
