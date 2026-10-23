package tools

import (
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// Rule R in the composed previews (handoff docs/handoff/S4C-PRIVILEGED.md
// N-8, P-14; PRIVILEGED §6): priv_backup_check reports which owners a file
// at the path may have (owner_rule), and shell_priv_write_file and
// shell_priv_copy_path refuse, before an approval is requested, what the
// helper would refuse: a new file or copy without an owner (root's) where
// root may not leave one, an owner given that may not own a file there, and
// an overwrite keeping an owner that may not (without both an owner and a
// group, N-6). Make-directory and move do not apply it. The delete preview
// shows the helper's warning that the tools could not restore its backup.
// Every path, name and value is invented.

func backupCheckWith(rule string) gateReply {
	return gateReply{data: `{"written":true,"bytes":11,"fits":true,"store_bytes":2048,"max_store_bytes":1073741824,"owner_rule":` + rule + `}`}
}

const (
	ruleOnlyApp = `{"verdict":"only","uid":1001,"name":"example-app","dir":"/etc/example-app","why":"owned by uid 1001"}`
	ruleNone    = `{"verdict":"none","dir":"/etc/example-app","why":"group- or world-writable (mode 0777)"}`
	// privAppStat is privConf owned by example-app.
	privAppStat = `{"path":"` + privConf + `","name":"app.conf","type":"file","size":11,"mode":"0640","uid":1001,"gid":1001,"owner":"example-app","group":"example-app","mtime":"2026-10-01T00:00:00Z"}`
)

func TestPrivWriteOwnerRule(t *testing.T) {
	noRule := gateReply{data: `{"written":true,"bytes":11,"fits":true,"store_bytes":2048,"max_store_bytes":1073741824}`}
	for _, c := range []struct {
		name   string
		tool   string
		args   map[string]any
		absent bool
		stat   string // the existing destination's stat, when not privStat
		check  gateReply
		code   string // "" when an approval is requested
		msg    string
	}{
		{"only the account: an overwrite keeping root's owner", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n"},
			false, "", backupCheckWith(ruleOnlyApp), "path_denied", "example-app"},
		{"only the account: owner root given", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n", "owner": "root", "group": "root"},
			false, "", backupCheckWith(ruleOnlyApp), "path_denied", "example-app"},
		{"only the account: owner given only", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n", "owner": "example-app"},
			false, "", backupCheckWith(ruleOnlyApp), "path_denied", "group"},
		{"only the account: that account given", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n", "owner": "example-app", "group": "example-app"},
			false, "", backupCheckWith(ruleOnlyApp), "", ""},
		{"only the account: its own file kept", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n"},
			false, privAppStat, backupCheckWith(ruleOnlyApp), "", ""},
		{"only the account: a new file without an owner", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n"},
			true, "", backupCheckWith(ruleOnlyApp), "path_denied", "example-app"},
		{"only the account: a new file of that account", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n", "owner": "example-app"},
			true, "", backupCheckWith(ruleOnlyApp), "", ""},
		{"none: a new file of any owner", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n", "owner": "example-app", "group": "example-app"},
			true, "", backupCheckWith(ruleNone), "path_denied", "/etc/example-app"},
		{"none: a new copy", "shell_priv_copy_path", map[string]any{"source": privSrc, "destination": privConf},
			true, "", backupCheckWith(ruleNone), "path_denied", "/etc/example-app"},
		{"only the account: a new copy", "shell_priv_copy_path", map[string]any{"source": privSrc, "destination": privConf},
			true, "", backupCheckWith(ruleOnlyApp), "path_denied", "example-app"},
		{"only the account: a copy over its own file", "shell_priv_copy_path", map[string]any{"source": privSrc, "destination": privConf, "overwrite": true},
			false, privAppStat, backupCheckWith(ruleOnlyApp), "", ""},
		{"only the account: a copy over root's file", "shell_priv_copy_path", map[string]any{"source": privSrc, "destination": privConf, "overwrite": true},
			false, "", backupCheckWith(ruleOnlyApp), "path_denied", "example-app"},
		{"no owner rule (an older helper)", "shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n"},
			false, "", noRule, "internal", "owner"},
		{"a make-directory is not concerned", "shell_priv_make_directory", map[string]any{"path": privDir},
			false, "", backupCheckWith(ruleNone), "", ""},
		{"a move is not concerned (N-17)", "shell_priv_move_path", map[string]any{"source": privSrc, "destination": privConf, "overwrite": true},
			false, "", backupCheckWith(ruleNone), "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newPrivWriteHarness(t, approval.MethodWeb)
			dst := privConf
			if c.tool == "shell_priv_make_directory" {
				dst = privDir
				a.g.setPath("priv_stat", privDir, privNotFound())
			}
			if c.absent {
				privAbsent(a.g, dst)
			}
			if c.stat != "" {
				a.g.setPath("priv_stat", dst, gateReply{data: c.stat})
			}
			a.g.set("priv_backup_check", c.check)
			a.g.setPath("priv_backup_check", dst, c.check)
			env, _ := a.call(c.tool, c.args)
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

// TestPrivDeletePreviewRestoreWarning: the helper's warning that the tools
// could not restore the delete's backup is on the approval page (and so
// bound by its hash), and in the read tool's warnings.
func TestPrivDeletePreviewRestoreWarning(t *testing.T) {
	warn := "the tools won't be able to restore 3 entries of this backup: " + privDelTree +
		": its recorded owner (uid 0) would land under the directory /etc/example-app, which is owned by uid 1001"
	a := newPrivDeleteHarness(t, approval.MethodWeb)
	a.g.set("priv_delete_preview", gateReply{data: fakeDeletePreview(shaDel), warnings: []string{warn}})
	id := a.pending("shell_priv_delete_path", privDelArgs)
	if p := previewMap(t, a, id); p["backup.restore"] != warn {
		t.Fatalf("approval preview %v, want backup.restore %q", p, warn)
	}
	b := newPrivDeleteHarness(t, approval.MethodNone)
	b.g.set("priv_delete_preview", gateReply{data: fakeDeletePreview(shaDel), warnings: []string{warn}})
	env, _ := b.call("shell_priv_preview_delete", privDelArgs)
	if ws, _ := env["warnings"].([]any); len(ws) != 1 || ws[0] != warn {
		t.Fatalf("read tool warnings %v", env["warnings"])
	}
	// A restorable backup: nothing on the page.
	c := newPrivDeleteHarness(t, approval.MethodWeb)
	id = c.pending("shell_priv_delete_path", privDelArgs)
	if p := previewMap(t, c, id); p["backup.restore"] != "" {
		t.Fatalf("a restorable backup shows %q", p["backup.restore"])
	}
}
