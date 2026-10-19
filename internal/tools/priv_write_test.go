package tools

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// The privileged write tools (S4c-2; docs/TOOLS.md, privileged tier;
// handoff docs/handoff/S4C-PRIVILEGED.md D2, D9, P-9, P-11, P-12):
// shell_priv_write_file, shell_priv_make_directory, shell_priv_copy_path
// and shell_priv_move_path, admin only and always approval-gated, with
// previews composed from the helper's read ops and preconditions passed
// through. Every path, hash and value below is an invented fixture.

var privWriteTools = []string{"shell_priv_copy_path", "shell_priv_make_directory", "shell_priv_move_path", "shell_priv_write_file"}

const (
	privConf  = "/etc/example-app/app.conf"
	privSrc   = "/etc/example-app/app.conf.new"
	privDir   = "/etc/example-app/conf.d"
	shaDest   = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
	privStat  = `{"path":"` + privConf + `","name":"app.conf","type":"file","size":11,"mode":"0640","uid":0,"gid":1001,"group":"example-app","mtime":"2026-10-01T00:00:00Z"}`
	privSrcSt = `{"path":"` + privSrc + `","name":"app.conf.new","type":"file","size":4,"mode":"0600","uid":0,"gid":0,"owner":"root","group":"root","mtime":"2026-10-01T00:00:00Z"}`
	privDirSt = `{"path":"/etc/example-app","name":"example-app","type":"dir","size":4096,"mode":"0755","uid":0,"gid":0,"mtime":"2026-10-01T00:00:00Z"}`
	privLink  = `{"path":"` + privConf + `","name":"app.conf","type":"symlink","size":5,"mode":"0777","uid":0,"gid":0,"mtime":"2026-10-01T00:00:00Z","link_target":"other"}`
	privCheck = `{"written":true,"bytes":11,"fits":true,"store_bytes":2048,"max_store_bytes":1073741824}`
	privWrote = `{"path":"` + privConf + `","sha256":"` + shaNew + `","old_sha256":"` + shaOld + `","bytes":4,"created":false,"mode":"0640",
"lines_old":1,"lines_new":1,"owner_preserved":true,"verified":true,"uid":0,"gid":1001,"group":"example-app","backup_ids":["20261001T000000Z-0123456789abcdef"]}`
	privCopied = `{"path":"` + privConf + `","sha256":"` + shaNew + `","old_sha256":"` + shaDest + `","bytes":4,"created":false,"mode":"0640",
"lines_old":1,"lines_new":1,"owner_preserved":true,"verified":true,"uid":0,"gid":1001,"group":"example-app","backup_ids":["20261001T000000Z-0123456789abcdef"]}`
	privMoved = `{"source":"` + privSrc + `","destination":"` + privConf + `","type":"file","replaced":true,"backup_ids":["20261001T000000Z-0123456789abcdef"]}`
	privMade  = `{"path":"` + privDir + `","created":true,"mode":"0750","uid":0,"gid":0,"owner":"root","group":"root"}`
)

func privNotFound() gateReply { return gateReply{code: "not_found", msg: "no such file"} }

// privWriteReplies answers the helper's preview reads and write ops.
func privWriteReplies() map[string]gateReply {
	r := privReplies(allReplies())
	r["priv_stat"] = gateReply{data: privStat}
	r["priv_read_file"] = gateReply{data: fakeReadSHA("key: value\n", shaOld)}
	r["priv_backup_check"] = gateReply{data: privCheck}
	r["priv_write_file"] = gateReply{data: privWrote}
	r["priv_copy"] = gateReply{data: privCopied}
	r["priv_move"] = gateReply{data: privMoved}
	r["priv_mkdir"] = gateReply{data: privMade}
	return r
}

// newPrivWriteHarness serves the admin catalogue with SHELL_MCP_APPROVAL_TIERS
// at its default (destructive): privileged operator tools are gated anyway.
func newPrivWriteHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	g := newRecordingGate(privWriteReplies())
	g.setPath("priv_stat", privSrc, gateReply{data: privSrcSt})
	g.setPath("priv_stat", "/etc/example-app", gateReply{data: privDirSt})
	tg, c := sshTarget(t, g.exec)
	logs := &syncBuffer{}
	store := approval.NewStore(approval.Options{TTL: 300 * time.Second, Method: method, Wait: 300 * time.Millisecond,
		Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	h := newHarnessWith(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "", func(d *Deps) {
		d.ApprovalTiers = []string{"destructive"}
		d.ApprovalMethod = method
		if method != approval.MethodNone {
			d.Approvals = store
		}
		d.ApprovalPublicURL = approvalOrigin
		d.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	})
	return &approvalHarness{harness: h, g: g, store: store, logs: logs}
}

var privMutating = []string{"priv_write_file", "priv_mkdir", "priv_copy", "priv_move", "priv_chmod", "priv_chown", "priv_delete", "priv_restore_backup", "priv_exec"}

func (a *approvalHarness) privMutatingOps() []string {
	var out []string
	for _, op := range a.g.ops() {
		if slices.Contains(privMutating, op) {
			out = append(out, op)
		}
	}
	return out
}

var privWriteArgs = map[string]map[string]any{
	"shell_priv_write_file":     {"path": privConf, "content": "new\n"},
	"shell_priv_make_directory": {"path": privDir},
	"shell_priv_copy_path":      {"source": privSrc, "destination": privConf, "overwrite": true},
	"shell_priv_move_path":      {"source": privSrc, "destination": privConf, "overwrite": true},
}

var privWriteOp = map[string]string{
	"shell_priv_write_file": "priv_write_file", "shell_priv_make_directory": "priv_mkdir",
	"shell_priv_copy_path": "priv_copy", "shell_priv_move_path": "priv_move",
}

// The privileged write tools are always gated: their ceiling is checked
// through the approval flow (TestPrivWriteToolsApprovalFlow).
func init() { alwaysGated = append(alwaysGated, privWriteTools...) }

// TestPrivWriteToolsRegistered: admin only, privileged, operator tier,
// destructiveHint true with idempotentHint per D9, approval inputs and
// requiresUserInteraction in every configuration, "as root".
func TestPrivWriteToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, n := range names(reg.ToolsForProfile(p, nil)) {
			if slices.Contains(privWriteTools, n) {
				t.Fatalf("%s is registered in the %s profile", n, p)
			}
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	idem := map[string]bool{"shell_priv_write_file": true, "shell_priv_make_directory": true, "shell_priv_copy_path": true, "shell_priv_move_path": false}
	for _, want := range privWriteTools {
		i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == want })
		if i < 0 {
			t.Fatalf("%s is not registered in admin", want)
		}
		r := admin[i]
		a := r.Tool.Def.Annotations
		if r.Tier != TierOperator || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint != idem[want] {
			t.Fatalf("%s: tier %s privileged %v annotations %+v", want, r.Tier, r.Privileged, a)
		}
		if r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || schemaOf(t, r).Properties["approval_id"] == nil {
			t.Fatalf("%s: not gated in the catalogue", want)
		}
		if !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
			t.Fatalf("%s: %q", want, r.Tool.Def.Description)
		}
	}
	// shell-mcp check: privileged tools follow privileged.max_tier.
	for _, c := range []struct {
		gateMax, privMax string
		want             bool
	}{{"destructive", "operator", true}, {"destructive", "read", false}, {"read", "destructive", false}, {"operator", "destructive", true}} {
		eff := EffectiveTools(admin, c.gateMax, true, c.privMax)
		if got := slices.Contains(eff, "shell_priv_write_file"); got != c.want {
			t.Errorf("max_tier %s, privileged.max_tier %s: write effective %v, want %v", c.gateMax, c.privMax, got, c.want)
		}
		if !slices.Contains(eff, "shell_priv_read_file") {
			t.Errorf("max_tier %s, privileged.max_tier %s: the read tools are not effective", c.gateMax, c.privMax)
		}
	}
}

// TestPrivWriteToolsUnderNone: refused, nothing sent.
func TestPrivWriteToolsUnderNone(t *testing.T) {
	a := newPrivWriteHarness(t, approval.MethodNone)
	for _, name := range privWriteTools {
		if env, _ := a.call(name, privWriteArgs[name]); errCode(env) != "approval_unavailable" {
			t.Fatalf("%s: %v", name, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivWriteToolsApprovalFlow: for each tool the first call sends only
// preview reads and returns approval_pending; the approved re-call sends
// the operation once at ceiling operator; a second re-call is
// approval_invalid and sends nothing more.
func TestPrivWriteToolsApprovalFlow(t *testing.T) {
	for _, name := range privWriteTools {
		t.Run(name, func(t *testing.T) {
			a := newPrivWriteHarness(t, approval.MethodWeb)
			if name == "shell_priv_make_directory" {
				a.g.setPath("priv_stat", privDir, privNotFound())
			}
			id := a.pending(name, privWriteArgs[name])
			if m := a.privMutatingOps(); len(m) != 0 {
				t.Fatalf("before approval: %v", m)
			}
			for _, q := range a.g.requests() {
				if !strings.HasPrefix(q.Op, "priv_") || q.Ceiling != "operator" {
					t.Fatalf("preview %s at ceiling %s", q.Op, q.Ceiling)
				}
			}
			a.approve(id)
			env, _ := a.call(name, withID(privWriteArgs[name], id))
			if env["ok"] != true {
				t.Fatalf("approved re-call: %v", env)
			}
			if m := a.privMutatingOps(); !slices.Equal(m, []string{privWriteOp[name]}) {
				t.Fatalf("after the re-call: %v", m)
			}
			reqs := a.g.requests()
			if q := reqs[len(reqs)-1]; q.Ceiling != "operator" {
				t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
			}
			if env, _ := a.call(name, withID(privWriteArgs[name], id)); errCode(env) != "approval_invalid" {
				t.Fatalf("second re-call: %v", env)
			}
			if m := a.privMutatingOps(); len(m) != 1 {
				t.Fatalf("after the second re-call: %v", m)
			}
		})
	}
}

// TestPrivWriteToolsChangeAfterApproval: the target, either policy, or the
// destination changing after approval is approval_invalid, and nothing is
// changed.
func TestPrivWriteToolsChangeAfterApproval(t *testing.T) {
	edits := map[string]func(*recordingGate){
		"privileged policy": func(g *recordingGate) { g.setHelperSHA("beef") },
		"gate policy":       func(g *recordingGate) { g.setSHA("cd34") },
		"target": func(g *recordingGate) {
			g.set("priv_stat", gateReply{data: strings.Replace(privStat, `"0640"`, `"0600"`, 1)})
		},
		"destination content": func(g *recordingGate) {
			g.set("priv_read_file", gateReply{data: fakeReadSHA("key: other\n", shaDest)})
		},
	}
	for _, name := range privWriteTools {
		for what, edit := range edits {
			if what == "destination content" && name == "shell_priv_make_directory" {
				continue
			}
			t.Run(name+"/"+what, func(t *testing.T) {
				a := newPrivWriteHarness(t, approval.MethodWeb)
				if name == "shell_priv_make_directory" {
					a.g.setPath("priv_stat", privDir, privNotFound())
					if what == "target" {
						edit = func(g *recordingGate) { g.setPath("priv_stat", privDir, gateReply{data: privDirSt}) }
					}
				}
				id := a.pending(name, privWriteArgs[name])
				a.approve(id)
				edit(a.g)
				env, _ := a.call(name, withID(privWriteArgs[name], id))
				want := "approval_invalid"
				if name == "shell_priv_make_directory" && what == "target" {
					want = "exists" // the directory appeared: the fresh preview refuses it
				}
				if errCode(env) != want || len(a.privMutatingOps()) != 0 {
					t.Fatalf("re-call after the %s changed: %v, sent %v", what, env, a.g.ops())
				}
			})
		}
	}
}

// TestPrivWritePreconditions: what the fresh preview saw is passed on. A
// write over a file sends expected_sha256 of its content, one that saw no
// file expect_absent; a copy or move with overwrite over a file sends
// expected_destination_sha256 (P-9), and one that saw no destination goes
// with overwrite false.
func TestPrivWritePreconditions(t *testing.T) {
	run := func(t *testing.T, name string, absent bool) map[string]any {
		t.Helper()
		a := newPrivWriteHarness(t, approval.MethodWeb)
		if absent {
			privAbsent(a.g, privConf)
		}
		id := a.pending(name, privWriteArgs[name])
		a.approve(id)
		if env, _ := a.call(name, withID(privWriteArgs[name], id)); env["ok"] != true {
			t.Fatalf("re-call: %v", env)
		}
		return a.g.args(t, privWriteOp[name])
	}
	w := run(t, "shell_priv_write_file", false)
	if w["expected_sha256"] != shaOld || w["expect_absent"] != nil {
		t.Fatalf("write over a file: %v", w)
	}
	w = run(t, "shell_priv_write_file", true)
	if w["expect_absent"] != true || w["expected_sha256"] != "" && w["expected_sha256"] != nil {
		t.Fatalf("write of a new file: %v", w)
	}
	for _, name := range []string{"shell_priv_copy_path", "shell_priv_move_path"} {
		w = run(t, name, false)
		if w["overwrite"] != true || w["expected_destination_sha256"] != shaOld {
			t.Fatalf("%s over a file: %v", name, w)
		}
		w = run(t, name, true)
		if w["overwrite"] != false || w["expected_destination_sha256"] != nil {
			t.Fatalf("%s with no destination: %v", name, w)
		}
	}
}

// TestPrivCopyPreviewShowsDestination: the approver sees the destination's
// type, mode, owner and SHA-256, the source's mode, what the copy will be
// set to, and the backup.
func TestPrivCopyPreviewShowsDestination(t *testing.T) {
	a := newPrivWriteHarness(t, approval.MethodWeb)
	id := a.pending("shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"])
	if ops := strings.Join(a.g.ops(), ","); ops != "priv_stat,priv_stat,priv_read_file,priv_backup_check" {
		t.Fatalf("preview ops %s", ops)
	}
	p := previewMap(t, a, id)
	for k, v := range map[string]string{
		"source.type": "file", "source.mode": "0600", "source.size": "4",
		"destination.state": "file", "destination.type": "file", "destination.mode": "0640", "destination.sha256": shaOld,
		"destination.group": "example-app", "overwrite": "true", "backup.written": "true", "backup.bytes": "11",
	} {
		if p[k] != v {
			t.Fatalf("preview %s = %q, want %q (all %v)", k, p[k], v, p)
		}
	}
	if !strings.Contains(p["set.mode"], "destination") || !strings.Contains(p["set.owner"], "kept") {
		t.Fatalf("what the copy is set to: %v", p)
	}
	// A new copy is root's (N-3), with the source's mode masked.
	b := newPrivWriteHarness(t, approval.MethodWeb)
	privAbsent(b.g, privConf)
	id = b.pending("shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"])
	p = previewMap(t, b, id)
	if p["destination.state"] != "absent" || p["backup.written"] != "false" || !strings.Contains(p["set.owner"], "root") || !strings.Contains(p["set.mode"], "source") {
		t.Fatalf("new copy preview %v", p)
	}
}

// TestPrivWritePreviewShowsOwnerAndBackup: the write preview shows the
// current owner and mode, what will be set (N-3: a new file without an
// owner is root's), and the backup.
func TestPrivWritePreviewShowsOwnerAndBackup(t *testing.T) {
	a := newPrivWriteHarness(t, approval.MethodWeb)
	id := a.pending("shell_priv_write_file", map[string]any{"path": privConf, "content": "new\n", "owner": "example-app", "mode": "0600"})
	if ops := strings.Join(a.g.ops(), ","); ops != "priv_stat,priv_read_file,priv_backup_check" {
		t.Fatalf("preview ops %s", ops)
	}
	p := previewMap(t, a, id)
	for k, v := range map[string]string{
		"current.state": "file", "current.mode": "0640", "current.uid": "0", "current.gid": "1001", "current.sha256": shaOld,
		"set.owner": "example-app", "set.mode": "0600", "backup.written": "true", "backup.bytes": "11",
	} {
		if p[k] != v {
			t.Fatalf("preview %s = %q, want %q (all %v)", k, p[k], v, p)
		}
	}
	if !strings.Contains(p["set.group"], "kept") {
		t.Fatalf("group %v", p)
	}
	b := newPrivWriteHarness(t, approval.MethodWeb)
	privAbsent(b.g, privConf)
	id = b.pending("shell_priv_write_file", privWriteArgs["shell_priv_write_file"])
	p = previewMap(t, b, id)
	if ops := strings.Join(b.g.ops(), ","); ops != "priv_stat,priv_backup_check" {
		t.Fatalf("new-file preview ops %s", ops)
	}
	if p["current.state"] != "absent" || p["backup.written"] != "false" || !strings.Contains(p["set.owner"], "root") || !strings.Contains(p["set.mode"], "0640") {
		t.Fatalf("new-file preview %v", p)
	}
}

// TestPrivMkdirPreviewListsParents: with parents, the preview lists every
// directory that will be created, up to the first that exists.
func TestPrivMkdirPreviewListsParents(t *testing.T) {
	a := newPrivWriteHarness(t, approval.MethodWeb)
	deep := "/etc/example-app/a/b"
	a.g.setPath("priv_stat", deep, privNotFound())
	a.g.setPath("priv_stat", "/etc/example-app/a", privNotFound())
	a.g.setPath("priv_stat", "/etc/example-app", gateReply{data: privDirSt})
	id := a.pending("shell_priv_make_directory", map[string]any{"path": deep, "parents": true})
	p := previewMap(t, a, id)
	if p["create[0]"] != "/etc/example-app/a" || p["create[1]"] != deep || p["create[2]"] != "" || !strings.Contains(p["set.owner"], "root") {
		t.Fatalf("preview %v", p)
	}
	// Without parents, a missing parent is refused before any approval.
	b := newPrivWriteHarness(t, approval.MethodWeb)
	b.g.setPath("priv_stat", deep, privNotFound())
	b.g.setPath("priv_stat", "/etc/example-app/a", privNotFound())
	if env, _ := b.call("shell_priv_make_directory", map[string]any{"path": deep}); errCode(env) != "not_found" || env["approval"] != nil {
		t.Fatalf("missing parent: %v", env)
	}
}

// TestPrivWritePreviewRefusals: an operation the helper would refuse
// requests no approval, and sends nothing that changes the host.
func TestPrivWritePreviewRefusals(t *testing.T) {
	full := gateReply{data: `{"written":true,"bytes":11,"fits":false,"store_bytes":1073741000,"max_store_bytes":1073741824}`}
	big := gateReply{data: `{"written":true,"bytes":70000000,"fits":false,"store_bytes":0,"max_store_bytes":1073741824}`}
	for _, c := range []struct {
		name, tool string
		args       map[string]any
		set        func(g *recordingGate)
		code, msg  string
	}{
		{"store full", "shell_priv_write_file", privWriteArgs["shell_priv_write_file"],
			func(g *recordingGate) { g.set("priv_backup_check", full) }, "backup_failed", "backup store is full"},
		{"over 64 MiB", "shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"],
			func(g *recordingGate) { g.set("priv_backup_check", big) }, "backup_failed", "64 MiB"},
		{"store full, move", "shell_priv_move_path", privWriteArgs["shell_priv_move_path"],
			func(g *recordingGate) { g.set("priv_backup_check", full) }, "backup_failed", "backup store is full"},
		{"backup check refused", "shell_priv_write_file", privWriteArgs["shell_priv_write_file"],
			func(g *recordingGate) {
				g.set("priv_backup_check", gateReply{code: "path_denied", msg: "path is outside the write roots"})
			}, "path_denied", "write roots"},
		{"write over a directory", "shell_priv_write_file", privWriteArgs["shell_priv_write_file"],
			func(g *recordingGate) { g.setPath("priv_stat", privConf, gateReply{data: privDirSt}) }, "is_a_directory", ""},
		{"write over a symlink", "shell_priv_write_file", privWriteArgs["shell_priv_write_file"],
			func(g *recordingGate) { g.setPath("priv_stat", privConf, gateReply{data: privLink}) }, "path_denied", "symlink"},
		{"write over a file with no hash", "shell_priv_write_file", privWriteArgs["shell_priv_write_file"],
			func(g *recordingGate) {
				g.set("priv_read_file", gateReply{data: `{"path":"` + privConf + `","size":300000000,"binary":true,"offset":0,"truncated":false}`})
			}, "too_large", ""},
		{"copy onto a directory", "shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"],
			func(g *recordingGate) { g.setPath("priv_stat", privConf, gateReply{data: privDirSt}) }, "is_a_directory", ""},
		{"move onto a symlink", "shell_priv_move_path", privWriteArgs["shell_priv_move_path"],
			func(g *recordingGate) { g.setPath("priv_stat", privConf, gateReply{data: privLink}) }, "path_denied", "symlink"},
		{"copy of a directory", "shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"],
			func(g *recordingGate) { g.setPath("priv_stat", privSrc, gateReply{data: privDirSt}) }, "is_a_directory", ""},
		{"copy over a file without overwrite", "shell_priv_copy_path", map[string]any{"source": privSrc, "destination": privConf},
			nil, "exists", ""},
		{"move over a file without overwrite", "shell_priv_move_path", map[string]any{"source": privSrc, "destination": privConf},
			nil, "exists", ""},
		{"mkdir of an existing directory", "shell_priv_make_directory", privWriteArgs["shell_priv_make_directory"],
			func(g *recordingGate) { g.setPath("priv_stat", privDir, gateReply{data: privDirSt}) }, "exists", ""},
		{"source outside the roots", "shell_priv_copy_path", privWriteArgs["shell_priv_copy_path"],
			func(g *recordingGate) {
				g.setPath("priv_stat", privSrc, gateReply{code: "path_denied", msg: "outside the privileged roots"})
			}, "path_denied", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newPrivWriteHarness(t, approval.MethodWeb)
			if c.set != nil {
				c.set(a.g)
			}
			env, _ := a.call(c.tool, c.args)
			if errCode(env) != c.code || env["approval"] != nil || len(a.privMutatingOps()) != 0 {
				t.Fatalf("%v, sent %v", env, a.g.ops())
			}
			if msg := fmt.Sprint(env["error"].(map[string]any)["message"]); !strings.Contains(msg, c.msg) {
				t.Fatalf("message %q", msg)
			}
		})
	}
}

// TestPrivWriteResults: the results carry what the helper set (mode, owner,
// group), the hashes and the backup ids; an unverified write is
// verify_failed; the helper's refusals pass through.
func TestPrivWriteResults(t *testing.T) {
	a := newPrivWriteHarness(t, approval.MethodWeb)
	id := a.pending("shell_priv_write_file", privWriteArgs["shell_priv_write_file"])
	a.approve(id)
	env, _ := a.call("shell_priv_write_file", withID(privWriteArgs["shell_priv_write_file"], id))
	d := data(t, env)
	if env["verified"] != true || d["mode"] != "0640" || d["uid"] != 0.0 || d["gid"] != 1001.0 || d["group"] != "example-app" ||
		d["old_sha256"] != shaOld || d["new_sha256"] != shaNew || fmt.Sprint(d["backup_ids"]) != "[20261001T000000Z-0123456789abcdef]" {
		t.Fatalf("write result %v", env)
	}
	for _, c := range []struct{ op, data, tool string }{
		{"priv_write_file", strings.Replace(privWrote, `"verified":true`, `"verified":false`, 1), "shell_priv_write_file"},
		{"priv_copy", strings.Replace(privCopied, `"verified":true`, `"verified":false`, 1), "shell_priv_copy_path"},
	} {
		b := newPrivWriteHarness(t, approval.MethodWeb)
		b.g.set(c.op, gateReply{data: c.data})
		id := b.pending(c.tool, privWriteArgs[c.tool])
		b.approve(id)
		if env, _ := b.call(c.tool, withID(privWriteArgs[c.tool], id)); errCode(env) != "verify_failed" {
			t.Fatalf("%s unverified: %v", c.tool, env)
		}
	}
	for _, name := range privWriteTools {
		b := newPrivWriteHarness(t, approval.MethodWeb)
		if name == "shell_priv_make_directory" {
			b.g.setPath("priv_stat", privDir, privNotFound())
		}
		b.g.set(privWriteOp[name], gateReply{code: "exists", msg: "destination exists"})
		id := b.pending(name, privWriteArgs[name])
		b.approve(id)
		if env, _ := b.call(name, withID(privWriteArgs[name], id)); errCode(env) != "exists" {
			t.Fatalf("%s: helper refusal %v", name, env)
		}
	}
	m := newPrivWriteHarness(t, approval.MethodWeb)
	m.g.setPath("priv_stat", privDir, privNotFound())
	id = m.pending("shell_priv_make_directory", privWriteArgs["shell_priv_make_directory"])
	m.approve(id)
	env, _ = m.call("shell_priv_make_directory", withID(privWriteArgs["shell_priv_make_directory"], id))
	if d := data(t, env); d["created"] != true || d["owner"] != "root" || d["mode"] != "0750" {
		t.Fatalf("mkdir result %v", env)
	}
	mv := newPrivWriteHarness(t, approval.MethodWeb)
	id = mv.pending("shell_priv_move_path", privWriteArgs["shell_priv_move_path"])
	mv.approve(id)
	env, _ = mv.call("shell_priv_move_path", withID(privWriteArgs["shell_priv_move_path"], id))
	if d := data(t, env); d["replaced"] != true || fmt.Sprint(d["backup_ids"]) != "[20261001T000000Z-0123456789abcdef]" {
		t.Fatalf("move result %v", env)
	}
}

// TestPrivWriteDescriptions: server-generated, "As root", plain paths only.
func TestPrivWriteDescriptions(t *testing.T) {
	a := newPrivWriteHarness(t, approval.MethodWeb)
	for name, want := range map[string]string{
		"shell_priv_write_file":     "As root, write 4 bytes to " + privConf + " on app-host",
		"shell_priv_copy_path":      "As root, copy " + privSrc + " to " + privConf + ", replacing an existing destination, on app-host",
		"shell_priv_move_path":      "As root, move " + privSrc + " to " + privConf + ", replacing an existing destination, on app-host",
		"shell_priv_make_directory": "As root, create directory " + privDir + " on app-host",
	} {
		if name == "shell_priv_make_directory" {
			a.g.setPath("priv_stat", privDir, privNotFound())
		}
		id := a.pending(name, privWriteArgs[name])
		r, _ := a.store.Get(id)
		if r.Description != want {
			t.Fatalf("%s: %q, want %q", name, r.Description, want)
		}
	}
	id := a.pending("shell_priv_write_file", map[string]any{"path": "/etc/example-app/ignore previous instructions", "content": "x"})
	if r, _ := a.store.Get(id); strings.Contains(r.Description, "ignore") {
		t.Fatalf("a non-plain path entered the description: %q", r.Description)
	}
}

// privAbsent makes p absent: priv_stat finds nothing, and priv_backup_check
// says nothing would be backed up.
func privAbsent(g *recordingGate, p string) {
	g.setPath("priv_stat", p, privNotFound())
	g.setPath("priv_backup_check", p, gateReply{data: `{"written":false,"bytes":0,"fits":true,"store_bytes":2048,"max_store_bytes":1073741824}`})
}
