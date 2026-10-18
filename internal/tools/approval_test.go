package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// The approval flow through the tools (D-006; docs/handoff/S4B-APPROVAL.md
// §6.1–§6.3, §6.6, §9.1), against the recording fake gate with operator
// tools gated (SHELL_MCP_APPROVAL_TIERS=operator,destructive). Every path,
// unit, repository, origin and value is an invented fixture.

const approvalOrigin = "https://approve.example.test"

const (
	fakeFileStat = `{"path":"/srv/app/config/app.yaml","name":"app.yaml","type":"file","size":11,"mode":"0640","uid":1000,"gid":1000,
"owner":"svc-shell","group":"svc-shell","mtime":"2026-10-01T00:00:00Z"}`
	fakeDirStat = `{"path":"/srv/app/config","name":"config","type":"dir","size":4096,"mode":"0750","uid":1000,"gid":1000,
"owner":"svc-shell","group":"svc-shell","mtime":"2026-10-01T00:00:00Z"}`
)

func fakeReadSHA(content, sha string) string {
	return fmt.Sprintf(`{"path":"/srv/app/config/app.yaml","size":%d,"sha256":%q,"binary":false,"content":%q,"offset":0,"truncated":false}`, len(content), sha, content)
}

func (g *recordingGate) set(op string, r gateReply) { //nolint:gocritic // the fake gate stores replies by value
	g.mu.Lock()
	defer g.mu.Unlock()
	g.replies[op] = r
}

func (g *recordingGate) setSHA(sha string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sha = sha
}

// approvalReplies answers the operator ops and their preview reads.
func approvalReplies() map[string]gateReply {
	r := operatorReplies()
	r["stat"] = gateReply{data: fakeFileStat}
	r["read_file"] = gateReply{data: fakeReadSHA("key: value\n", shaOld)}
	return r
}

type approvalHarness struct {
	*harness
	g     *recordingGate
	store *approval.Store
	logs  *syncBuffer
}

func newApprovalHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	g := newRecordingGate(approvalReplies())
	tg, c := sshTarget(t, g.exec)
	return newApprovalHarnessOn(t, g, method, []config.Target{tg}, map[string]*sshx.Client{"app-host": c})
}

// newApprovalHarnessOn serves the admin profile, or the profile given.
func newApprovalHarnessOn(t *testing.T, g *recordingGate, method approval.Method, targets []config.Target, clients map[string]*sshx.Client, profile ...Profile) *approvalHarness {
	t.Helper()
	logs := &syncBuffer{}
	store := approval.NewStore(approval.Options{TTL: 300 * time.Second, Method: method, Wait: 300 * time.Millisecond,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	h := newHarnessWith(t, targets, clients, "", func(d *Deps) {
		d.ApprovalTiers = []string{"operator", "destructive"}
		d.ApprovalMethod = method
		d.Approvals = store
		d.ApprovalPublicURL = approvalOrigin
		if len(profile) == 1 {
			d.Principal.Profile = string(profile[0])
		}
		d.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	h.deps.MaxOutputBytes = 4096
	return &approvalHarness{harness: h, g: g, store: store, logs: logs}
}

// mutating are the ops that change a host.
var mutating = []string{"write_file", "mkdir", "copy", "move", "chmod", "git_pull", "service_control", "exec", "delete", "git_discard"}

func (a *approvalHarness) mutatingOps() []string {
	var out []string
	for _, op := range a.g.ops() {
		if slices.Contains(mutating, op) {
			out = append(out, op)
		}
	}
	return out
}

func approvalOf(t *testing.T, env map[string]any) map[string]any {
	t.Helper()
	ap, ok := env["approval"].(map[string]any)
	if !ok {
		t.Fatalf("no approval object: %v", env)
	}
	return ap
}

// pending makes the first call and returns the approval id.
func (a *approvalHarness) pending(name string, args map[string]any) string {
	a.t.Helper()
	env, _ := a.call(name, args)
	if errCode(env) != "approval_pending" || env["ok"] != false || env["data"] != nil {
		a.t.Fatalf("%s first call: %v", name, env)
	}
	ap := approvalOf(a.t, env)
	id, _ := ap["id"].(string)
	if !approval.ParseID(id) || ap["status"] != "pending" {
		a.t.Fatalf("approval object %v", ap)
	}
	return id
}

func withID(args map[string]any, id string) map[string]any {
	out := map[string]any{"approval_id": id}
	for k, v := range args {
		out[k] = v
	}
	return out
}

func (a *approvalHarness) approve(id string) {
	a.t.Helper()
	if _, err := a.store.Decide(id, true, "alice", "192.0.2.50"); err != nil {
		a.t.Fatal(err)
	}
}

var writeArgs = map[string]any{"path": "/srv/app/config/app.yaml", "content": "key: value2\n"}

func sha(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

// --- The web flow ------------------------------------------------------------------

func TestApprovalPendingResult(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	env, res := a.call("shell_write_file", writeArgs)
	if errCode(env) != "approval_pending" || !res.IsError {
		t.Fatalf("first call: %v", env)
	}
	ap := approvalOf(t, env)
	id, _ := ap["id"].(string)
	url := approvalOrigin + "/approvals/" + id
	if ap["url"] != url || ap["status"] != "pending" || ap["summary"] == "" {
		t.Fatalf("approval object %v", ap)
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(ap["expires_at"])); err != nil {
		t.Fatalf("expires_at %v", ap["expires_at"])
	}
	e, _ := env["error"].(map[string]any)
	want := "Approval required. Show the user this URL exactly as written, without changing or shortening it: " + url +
		". The approver opens it from their bookmark or the server's notification, checks the operation, and approves with a code. " +
		"Then call this tool again with the same arguments and approval_id " + id + "."
	if e["message"] != want {
		t.Fatalf("message\n got: %q\nwant: %q", e["message"], want)
	}
	// The summary line carries nothing from the host or the caller.
	text := jsonOf(t, res.Content[0])
	if !strings.Contains(text, `"text":"error: approval_pending\n`) {
		t.Fatalf("text block %s", text)
	}
	// Only preview reads reached the gate.
	if ops := a.g.ops(); strings.Join(ops, ",") != "stat,read_file" {
		t.Fatalf("gate ops %v", ops)
	}
	r, ok := a.store.Get(id)
	if !ok || r.Tool != "shell_write_file" || r.Target != "app-host" || r.Principal != auth.PrincipalBearer ||
		r.PolicySHA256 != "ab12" || r.ToolTitle != "Write file" || r.TargetHost == "" {
		t.Fatalf("record %+v", r)
	}
	// An identical call returns the same record and pushes nothing new.
	env2, _ := a.call("shell_write_file", writeArgs)
	if approvalOf(t, env2)["id"] != id {
		t.Fatal("an identical pending request made a new record")
	}
}

func TestApprovalApprovedRunsOnce(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	id := a.pending("shell_write_file", writeArgs)
	a.approve(id)
	env, _ := a.call("shell_write_file", withID(writeArgs, id))
	if env["ok"] != true || env["verified"] != true {
		t.Fatalf("approved re-call: %v", env)
	}
	if ap := approvalOf(t, env); ap["id"] != id || ap["status"] != "used" {
		t.Fatalf("approval object %v", ap)
	}
	if got := a.mutatingOps(); len(got) != 1 || got[0] != "write_file" {
		t.Fatalf("mutating ops %v", got)
	}
	// The preview's precondition is passed: the write is refused if the
	// file changed after the fresh preview.
	if w := a.g.args(t, "write_file"); w["expected_sha256"] != shaOld || w["expect_absent"] != nil {
		t.Fatalf("write args %v", w)
	}
	// A second re-call is invalid and sends nothing mutating.
	env, _ = a.call("shell_write_file", withID(writeArgs, id))
	if errCode(env) != "approval_invalid" {
		t.Fatalf("second re-call: %v", env)
	}
	if got := a.mutatingOps(); len(got) != 1 {
		t.Fatalf("mutating ops after the second re-call %v", got)
	}
}

// An approval for a create never becomes a replace: when the preview saw
// the file absent, the write carries expect_absent (and no
// expected_sha256), so the gate refuses a file that appears after the fresh
// preview.
func TestApprovalAbsentPreviewExpectsAbsent(t *testing.T) {
	for name, set := range map[string]func(*recordingGate){
		"absent at stat": func(g *recordingGate) { g.set("stat", gateReply{code: "not_found", msg: "no such file"}) },
		"removed before read_file": func(g *recordingGate) {
			g.set("read_file", gateReply{code: "not_found", msg: "no such file"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			set(a.g)
			id := a.pending("shell_write_file", writeArgs)
			a.approve(id)
			env, _ := a.call("shell_write_file", withID(writeArgs, id))
			if env["ok"] != true {
				t.Fatalf("approved re-call: %v", env)
			}
			if w := a.g.args(t, "write_file"); w["expect_absent"] != true || w["expected_sha256"] != "" {
				t.Fatalf("write args %v", w)
			}
		})
	}
}

func TestApprovalCallerPreconditionKept(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	args := map[string]any{"path": "/srv/app/config/app.yaml", "content": "x\n", "expected_sha256": shaNew}
	id := a.pending("shell_write_file", args)
	a.approve(id)
	a.call("shell_write_file", withID(args, id))
	if w := a.g.args(t, "write_file"); w["expected_sha256"] != shaNew {
		t.Fatalf("the caller's expected_sha256 was replaced: %v", w)
	}
}

func TestApprovalBindingMismatch(t *testing.T) {
	for name, recall := range map[string]struct {
		tool string
		args map[string]any
		pre  func(*approvalHarness)
	}{
		"target":    {"shell_write_file", map[string]any{"target": "db-host", "path": "/srv/app/config/app.yaml", "content": "key: value2\n"}, nil},
		"path":      {"shell_write_file", map[string]any{"path": "/srv/app/config/other.yaml", "content": "key: value2\n"}, nil},
		"content":   {"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "key: value3\n"}, nil},
		"mode":      {"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "key: value2\n", "mode": "0600"}, nil},
		"create":    {"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "key: value2\n", "create": false}, nil},
		"tool":      {"shell_set_permissions", map[string]any{"path": "/srv/app/config/app.yaml", "mode": "0600"}, nil},
		"principal": {"shell_write_file", writeArgs, func(a *approvalHarness) { a.deps.Principal = auth.Principal{Name: auth.PrincipalUnauthenticated} }},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRecordingGate(approvalReplies())
			tg, c := sshTarget(t, g.exec)
			tg2 := tg
			tg2.Name = "db-host"
			clients := map[string]*sshx.Client{"app-host": c, "db-host": c}
			a := newApprovalHarnessOn(t, g, approval.MethodWeb, []config.Target{tg, tg2}, clients)
			a.deps.DefaultTarget = "app-host"
			args := map[string]any{"target": "app-host"}
			for k, v := range writeArgs {
				args[k] = v
			}
			id := a.pending("shell_write_file", args)
			a.approve(id)
			if recall.pre != nil {
				recall.pre(a)
			}
			before := len(a.g.requests())
			env, _ := a.call(recall.tool, withID(recall.args, id))
			if errCode(env) != "approval_invalid" {
				t.Fatalf("re-call differing in %s: %v", name, env)
			}
			// The gate sees no request at all.
			if n := len(a.g.requests()); n != before {
				t.Fatalf("the gate saw %d requests", n-before)
			}
			// The record was not consumed.
			if r, _ := a.store.Get(id); r.Status != approval.StatusApproved {
				t.Fatalf("record %s", r.Status)
			}
		})
	}
}

func TestApprovalDefaultsHashTheSame(t *testing.T) {
	g := newRecordingGate(approvalReplies())
	tg, c := sshTarget(t, g.exec)
	a := newApprovalHarnessOn(t, g, approval.MethodWeb, []config.Target{tg}, map[string]*sshx.Client{"app-host": c})
	id := a.pending("shell_write_file", writeArgs)
	a.approve(id)
	// Defaults made explicit, and the only target named.
	explicit := map[string]any{"target": "app-host", "path": "/srv/app/config/app.yaml", "content": "key: value2\n", "create": true}
	if env, _ := a.call("shell_write_file", withID(explicit, id)); env["ok"] != true {
		t.Fatalf("defaults made explicit: %v", env)
	}
}

func TestApprovalFreshPreviewChanged(t *testing.T) {
	for name, change := range map[string]func(*recordingGate){
		"content": func(g *recordingGate) { g.set("read_file", gateReply{data: fakeReadSHA("key: other\n", shaNew)}) },
		"mode": func(g *recordingGate) {
			g.set("stat", gateReply{data: strings.Replace(fakeFileStat, `"0640"`, `"0600"`, 1)})
		},
		"policy":  func(g *recordingGate) { g.setSHA("cd34") },
		"removed": func(g *recordingGate) { g.set("stat", gateReply{code: "not_found", msg: "no such file"}) },
	} {
		t.Run(name, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			id := a.pending("shell_write_file", writeArgs)
			a.approve(id)
			change(a.g)
			env, _ := a.call("shell_write_file", withID(writeArgs, id))
			e, _ := env["error"].(map[string]any)
			if errCode(env) != "approval_invalid" || !strings.Contains(fmt.Sprint(e["message"]), "changed since approval") {
				t.Fatalf("changed %s: %v", name, env)
			}
			if got := a.mutatingOps(); len(got) != 0 {
				t.Fatalf("mutating ops %v", got)
			}
			// The record is used: it cannot run later either.
			if r, _ := a.store.Get(id); r.Status != approval.StatusUsed {
				t.Fatalf("record %s", r.Status)
			}
		})
	}
}

func TestApprovalFailedExecutionLeavesRecordUsed(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	id := a.pending("shell_write_file", writeArgs)
	a.approve(id)
	a.g.set("write_file", gateReply{code: "exists", msg: "current content does not match expected_sha256"})
	if env, _ := a.call("shell_write_file", withID(writeArgs, id)); errCode(env) != "exists" {
		t.Fatalf("failed execution: %v", env)
	}
	a.g.set("write_file", gateReply{data: fakeWrite})
	if env, _ := a.call("shell_write_file", withID(writeArgs, id)); errCode(env) != "approval_invalid" {
		t.Fatalf("re-call after a failed execution: %v", env)
	}
}

func TestApprovalDeclinedPendingUnknown(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	id := a.pending("shell_write_file", writeArgs)
	// Pending: waits, then pending again.
	start := time.Now()
	env, _ := a.call("shell_write_file", withID(writeArgs, id))
	if errCode(env) != "approval_pending" || time.Since(start) < 250*time.Millisecond || approvalOf(t, env)["id"] != id {
		t.Fatalf("pending re-call: %v", env)
	}
	if _, err := a.store.Decide(id, false, "alice", "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	env, _ = a.call("shell_write_file", withID(writeArgs, id))
	if errCode(env) != "approval_declined" || approvalOf(t, env)["status"] != "declined" {
		t.Fatalf("declined: %v", env)
	}
	env, _ = a.call("shell_write_file", withID(writeArgs, "aaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if errCode(env) != "approval_invalid" {
		t.Fatalf("unknown id: %v", env)
	}
	for _, bad := range []string{"AAAAAAAAAAAAAAAAAAAAAAAAAA", "short", strings.Repeat("a", 27)} {
		if env, _ := a.call("shell_write_file", withID(writeArgs, bad)); errCode(env) != "validation_error" {
			t.Fatalf("malformed id %q: %v", bad, env)
		}
	}
	if got := a.mutatingOps(); len(got) != 0 {
		t.Fatalf("mutating ops %v", got)
	}
}

func TestApprovalTooManyPending(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	for i := range approval.MaxPendingPerPrincipal {
		a.pending("shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": fmt.Sprintf("v%d\n", i)})
	}
	env, _ := a.call("shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "v9\n"})
	if errCode(env) != "approval_unavailable" || !strings.Contains(jsonOf(t, env["error"]), "too many pending approvals") {
		t.Fatalf("sixth request: %v", env)
	}
}

func TestApprovalNotify(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	var got []string
	a.deps.Notify = func(r *approval.Record, url string) { got = append(got, r.ID+" "+url) }
	id := a.pending("shell_write_file", writeArgs)
	a.pending("shell_write_file", writeArgs) // deduplicated: no second push
	if len(got) != 1 || got[0] != id+" "+approvalOrigin+"/approvals/"+id {
		t.Fatalf("pushes %v", got)
	}
}

func TestApprovalAuditLines(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	id := a.pending("shell_write_file", writeArgs)
	a.approve(id)
	a.call("shell_write_file", withID(writeArgs, id))
	a.call("shell_write_file", withID(writeArgs, id))
	id2 := a.pending("shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "z\n"})
	_, _ = a.store.Decide(id2, false, "alice", "")
	a.call("shell_write_file", withID(map[string]any{"path": "/srv/app/config/app.yaml", "content": "z\n"}, id2))
	var outcomes []string
	for _, l := range strings.Split(strings.TrimSpace(a.logs.String()), "\n") {
		var m map[string]any
		_ = json.Unmarshal([]byte(l), &m)
		if m["msg"] == "tool call" {
			outcomes = append(outcomes, fmt.Sprint(m["approval_outcome"])+"/"+fmt.Sprint(m["approval_id"] != nil && m["approval_id"] != ""))
		}
	}
	want := "pending/true,used/true,invalid/true,pending/true,declined/true"
	if strings.Join(outcomes, ",") != want {
		t.Fatalf("tool call outcomes %v, want %s", outcomes, want)
	}
	// Never logged: content, descriptions, previews, URLs with CSRF tokens.
	r, _ := a.store.Get(id)
	for _, s := range []string{"key: value2", r.Description, r.CSRFToken, shaOld} {
		if strings.Contains(a.logs.String(), s) {
			t.Fatalf("log contains %q", s)
		}
	}
}

// --- none and confirm-argument ----------------------------------------------------

func TestApprovalMethodNone(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodNone)
	for _, name := range operatorTools {
		for _, args := range []map[string]any{operatorCallArgs[name], {"target": "app-host"}, withID(operatorCallArgs[name], "aaaaaaaaaaaaaaaaaaaaaaaaaa")} {
			env, _ := a.call(name, args)
			if errCode(env) != "approval_unavailable" || !strings.Contains(jsonOf(t, env["error"]), "SHELL_MCP_APPROVAL_METHOD=none") {
				t.Fatalf("%s: %v", name, env)
			}
		}
	}
	if ops := a.g.ops(); len(ops) != 0 {
		t.Fatalf("requests reached the gate: %v", ops)
	}
}

func TestApprovalConfirmArgument(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodConfirm)
	env, _ := a.call("shell_write_file", writeArgs)
	ap := approvalOf(t, env)
	id, _ := ap["id"].(string)
	e, _ := env["error"].(map[string]any)
	if errCode(env) != "approval_pending" || ap["url"] != nil ||
		e["message"] != "Approval required. Call this tool again with the same arguments, approval_id "+id+" and confirm true." {
		t.Fatalf("first call: %v", env)
	}
	// Without confirm: pending again, at once.
	if again, _ := a.call("shell_write_file", withID(writeArgs, id)); errCode(again) != "approval_pending" {
		t.Fatalf("no confirm: %v", again)
	}
	// confirm without approval_id is refused.
	if noID, _ := a.call("shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "key: value2\n", "confirm": true}); errCode(noID) != "validation_error" {
		t.Fatalf("confirm without id: %v", noID)
	}
	args := withID(writeArgs, id)
	args["confirm"] = true
	env, _ = a.call("shell_write_file", args)
	if env["ok"] != true || approvalOf(t, env)["status"] != "used" {
		t.Fatalf("confirmed: %v", env)
	}
	r, _ := a.store.Get(id)
	if r.Approver != approval.ConfirmApprover {
		t.Fatalf("approver %q", r.Approver)
	}
	if !strings.Contains(a.logs.String(), `"level":"WARN"`) {
		t.Fatalf("no WARN: %s", a.logs.String())
	}
}

func TestConfirmRefusedUnderWeb(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	id := a.pending("shell_write_file", writeArgs)
	args := withID(writeArgs, id)
	args["confirm"] = true
	if env, _ := a.call("shell_write_file", args); errCode(env) != "validation_error" {
		t.Fatalf("confirm under web: %v", env)
	}
	if r, _ := a.store.Get(id); r.Status != approval.StatusPending {
		t.Fatalf("record %s", r.Status)
	}
}

func TestApprovalIDOnUngatedCall(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	a.deps.ApprovalTiers = []string{"destructive"}
	if env, _ := a.call("shell_write_file", withID(writeArgs, "aaaaaaaaaaaaaaaaaaaaaaaaaa")); errCode(env) != "validation_error" {
		t.Fatalf("approval_id on an ungated call: %v", env)
	}
	if env, _ := a.call("shell_write_file", writeArgs); env["ok"] != true {
		t.Fatalf("ungated call: %v", env)
	}
}

// --- Schemas and metadata -----------------------------------------------------------

func TestApprovalSchemaAndMeta(t *testing.T) {
	for _, c := range []struct {
		method  approval.Method
		tiers   []string
		confirm bool
		gated   bool
	}{
		{approval.MethodNone, []string{"destructive"}, false, false},
		{approval.MethodWeb, []string{"destructive"}, false, false},
		{approval.MethodWeb, []string{"operator", "destructive"}, false, true},
		{approval.MethodConfirm, []string{"operator", "destructive"}, true, true},
		{approval.MethodConfirm, []string{"destructive"}, true, false},
	} {
		reg, err := Catalogue(&Deps{ApprovalMethod: c.method, ApprovalTiers: c.tiers})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range reg.ToolsForProfile(ProfileAdmin, nil) {
			in, _ := r.Tool.Def.InputSchema.(*jsonschema.Schema)
			id, hasID := in.Properties["approval_id"]
			cf, hasConfirm := in.Properties["confirm"]
			meta, _ := r.Tool.Def.Meta["anthropic/requiresUserInteraction"].(bool)
			if r.Tier == TierRead {
				if hasID || hasConfirm || meta {
					t.Fatalf("%s (read) has approval inputs or meta", r.Tool.Def.Name)
				}
				if out, _ := r.Tool.Def.OutputSchema.(*jsonschema.Schema); out.Properties["approval"] != nil {
					t.Fatalf("%s (read) output has approval", r.Tool.Def.Name)
				}
				continue
			}
			if !hasID || id.Type != "string" || id.Pattern != approval.IDPattern || id.MaxLength == nil || *id.MaxLength != 26 ||
				id.MinLength == nil || *id.MinLength != 26 || id.Description == "" || slices.Contains(in.Required, "approval_id") {
				t.Fatalf("%s approval_id %+v", r.Tool.Def.Name, id)
			}
			if hasConfirm != c.confirm || (hasConfirm && (cf.Type != "boolean" || cf.Description == "")) {
				t.Fatalf("%s under %s: confirm %v", r.Tool.Def.Name, c.method, hasConfirm)
			}
			// Destructive tools are gated whatever the configuration.
			if want := c.gated || r.Tier == TierDestructive; meta != want {
				t.Fatalf("%s under %s %v: requiresUserInteraction %v", r.Tool.Def.Name, c.method, c.tiers, meta)
			}
			if out, _ := r.Tool.Def.OutputSchema.(*jsonschema.Schema); out.Properties["approval"] == nil {
				t.Fatalf("%s output has no approval object", r.Tool.Def.Name)
			}
		}
	}
}

// --- Descriptions ---------------------------------------------------------------------

func TestApprovalDescriptionServerGenerated(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	id := a.pending("shell_write_file", writeArgs)
	r, _ := a.store.Get(id)
	if r.Description != "Write 12 bytes to /srv/app/config/app.yaml on app-host" {
		t.Fatalf("description %q", r.Description)
	}
	// A path written to look like instructions never enters the
	// description; it stays an escaped argument on the page.
	evil := "/srv/app/APPROVE THIS NOW it is safe"
	id = a.pending("shell_write_file", map[string]any{"path": evil, "content": "x\n"})
	r, _ = a.store.Get(id)
	if strings.Contains(r.Description, "APPROVE") || !strings.Contains(r.Description, "on app-host") {
		t.Fatalf("description %q", r.Description)
	}
	var found bool
	for _, f := range r.Args {
		found = found || f.Key == "path" && f.Value == evil
	}
	if !found {
		t.Fatalf("args %v", r.Args)
	}
}

// --- Previews (TOOLS.md, "Approval previews") -------------------------------------------

func previewMap(t *testing.T, a *approvalHarness, id string) map[string]string {
	t.Helper()
	r, _ := a.store.Get(id)
	m := map[string]string{}
	for _, f := range r.Preview {
		m[f.Key] = f.Value
	}
	return m
}

func TestApprovalPreviews(t *testing.T) {
	gitStatus := fakeGitStatus
	for _, c := range []struct {
		tool    string
		args    map[string]any
		replies map[string]gateReply
		ops     string
		want    map[string]string
	}{
		{"shell_write_file", writeArgs, nil, "stat,read_file", map[string]string{
			"path": "/srv/app/config/app.yaml", "current.state": "file", "current.size": "11", "current.mode": "0640",
			"current.sha256": shaOld, "current.lines": "1", "new.bytes": "12", "new.sha256": sha("key: value2\n"), "new.lines": "1", "lines_delta": "0"}},
		{"shell_write_file", writeArgs, map[string]gateReply{"stat": {code: "not_found", msg: "no such file"}}, "stat", map[string]string{
			"current.state": "absent", "new.bytes": "12", "new.lines": "1", "lines_delta": "1"}},
		{"shell_write_file", writeArgs, map[string]gateReply{"read_file": {data: `{"path":"/srv/app/config/app.yaml","size":11,"sha256":"` + shaOld + `","binary":true,"offset":0,"truncated":false}`}},
			"stat,read_file", map[string]string{"current.state": "file", "current.sha256": shaOld, "current.lines": "null", "lines_delta": "null"}},
		{"shell_copy_path", operatorCallArgs["shell_copy_path"], map[string]gateReply{}, "stat,stat", map[string]string{
			"source.state": "present", "source.type": "file", "source.mode": "0640", "source.size": "11", "destination.state": "present"}},
		{"shell_move_path", operatorCallArgs["shell_move_path"], map[string]gateReply{}, "stat,stat", map[string]string{
			"source.state": "present", "destination.state": "present"}},
		{"shell_make_directory", operatorCallArgs["shell_make_directory"], map[string]gateReply{"stat": {code: "not_found", msg: "no such file"}}, "stat",
			map[string]string{"path.state": "absent"}},
		{"shell_set_permissions", operatorCallArgs["shell_set_permissions"], map[string]gateReply{"stat": {data: fakeDirStat}}, "stat",
			map[string]string{"path.state": "present", "path.type": "dir", "path.mode": "0750", "path.uid": "1000"}},
		{"shell_control_service", operatorCallArgs["shell_control_service"], nil, "service_status", map[string]string{
			"unit": "example-app.service", "load_state": "loaded", "active_state": "active", "sub_state": "running",
			"unit_file_state": "enabled", "main_pid": "4242", "result": "success"}},
		{"shell_git_pull", operatorCallArgs["shell_git_pull"], map[string]gateReply{"git_status": {data: gitStatus}}, "git_status", map[string]string{
			"repo": "/srv/app/deploy", "branch": "main", "upstream": "origin/main", "ahead": "1", "behind": "2",
			"entries_total": "3", "entries[0].path": "config.yaml", "truncated": "false"}},
		{"shell_run_command", operatorCallArgs["shell_run_command"], map[string]gateReply{"exec_preview": {data: fakeExecPreview(shaExec, "operator")}, "exec": {data: fakeExec("ok\n", 0)}},
			"exec_preview", map[string]string{"command_id": "app-restart", "tier": "operator", "description": "Restart the application",
				"root_equivalent": "false", "template[0]": "restart", "argv[0]": "/usr/local/bin/example-app", "argv[1]": "restart", "cwd": "/",
				"preview_sha256": shaExec}},
	} {
		t.Run(c.tool, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			for op, r := range c.replies {
				a.g.set(op, r)
			}
			id := a.pending(c.tool, c.args)
			if ops := strings.Join(a.g.ops(), ","); ops != c.ops {
				t.Fatalf("preview ops %s, want %s", ops, c.ops)
			}
			got := previewMap(t, a, id)
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("preview %s = %q, want %q (all %v)", k, got[k], v, got)
				}
			}
			// Volatile fields never enter a preview, so it hashes the same
			// at execution.
			for k := range got {
				if regexp.MustCompile(`memory|active_since|state_changed|n_restarts|duration`).MatchString(k) {
					t.Fatalf("volatile preview field %s", k)
				}
			}
			// The fresh preview at execution matches and the operation runs.
			a.approve(id)
			if env, _ := a.call(c.tool, withID(c.args, id)); env["ok"] != true {
				t.Fatalf("approved re-call: %v", env)
			}
		})
	}
}

func TestRunCommandPreviewRefusals(t *testing.T) {
	// The gate resolves the command in exec_preview; its refusal is the
	// result, no approval is requested and nothing runs.
	for _, code := range []string{"policy_denied", "template_mismatch", "tier_denied", "path_denied"} {
		t.Run(code, func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			a.g.set("exec_preview", gateReply{code: code, msg: "refused"})
			env, _ := a.call("shell_run_command", map[string]any{"command_id": "app-restart", "args": []string{"restart"}})
			if errCode(env) != code || env["approval"] != nil {
				t.Fatalf("%v, want %s", env, code)
			}
			if got := a.mutatingOps(); len(got) != 0 {
				t.Fatalf("mutating ops %v", got)
			}
		})
	}
}
