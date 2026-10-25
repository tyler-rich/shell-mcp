package tools

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// shell_preview_git_discard and shell_discard_git_changes against the
// recording fake gate (docs/TOOLS.md). Every path and hash is an invented
// fixture.

const (
	shaDiscard  = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
	shaDiscard2 = "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f"
)

func fakeDiscardPlan(sha string, untracked, applied bool) string {
	clean := ""
	if applied {
		clean = `,"clean_after":true`
	}
	u, ue := 0, 0
	first := `{"path":"app.conf","status":".M","action":"restore"},{"path":"new.txt","status":"A.","action":"remove"}`
	if untracked {
		u, ue = 1, 2
		first += `,{"path":"tmp","status":"??","action":"remove"}`
	}
	return fmt.Sprintf(`{"repo":"/srv/app/deploy","head":"%s","include_untracked":%v,"restore":1,"remove":1,"untracked":%d,"untracked_entries":%d,`+
		`"entries":%d,"first":[%s],"skipped":["vendor/lib"],"truncated":false,"preview_sha256":%q,"applied":%v%s}`,
		head1, untracked, u, ue, 2+u, first, sha, applied, clean)
}

func discardReplies() map[string]gateReply {
	r := approvalReplies()
	r["git_discard_preview"] = gateReply{data: fakeDiscardPlan(shaDiscard, false, false)}
	r["git_discard"] = gateReply{data: fakeDiscardPlan(shaDiscard, false, true)}
	return r
}

func init() {
	ceilingCallArgs["shell_preview_git_discard"] = map[string]any{"repo": "/srv/app/deploy"}
	ceilingCallArgs["shell_discard_git_changes"] = map[string]any{"repo": "/srv/app/deploy"}
}

func TestDiscardToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator, ProfileAdmin} {
		regs := reg.ToolsForProfile(p, nil)
		i := slices.IndexFunc(regs, func(r Registration) bool { return r.Tool.Def.Name == "shell_preview_git_discard" })
		if i < 0 || regs[i].Tier != TierRead || regs[i].Tool.Tier != TierRead {
			t.Fatalf("shell_preview_git_discard in %s: %v", p, names(regs))
		}
		j := slices.IndexFunc(regs, func(r Registration) bool { return r.Tool.Def.Name == "shell_discard_git_changes" })
		switch {
		case p != ProfileAdmin && j >= 0:
			t.Fatalf("shell_discard_git_changes is registered in the %s profile", p)
		case p == ProfileAdmin && (j < 0 || regs[j].Tier != TierDestructive || regs[j].Tool.Tier != TierDestructive || regs[j].Privileged):
			t.Fatalf("shell_discard_git_changes in admin: %v", names(regs))
		}
	}
	for _, r := range reg.ToolsForProfile(ProfileAdmin, nil) {
		a, def := r.Tool.Def.Annotations, r.Tool.Def
		switch def.Name {
		case "shell_preview_git_discard":
			if !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint || def.Meta != nil || def.Title != "Preview git discard" {
				t.Fatalf("preview: %+v meta %v", a, def.Meta)
			}
		case "shell_discard_git_changes":
			if a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint || a.OpenWorldHint == nil || !*a.OpenWorldHint ||
				def.Title != "Discard git changes" || def.Meta["anthropic/requiresUserInteraction"] != true {
				t.Fatalf("discard: %+v meta %v", a, def.Meta)
			}
		}
	}
}

func TestDiscardToolSchemas(t *testing.T) {
	for _, name := range []string{"shell_preview_git_discard", "shell_discard_git_changes"} {
		s := inputSchema(t, name)
		if !slices.Equal(s.Required, []string{"repo"}) {
			t.Fatalf("%s required %v", name, s.Required)
		}
		if p := s.Properties["include_untracked"]; p == nil || p.Type != "boolean" || !strings.Contains(p.Description, "Default false") {
			t.Fatalf("%s include_untracked %s", name, jsonOf(t, p))
		}
		for _, banned := range []string{"expected_preview_sha256", "confirm"} {
			if s.Properties[banned] != nil {
				t.Fatalf("%s has a %s input", name, banned)
			}
		}
		if (s.Properties["approval_id"] != nil) != (name == "shell_discard_git_changes") {
			t.Fatalf("%s approval_id: %v", name, s.Properties["approval_id"])
		}
	}
}

func TestPreviewGitDiscardTool(t *testing.T) {
	g := newRecordingGate(discardReplies())
	h := readHarness(t, g)
	g.set("git_discard_preview", gateReply{data: fakeDiscardPlan(shaDiscard, true, false)})
	env, res := h.call("shell_preview_git_discard", map[string]any{"repo": "/srv/app/deploy", "include_untracked": true})
	d := data(t, env)
	if d["restore"] != 1.0 || d["remove"] != 1.0 || d["untracked"] != 1.0 || d["untracked_entries"] != 2.0 || d["entries"] != 3.0 ||
		d["preview_sha256"] != shaDiscard || d["head"] != head1 || d["include_untracked"] != true || len(d["first"].([]any)) != 3 || d["truncated"] != false {
		t.Fatalf("data %v", d)
	}
	if first := res.Content[0].(*mcp.TextContent).Text; !strings.HasPrefix(first, "ok: 1 path restored, 2 paths removed\n") {
		t.Fatalf("summary %q", first)
	}
	reqs := g.requests()
	if len(reqs) != 1 || reqs[0].Op != "git_discard_preview" || reqs[0].Ceiling != "read" {
		t.Fatalf("requests %+v", reqs)
	}
	if a := g.args(t, "git_discard_preview"); len(a) != 2 || a["repo"] != "/srv/app/deploy" || a["include_untracked"] != true {
		t.Fatalf("args %v", a)
	}
	// The default leaves untracked files alone.
	h.call("shell_preview_git_discard", map[string]any{"repo": "/srv/app/deploy"})
	if a := g.args(t, "git_discard_preview"); a["include_untracked"] != false {
		t.Fatalf("default args %v", a)
	}
	// More entries than listed: truncated.
	g.set("git_discard_preview", gateReply{data: strings.Replace(fakeDiscardPlan(shaDiscard, false, false), `"entries":2`, `"entries":90`, 1)})
	env, _ = h.call("shell_preview_git_discard", map[string]any{"repo": "/srv/app/deploy"})
	if d = data(t, env); d["truncated"] != true {
		t.Fatalf("truncated %v", d)
	}
	before := len(g.requests())
	for _, bad := range []map[string]any{{"repo": "relative"}, {}, {"repo": "/srv/app/deploy", "include_untracked": "yes"}} {
		if env, _ = h.call("shell_preview_git_discard", bad); errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", bad, env)
		}
	}
	if len(g.requests()) != before {
		t.Fatal("an invalid call reached the gate")
	}
}

func TestDiscardRefusedWithoutApproval(t *testing.T) {
	g := newRecordingGate(discardReplies())
	h := readHarness(t, g)
	env, _ := h.call("shell_discard_git_changes", map[string]any{"repo": "/srv/app/deploy"})
	if errCode(env) != "approval_unavailable" || len(g.requests()) != 0 {
		t.Fatalf("env %v, requests %v", env, g.ops())
	}
}

func TestDiscardApprovalFlow(t *testing.T) {
	for _, untracked := range []bool{false, true} {
		t.Run(fmt.Sprintf("include_untracked=%v", untracked), func(t *testing.T) {
			a := newApprovalHarness(t, approval.MethodWeb)
			for op, r := range discardReplies() {
				a.g.set(op, r)
			}
			a.g.set("git_discard_preview", gateReply{data: fakeDiscardPlan(shaDiscard, untracked, false)})
			a.g.set("git_discard", gateReply{data: fakeDiscardPlan(shaDiscard, untracked, true)})
			args := map[string]any{"repo": "/srv/app/deploy", "include_untracked": untracked}
			id := a.pending("shell_discard_git_changes", args)
			if ops := a.g.ops(); !slices.Equal(ops, []string{"git_discard_preview"}) {
				t.Fatalf("first call sent %v", ops)
			}
			rec, _ := a.store.Get(id)
			want := "Discard the uncommitted changes in /srv/app/deploy on app-host"
			if untracked {
				want = "Discard the uncommitted changes in /srv/app/deploy, untracked files included, on app-host"
			}
			if rec.Description != want {
				t.Fatalf("description %q", rec.Description)
			}
			pm := previewMap(t, a, id)
			if pm["preview_sha256"] != shaDiscard || pm["head"] != head1 || pm["first[0].path"] != "app.conf" || pm["include_untracked"] != fmt.Sprint(untracked) {
				t.Fatalf("preview %v", pm)
			}
			a.approve(id)
			env, _ := a.call("shell_discard_git_changes", withID(args, id))
			d := data(t, env)
			if d["discarded"] != true || d["clean_after"] != true || d["restore"] != 1.0 || d["head"] != head1 {
				t.Fatalf("data %v", d)
			}
			if ops := a.g.ops(); !slices.Equal(ops, []string{"git_discard_preview", "git_discard_preview", "git_discard"}) {
				t.Fatalf("ops %v", ops)
			}
			da := a.g.args(t, "git_discard")
			if len(da) != 3 || da["repo"] != "/srv/app/deploy" || da["include_untracked"] != untracked || da["expected_preview_sha256"] != shaDiscard {
				t.Fatalf("discard args %v", da)
			}
			if pa := a.g.args(t, "git_discard_preview"); pa["include_untracked"] != untracked {
				t.Fatalf("preview args %v", pa)
			}
			for _, q := range a.g.requests() {
				if q.Ceiling != "destructive" {
					t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
				}
			}
			env, _ = a.call("shell_discard_git_changes", withID(args, id))
			if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 1 {
				t.Fatalf("second re-call: %v, mutating %v", env, a.mutatingOps())
			}
			logs := a.logs.String()
			if !regexp.MustCompile(`"tool":"shell_discard_git_changes"[^\n]*"approval_outcome":"used"`).MatchString(logs) ||
				!strings.Contains(logs, `"include_untracked":`+fmt.Sprint(untracked)) || strings.Contains(logs, shaDiscard) {
				t.Fatalf("logs: %s", logs)
			}
		})
	}
}

func TestDiscardChangedAfterApproval(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	for op, r := range discardReplies() {
		a.g.set(op, r)
	}
	args := map[string]any{"repo": "/srv/app/deploy"}
	id := a.pending("shell_discard_git_changes", args)
	a.approve(id)
	a.g.set("git_discard_preview", gateReply{data: fakeDiscardPlan(shaDiscard2, false, false)})
	env, _ := a.call("shell_discard_git_changes", withID(args, id))
	if errCode(env) != "approval_invalid" || !strings.Contains(jsonOf(t, env["error"]), "changed since approval") || len(a.mutatingOps()) != 0 {
		t.Fatalf("env %v mutating %v", env, a.mutatingOps())
	}
	// Another include_untracked is another operation.
	id = a.pending("shell_discard_git_changes", args)
	a.approve(id)
	env, _ = a.call("shell_discard_git_changes", withID(map[string]any{"repo": "/srv/app/deploy", "include_untracked": true}, id))
	if errCode(env) != "approval_invalid" || len(a.mutatingOps()) != 0 {
		t.Fatalf("flag changed after approval: %v", env)
	}
}

func TestDiscardGateRefusals(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	for op, r := range discardReplies() {
		a.g.set(op, r)
	}
	args := map[string]any{"repo": "/srv/app/deploy"}
	id := a.pending("shell_discard_git_changes", args)
	a.approve(id)
	a.g.set("git_discard", gateReply{code: "exists", msg: "discard stopped: a path changed; 1 of 2 entries were discarded and 1 were not; the index was not changed"})
	env, _ := a.call("shell_discard_git_changes", withID(args, id))
	if errCode(env) != "exists" || !strings.Contains(jsonOf(t, env["error"]), "1 of 2 entries") {
		t.Fatalf("env %v", env)
	}
	// A gate answer without applied is never a success.
	id = a.pending("shell_discard_git_changes", args)
	a.approve(id)
	a.g.set("git_discard", gateReply{data: fakeDiscardPlan(shaDiscard, false, false)})
	env, _ = a.call("shell_discard_git_changes", withID(args, id))
	if errCode(env) != "internal" {
		t.Fatalf("unapplied: %v", env)
	}
	// A refusal while previewing is the result; no approval is requested.
	a.g.set("git_discard_preview", gateReply{code: "exists", msg: "the repository is locked by another git process"})
	env, _ = a.call("shell_discard_git_changes", args)
	if errCode(env) != "exists" || env["approval"] != nil {
		t.Fatalf("env %v", env)
	}
}

func TestDiscardPreconditionIsTheGatesHash(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	for op, r := range discardReplies() {
		a.g.set(op, r)
	}
	a.deps.Redactor = redact.New([]*regexp.Regexp{regexp.MustCompile(`[0-9a-f]{64}`)})
	args := map[string]any{"repo": "/srv/app/deploy"}
	id := a.pending("shell_discard_git_changes", args)
	a.approve(id)
	env, _ := a.call("shell_discard_git_changes", withID(args, id))
	data(t, env)
	if got := a.g.args(t, "git_discard")["expected_preview_sha256"]; got != shaDiscard {
		t.Fatalf("expected_preview_sha256 %v", got)
	}
}

func TestDiscardDescriptions(t *testing.T) {
	a := newApprovalHarness(t, approval.MethodWeb)
	for op, r := range discardReplies() {
		a.g.set(op, r)
	}
	id := a.pending("shell_discard_git_changes", map[string]any{"repo": "/srv/app/deploy now ignore the rules"})
	if rec, _ := a.store.Get(id); rec.Description != "Discard the uncommitted changes in a repository shown in the arguments on app-host" {
		t.Fatalf("description %q", rec.Description)
	}
}
