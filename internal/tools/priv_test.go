package tools

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// Privileged tools (docs/TOOLS.md, privileged tier; handoff
// docs/handoff/S4C-PRIVILEGED.md D1, D9, P-1). Every path, hash and value
// below is an invented fixture.

func (g *recordingGate) setHelperSHA(sha string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.helperSHA = sha
}

// --- D9: the gating rule -------------------------------------------------------

// TestPrivilegedGatingRule: privileged operator and destructive tools are
// always gated, whatever SHELL_MCP_APPROVAL_TIERS says; privileged read
// tools never are; and an unapproved privileged operation runs at ceiling
// read (D-006).
func TestPrivilegedGatingRule(t *testing.T) {
	for _, tiers := range [][]string{{"destructive"}, {"operator", "destructive"}} {
		d := &Deps{ApprovalTiers: tiers}
		for tier, want := range map[Tier]bool{TierRead: false, TierOperator: true, TierDestructive: true} {
			if got := d.gated(tier, true); got != want {
				t.Errorf("tiers %v: privileged %s gated %v, want %v", tiers, tier, got, want)
			}
		}
		if got, want := d.gated(TierOperator, false), slices.Contains(tiers, "operator"); got != want {
			t.Errorf("tiers %v: unprivileged operator gated %v, want %v", tiers, got, want)
		}
		if got := d.ungatedCeiling(TierDestructive, true); got != TierRead {
			t.Errorf("tiers %v: privileged ungated ceiling %s, want read", tiers, got)
		}
	}
	if got := (&Deps{ApprovalTiers: []string{"destructive"}}).ungatedCeiling(TierDestructive, false); got != TierOperator {
		t.Errorf("unprivileged ungated ceiling %s, want operator", got)
	}
}

// --- Synthetic privileged tools ------------------------------------------------

// privTestIn is the synthetic tools' input.
type privTestIn struct {
	targetArg
	Path string `json:"path" jsonschema:"An absolute, clean path."`
}

// privPreviewTier is the tier the synthetic per-tier tool's preview names.
type privPreviewTier struct{ tier Tier }

// syntheticPrivTools are privileged tools that are not in the catalogue: an
// operator tool whose preview is a priv_stat and whose operation is a
// priv_chmod; a read tool; and a per-tier tool (as shell_priv_run_command
// will be) whose preview names the tier given.
func syntheticPrivTools(d *Deps, pt *privPreviewTier) []Tool {
	change := define(d, spec[privTestIn, map[string]any]{
		name: "shell_priv_test_change", title: "Test change", description: "A synthetic privileged operator tool.",
		tier: TierOperator, privileged: true, idempotent: true,
		approvalArgs: func(in privTestIn) any { return map[string]any{"path": in.Path} },
		describe: func(in privTestIn, target string) string {
			return "As root, change " + plain(in.Path, "a path") + " on " + target
		},
		preview: func(ctx context.Context, in privTestIn, target string) (*preview, *envelope.Error) {
			var acc policyAcc
			st, _, pol, e := previewFetch[Entry](ctx, d, target, "priv_stat", pathWire{Path: in.Path}, true)
			acc.add(pol)
			if e != nil {
				return nil, e
			}
			return acc.result(map[string]any{"path": entryPreview(st)}, "")
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privTestIn) envelope.Envelope[map[string]any] {
			return fetch[map[string]any](ctx, d, in.Target, "priv_chmod", map[string]any{"path": in.Path, "mode": "0640"}, d.budget())
		},
	})
	read := define(d, spec[privTestIn, Entry]{
		name: "shell_priv_test_read", title: "Test read", description: "A synthetic privileged read tool.",
		tier: TierRead, privileged: true,
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privTestIn) envelope.Envelope[Entry] {
			return fetch[Entry](ctx, d, in.Target, "priv_stat", pathWire{Path: in.Path}, d.budget())
		},
	})
	perTier := define(d, spec[privTestIn, map[string]any]{
		name: "shell_priv_test_command", title: "Test command", description: "A synthetic privileged per-tier tool.",
		tier: TierDestructive, privileged: true, tierFromPreview: true,
		approvalArgs: func(in privTestIn) any { return map[string]any{"path": in.Path} },
		describe:     func(_ privTestIn, target string) string { return "As root, run a test command on " + target },
		preview: func(ctx context.Context, in privTestIn, target string) (*preview, *envelope.Error) {
			var acc policyAcc
			_, _, pol, e := previewFetch[Entry](ctx, d, target, "priv_stat", pathWire{Path: in.Path}, true)
			acc.add(pol)
			if e != nil {
				return nil, e
			}
			p, e := acc.result(map[string]any{"tier": pt.tier.String()}, "")
			if p != nil {
				p.tier = pt.tier
			}
			return p, e
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privTestIn) envelope.Envelope[map[string]any] {
			return fetch[map[string]any](ctx, d, in.Target, "priv_exec", map[string]any{"command_id": "probe", "args": []string{in.Path}}, d.budget())
		},
	})
	return []Tool{change, read, perTier}
}

type privHarness struct {
	*harness
	g     *recordingGate
	store *approval.Store
	tools map[string]Tool
	pt    *privPreviewTier
}

// newPrivHarness serves the synthetic privileged tools against a recording
// gate under the given approval method and SHELL_MCP_APPROVAL_TIERS.
func newPrivHarness(t *testing.T, method approval.Method, tiers []string) *privHarness {
	t.Helper()
	r := operatorReplies()
	r["priv_stat"] = gateReply{data: fakeFileStat}
	r["priv_chmod"] = gateReply{data: `{"path":"/srv/app/config/app.yaml","old_mode":"0644","mode":"0640"}`}
	r["priv_exec"] = gateReply{data: `{"ran":true}`}
	g := newRecordingGate(r)
	tg, c := sshTarget(t, g.exec)
	clients := map[string]*sshx.Client{"app-host": c}
	logs := &syncBuffer{}
	store := approval.NewStore(approval.Options{TTL: 300 * time.Second, Method: method, Wait: 300 * time.Millisecond,
		Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	d := &Deps{
		Targets: []config.Target{tg},
		Opener: func(name string) (gateclient.Opener, bool) {
			c, ok := clients[name]
			return c, ok
		},
		Gate:           gateclient.New(gateclient.Options{}),
		Principal:      auth.Principal{Name: auth.PrincipalBearer, Profile: "admin"},
		Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
		DefaultTimeout: 10 * time.Second,
		ApprovalTiers:  tiers, ApprovalMethod: method, ApprovalPublicURL: approvalOrigin,
	}
	if method != approval.MethodNone {
		d.Approvals = store
	}
	pt := &privPreviewTier{tier: TierRead}
	server := mcp.NewServer(&mcp.Implementation{Name: "shell-mcp", Version: "test"}, nil)
	byName := map[string]Tool{}
	for _, tool := range syntheticPrivTools(d, pt) {
		tool.Install(server)
		byName[tool.Def.Name] = tool
	}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return &privHarness{harness: &harness{t: t, deps: d, logs: logs, cs: cs}, g: g, store: store, tools: byName, pt: pt}
}

func (p *privHarness) opsSent(op string) int {
	n := 0
	for _, o := range p.g.ops() {
		if o == op {
			n++
		}
	}
	return n
}

var privArgs = map[string]any{"path": "/srv/app/config/app.yaml"}

// TestPrivilegedOperatorAlwaysGated: with SHELL_MCP_APPROVAL_TIERS at its
// default (destructive), a privileged operator tool is still gated: under
// none it refuses and sends nothing, under web it asks for approval; it
// carries requiresUserInteraction. A privileged read tool runs at once.
func TestPrivilegedOperatorAlwaysGated(t *testing.T) {
	p := newPrivHarness(t, approval.MethodNone, []string{"destructive"})
	if m := p.tools["shell_priv_test_change"].Def.Meta; m["anthropic/requiresUserInteraction"] != true {
		t.Fatalf("meta %v", m)
	}
	if m := p.tools["shell_priv_test_read"].Def.Meta; m["anthropic/requiresUserInteraction"] != nil {
		t.Fatalf("a privileged read tool requires user interaction: %v", m)
	}
	env, _ := p.call("shell_priv_test_change", privArgs)
	if errCode(env) != "approval_unavailable" || len(p.g.requests()) != 0 {
		t.Fatalf("under none: %v, sent %v", env, p.g.ops())
	}
	env, _ = p.call("shell_priv_test_read", privArgs)
	if env["ok"] != true || p.opsSent("priv_stat") != 1 {
		t.Fatalf("read: %v, sent %v", env, p.g.ops())
	}

	w := newPrivHarness(t, approval.MethodWeb, []string{"destructive"})
	env, _ = w.call("shell_priv_test_change", privArgs)
	if errCode(env) != "approval_pending" || w.opsSent("priv_chmod") != 0 {
		t.Fatalf("under web: %v, sent %v", env, w.g.ops())
	}
}

// pendingPriv makes the first call and approves it.
func (p *privHarness) pendingPriv() string {
	p.t.Helper()
	env, _ := p.call("shell_priv_test_change", privArgs)
	if errCode(env) != "approval_pending" {
		p.t.Fatalf("first call: %v", env)
	}
	id, _ := approvalOf(p.t, env)["id"].(string)
	if _, err := p.store.Decide(id, true, "alice", "192.0.2.50"); err != nil {
		p.t.Fatal(err)
	}
	return id
}

// TestPrivilegedApprovalBindsBothPolicies: an approval of a privileged
// operation is bound to the gate policy's hash and to the privileged
// policy's (D1, D-006 as extended): an edit of either between approval and
// re-call is approval_invalid, and nothing is changed.
func TestPrivilegedApprovalBindsBothPolicies(t *testing.T) {
	for name, edit := range map[string]func(*recordingGate){
		"privileged policy": func(g *recordingGate) { g.setHelperSHA("beef") },
		"gate policy":       func(g *recordingGate) { g.setSHA("cd34") },
	} {
		t.Run(name, func(t *testing.T) {
			p := newPrivHarness(t, approval.MethodWeb, []string{"destructive"})
			id := p.pendingPriv()
			edit(p.g)
			env, _ := p.call("shell_priv_test_change", withID(privArgs, id))
			if errCode(env) != "approval_invalid" || p.opsSent("priv_chmod") != 0 {
				t.Fatalf("re-call after the %s changed: %v, sent %v", name, env, p.g.ops())
			}
		})
	}
	t.Run("unchanged", func(t *testing.T) {
		p := newPrivHarness(t, approval.MethodWeb, []string{"destructive"})
		id := p.pendingPriv()
		env, _ := p.call("shell_priv_test_change", withID(privArgs, id))
		if env["ok"] != true || p.opsSent("priv_chmod") != 1 {
			t.Fatalf("approved re-call: %v, sent %v", env, p.g.ops())
		}
		for _, q := range p.g.requests() {
			if q.Ceiling != "operator" {
				t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
			}
		}
	})
}

// TestPrivilegedPreviewNeedsHelperBlock: a forwarded answer without the
// helper block (a gate that predates P-1) cannot bind the privileged
// policy, so a privileged preview refuses with internal and no approval is
// requested.
func TestPrivilegedPreviewNeedsHelperBlock(t *testing.T) {
	p := newPrivHarness(t, approval.MethodWeb, []string{"destructive"})
	p.g.set("priv_stat", gateReply{data: fakeFileStat, noHelper: true})
	env, _ := p.call("shell_priv_test_change", privArgs)
	if errCode(env) != "internal" || env["approval"] != nil || p.opsSent("priv_chmod") != 0 {
		t.Fatalf("preview without a helper block: %v", env)
	}
	// Nor without its policy hash.
	p.g.set("priv_stat", gateReply{data: fakeFileStat})
	p.g.setHelperSHA("")
	env, _ = p.call("shell_priv_test_change", privArgs)
	if errCode(env) != "internal" || env["approval"] != nil {
		t.Fatalf("preview with an empty helper policy hash: %v", env)
	}
}

// TestPrivilegedPerTierCeiling: a privileged tool whose gating follows the
// previewed tier (shell_priv_run_command, S4c-6) runs a read operation
// unapproved at ceiling read, and gates an operator one under every
// SHELL_MCP_APPROVAL_TIERS (D9).
func TestPrivilegedPerTierCeiling(t *testing.T) {
	for _, tiers := range [][]string{{"destructive"}, {"operator", "destructive"}} {
		p := newPrivHarness(t, approval.MethodWeb, tiers)
		p.pt.tier = TierRead
		env, _ := p.call("shell_priv_test_command", privArgs)
		if env["ok"] != true {
			t.Fatalf("tiers %v, read: %v", tiers, env)
		}
		if a := p.g.requests(); a[len(a)-1].Op != "priv_exec" || a[len(a)-1].Ceiling != "read" {
			t.Fatalf("tiers %v: unapproved %s at ceiling %s, want read", tiers, a[len(a)-1].Op, a[len(a)-1].Ceiling)
		}
		p.pt.tier = TierOperator
		env, _ = p.call("shell_priv_test_command", privArgs)
		if errCode(env) != "approval_pending" || p.opsSent("priv_exec") != 1 {
			t.Fatalf("tiers %v, operator: %v, sent %v", tiers, env, p.g.ops())
		}
	}
}

// --- The privileged read tools ------------------------------------------------

var privReadTools = []string{"shell_priv_list_backups", "shell_priv_list_directory", "shell_priv_read_file", "shell_priv_stat_path"}

const fakeBackups = `{"backups":[{"id":"20261001T000000Z-0123456789abcdef","kind":"file","path":"/etc/example-app/app.conf","uid":0,"gid":0,
"mode":"0640","size":12,"sha256":"` + shaOld + `","entries":0,"created":"2026-10-01T00:00:00Z","op":"priv_write_file"}],"truncated":false}`

func init() {
	ceilingCallArgs["shell_priv_read_file"] = map[string]any{"path": "/etc/example-app/app.conf"}
	ceilingCallArgs["shell_priv_list_directory"] = map[string]any{"path": "/etc/example-app"}
	ceilingCallArgs["shell_priv_stat_path"] = map[string]any{"path": "/etc/example-app/app.conf"}
	ceilingCallArgs["shell_priv_list_backups"] = map[string]any{}
}

// privReplies answers the helper's read ops in their wire shapes.
func privReplies(r map[string]gateReply) map[string]gateReply {
	r["priv_read_file"] = gateReply{data: fakeRead("key: value\n")}
	r["priv_list_dir"] = gateReply{data: fakeList("app.conf", "conf.d")}
	r["priv_stat"] = gateReply{data: fakeStatEntry}
	r["priv_list_backups"] = gateReply{data: fakeBackups}
	r["priv_delete_preview"] = gateReply{data: fakeDeletePreview(shaDel)}
	return r
}

// TestPrivReadToolsRegistered: admin only, privileged, read tier, read
// annotations, never approval inputs; dropped from a target whose gate does
// not forward privileged operations.
func TestPrivReadToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, n := range names(reg.ToolsForProfile(p, nil)) {
			if strings.HasPrefix(n, "shell_priv_") {
				t.Fatalf("%s is registered in the %s profile", n, p)
			}
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	for _, want := range privReadTools {
		i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == want })
		if i < 0 {
			t.Fatalf("%s is not registered in admin (have %v)", want, names(admin))
		}
		r := admin[i]
		a := r.Tool.Def.Annotations
		if r.Tier != TierRead || !r.Privileged || r.Tool.Tier != TierRead || !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
			t.Fatalf("%s: tier %s privileged %v annotations %+v", want, r.Tier, r.Privileged, a)
		}
		if !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
			t.Fatalf("%s: description does not say it runs as root: %q", want, r.Tool.Def.Description)
		}
		in := schemaOf(t, r)
		if in.Properties["approval_id"] != nil || r.Tool.Def.Meta != nil {
			t.Fatalf("%s carries approval inputs or meta", want)
		}
	}
	on := EffectiveTools(admin, "destructive", true, "destructive")
	off := EffectiveTools(admin, "destructive", false, "destructive")
	for _, n := range privReadTools {
		if !slices.Contains(on, n) || slices.Contains(off, n) {
			t.Fatalf("%s: effective with forwarding %v, without %v", n, slices.Contains(on, n), slices.Contains(off, n))
		}
	}
}

// TestPrivReadTools: each tool sends its helper op once at ceiling read
// with the arguments given, and shapes the result as its unprivileged
// equivalent does: the server's redaction, the output caps and truncation.
func TestPrivReadTools(t *testing.T) {
	tok := randomToken(t)
	g := newRecordingGate(privReplies(allReplies()))
	g.set("priv_read_file", gateReply{data: fakeRead("api: " + tok + "\n" + strings.Repeat("x", 8000))})
	h := readHarness(t, g)
	withServerPattern(h)

	env, _ := h.call("shell_priv_read_file", map[string]any{"path": "/etc/example-app/app.conf", "max_bytes": 9000})
	d := data(t, env)
	content, _ := d["content"].(string)
	if strings.Contains(jsonOf(t, env), tok) || !strings.Contains(content, "[REDACTED") || len(content) > 4096 || d["truncated"] != true {
		t.Fatalf("read: %v", d)
	}
	if a := g.args(t, "priv_read_file"); a["path"] != "/etc/example-app/app.conf" || a["max_bytes"] != float64(9000) {
		t.Fatalf("read args %v", a)
	}

	env, _ = h.call("shell_priv_list_directory", map[string]any{"path": "/etc/example-app", "include_hidden": true, "limit": 7})
	if d := data(t, env); len(d["entries"].([]any)) != 2 {
		t.Fatalf("list: %v", d)
	}
	if a := g.args(t, "priv_list_dir"); a["path"] != "/etc/example-app" || a["include_hidden"] != true || a["limit"] != float64(7) {
		t.Fatalf("list args %v", a)
	}

	env, _ = h.call("shell_priv_stat_path", map[string]any{"path": "/etc/example-app/app.conf"})
	if d := data(t, env); d["type"] != "symlink" {
		t.Fatalf("stat: %v", d)
	}

	env, _ = h.call("shell_priv_list_backups", map[string]any{"path": "/etc/example-app/app.conf", "limit": 5})
	b := data(t, env)["backups"].([]any)
	if len(b) != 1 || b[0].(map[string]any)["id"] != "20261001T000000Z-0123456789abcdef" {
		t.Fatalf("backups: %v", env)
	}
	if a := g.args(t, "priv_list_backups"); a["path"] != "/etc/example-app/app.conf" || a["limit"] != float64(5) {
		t.Fatalf("backups args %v", a)
	}
	for _, q := range g.requests() {
		if q.Ceiling != "read" || !strings.HasPrefix(q.Op, "priv_") {
			t.Fatalf("%s at ceiling %s", q.Op, q.Ceiling)
		}
	}
}

// TestPrivReadToolsRefusals: the helper's refusals pass through with their
// code; bad input is a validation_error and sends nothing.
func TestPrivReadToolsRefusals(t *testing.T) {
	g := newRecordingGate(privReplies(allReplies()))
	h := readHarness(t, g)
	for op, code := range map[string]string{"priv_read_file": "path_denied", "priv_list_dir": "not_a_directory", "priv_stat": "not_found", "priv_list_backups": "bad_request"} {
		g.set(op, gateReply{code: code, msg: "refused by the helper"})
	}
	for name, c := range map[string]struct {
		args map[string]any
		code string
	}{
		"shell_priv_read_file":      {map[string]any{"path": "/etc/example-app/secrets/key"}, "path_denied"},
		"shell_priv_list_directory": {map[string]any{"path": "/etc/example-app/app.conf"}, "not_a_directory"},
		"shell_priv_stat_path":      {map[string]any{"path": "/etc/example-app/gone"}, "not_found"},
		"shell_priv_list_backups":   {map[string]any{"path": "/etc/example-app/app.conf"}, "bad_request"},
	} {
		if env, _ := h.call(name, c.args); errCode(env) != c.code {
			t.Fatalf("%s: %v, want %s", name, env, c.code)
		}
	}
	before := len(g.requests())
	for _, c := range []struct {
		name string
		args map[string]any
	}{
		{"shell_priv_read_file", map[string]any{"path": "etc/example-app"}},
		{"shell_priv_read_file", map[string]any{"path": "/etc/example-app/x", "offset": 1, "tail_lines": 2}},
		{"shell_priv_read_file", map[string]any{"path": "/etc/example-app/x", "max_bytes": 0}},
		{"shell_priv_list_directory", map[string]any{"path": "/etc/example-app/../shadow"}},
		{"shell_priv_list_directory", map[string]any{"path": "/etc/example-app", "limit": 5001}},
		{"shell_priv_stat_path", map[string]any{"path": "/etc//example-app"}},
		{"shell_priv_list_backups", map[string]any{"path": "relative"}},
		{"shell_priv_list_backups", map[string]any{"limit": 0}},
		{"shell_priv_list_backups", map[string]any{"limit": 1001}},
		{"shell_priv_stat_path", map[string]any{"path": "/etc/example-app", "approval_id": strings.Repeat("a", 26)}},
	} {
		if env, _ := h.call(c.name, c.args); errCode(env) != "validation_error" {
			t.Fatalf("%s %v: %v", c.name, c.args, env)
		}
	}
	if n := len(g.requests()); n != before {
		t.Fatalf("invalid input reached the gate: %v", g.ops()[before:])
	}
}
