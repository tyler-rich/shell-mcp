package tools

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// Operator-tier tools against a recording fake gate (docs/TOOLS.md,
// operator tier). Every path, unit, repository and command below is an
// invented fixture; token-shaped values are generated at test time.

var operatorTools = []string{
	"shell_control_service", "shell_write_file", "shell_make_directory", "shell_copy_path",
	"shell_move_path", "shell_set_permissions", "shell_git_pull", "shell_run_command",
}

// operatorIdempotent is each operator tool's idempotentHint (TOOLS.md,
// "Operator tier: what the table leaves open").
var operatorIdempotent = map[string]bool{
	"shell_control_service": false, "shell_write_file": true, "shell_make_directory": true,
	"shell_copy_path": true, "shell_move_path": false, "shell_set_permissions": true,
	"shell_git_pull": false, "shell_run_command": false,
}

const (
	shaOld = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	shaNew = "2222222222222222222222222222222222222222222222222222222222222222"
	head1  = "0123456789abcdef0123456789abcdef01234567"
	head2  = "89abcdef0123456789abcdef0123456789abcdef"
)

// --- Fake gate data, in the gate's wire shapes (internal/gate/fsx,
// internal/gate/ops) ---------------------------------------------------------

const (
	fakeWrite = `{"path":"/srv/app/config/app.yaml","sha256":"` + shaNew + `","old_sha256":"` + shaOld + `","bytes":12,"created":false,
"mode":"0640","lines_old":3,"lines_new":5,"owner_preserved":true,"verified":true}`
	fakeCreate = `{"path":"/srv/app/config/new.yaml","sha256":"` + shaNew + `","bytes":4,"created":true,
"mode":"0640","lines_old":0,"lines_new":1,"owner_preserved":false,"verified":true}`
	fakeUnverified = `{"path":"/srv/app/config/app.yaml","sha256":"` + shaNew + `","old_sha256":"` + shaOld + `","bytes":12,"created":false,
"mode":"0640","lines_old":3,"lines_new":5,"owner_preserved":true,"verified":false}`
	fakeCopy = `{"path":"/srv/app/config/app.yaml.bak","sha256":"` + shaNew + `","bytes":12,"created":true,
"mode":"0640","lines_old":0,"lines_new":5,"owner_preserved":false,"verified":true}`
	fakeMkdir   = `{"path":"/srv/app/config/conf.d","created":true,"mode":"0750"}`
	fakeMove    = `{"source":"/srv/app/config/a.yaml","destination":"/srv/app/config/b.yaml","type":"file","replaced":false}`
	fakeChmod   = `{"path":"/srv/app/config/app.yaml","old_mode":"0644","mode":"0600"}`
	fakePull    = `{"repo":"/srv/app/deploy","old_head":"` + head1 + `","new_head":"` + head2 + `","changed_files":3,"updated":true}`
	fakeControl = `{"unit":"example-app.service","action":"restart","status":` + fakeStatus + `}`
)

// operatorReplies answers every operator op with typical data.
func operatorReplies() map[string]gateReply {
	r := allReplies()
	r["write_file"] = gateReply{data: fakeWrite}
	r["mkdir"] = gateReply{data: fakeMkdir}
	r["copy"] = gateReply{data: fakeCopy}
	r["move"] = gateReply{data: fakeMove}
	r["chmod"] = gateReply{data: fakeChmod}
	r["git_pull"] = gateReply{data: fakePull}
	r["service_control"] = gateReply{data: fakeControl}
	r["exec_preview"] = gateReply{data: fakeExecPreview(shaExec, "operator")}
	return r
}

// operatorCallArgs are valid arguments for every operator tool.
var operatorCallArgs = map[string]map[string]any{
	"shell_control_service": {"unit": "example-app.service", "action": "restart"},
	"shell_write_file":      {"path": "/srv/app/config/app.yaml", "content": "key: value\n"},
	"shell_make_directory":  {"path": "/srv/app/config/conf.d"},
	"shell_copy_path":       {"source": "/srv/app/config/app.yaml", "destination": "/srv/app/config/app.yaml.bak"},
	"shell_move_path":       {"source": "/srv/app/config/a.yaml", "destination": "/srv/app/config/b.yaml"},
	"shell_set_permissions": {"path": "/srv/app/config/app.yaml", "mode": "0600"},
	"shell_git_pull":        {"repo": "/srv/app/deploy"},
	"shell_run_command":     {"command_id": "app-restart", "args": []string{"restart"}},
}

func init() {
	for name, args := range operatorCallArgs {
		ceilingCallArgs[name] = args
	}
}

// --- Registration, annotations, schemas ----------------------------------------

func TestOperatorToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	ro := names(reg.ToolsForProfile(ProfileReadOnly, nil))
	for _, p := range []Profile{ProfileOperator, ProfileAdmin} {
		regs := reg.ToolsForProfile(p, nil)
		for _, want := range operatorTools {
			i := slices.IndexFunc(regs, func(r Registration) bool { return r.Tool.Def.Name == want })
			if i < 0 {
				t.Fatalf("%s is not registered in the %s profile (have %v)", want, p, names(regs))
			}
			// shell_run_command is registered at destructive in admin
			// (TestRunCommandRegistrations).
			wantTier := TierOperator
			if want == "shell_run_command" && p == ProfileAdmin {
				wantTier = TierDestructive
			}
			if regs[i].Tier != wantTier || regs[i].Privileged || regs[i].Tool.Tier != wantTier {
				t.Fatalf("%s in %s: tier %s (defined %s), privileged %v", want, p, regs[i].Tier, regs[i].Tool.Tier, regs[i].Privileged)
			}
		}
	}
	for _, n := range operatorTools {
		if slices.Contains(ro, n) {
			t.Fatalf("%s is registered in the read-only profile", n)
		}
	}
}

func TestOperatorToolAnnotations(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reg.ToolsForProfile(ProfileAdmin, nil) {
		want, ok := operatorIdempotent[r.Tool.Def.Name]
		if r.Tier != TierOperator {
			continue
		}
		if !ok {
			t.Fatalf("%s: operator tool without an idempotency decision", r.Tool.Def.Name)
		}
		a := r.Tool.Def.Annotations
		if a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || a.IdempotentHint != want ||
			a.OpenWorldHint == nil || !*a.OpenWorldHint || a.Title == "" || a.Title != r.Tool.Def.Title {
			t.Fatalf("%s: annotations %+v (want idempotent %v)", r.Tool.Def.Name, a, want)
		}
	}
}

func TestOperatorToolSchemaBounds(t *testing.T) {
	type bound struct{ min, max float64 }
	cases := map[string]struct {
		required []string
		ints     map[string]bound
		enums    map[string][]any
		strs     map[string]int
	}{
		"shell_control_service": {required: []string{"unit", "action"}, strs: map[string]int{"unit": 256},
			enums: map[string][]any{"action": {"start", "stop", "restart", "reload"}}, ints: map[string]bound{"timeout_seconds": {1, 3600}}},
		"shell_write_file": {required: []string{"path", "content"},
			strs: map[string]int{"path": 4096, "content": 1 << 20, "mode": 4, "expected_sha256": 64}},
		"shell_make_directory":  {required: []string{"path"}, strs: map[string]int{"path": 4096, "mode": 4}},
		"shell_copy_path":       {required: []string{"source", "destination"}, strs: map[string]int{"source": 4096, "destination": 4096}},
		"shell_move_path":       {required: []string{"source", "destination"}, strs: map[string]int{"source": 4096, "destination": 4096}},
		"shell_set_permissions": {required: []string{"path", "mode"}, strs: map[string]int{"path": 4096, "mode": 4}},
		"shell_git_pull":        {required: []string{"repo"}, strs: map[string]int{"repo": 4096}, ints: map[string]bound{"timeout_seconds": {1, 3600}}},
		"shell_run_command": {required: []string{"command_id"}, strs: map[string]int{"command_id": 63, "cwd": 4096, "stdin": 1 << 20},
			ints: map[string]bound{"timeout_seconds": {1, 3600}, "max_output_bytes": {1, 4 << 20}}},
	}
	for _, name := range operatorTools {
		c, ok := cases[name]
		if !ok {
			t.Fatalf("no schema case for %s", name)
		}
		t.Run(name, func(t *testing.T) {
			s := inputSchema(t, name)
			req := slices.Clone(s.Required)
			slices.Sort(req)
			want := slices.Clone(c.required)
			slices.Sort(want)
			if !slices.Equal(req, want) {
				t.Fatalf("required %v, want %v", req, want)
			}
			if s.Properties["target"] == nil {
				t.Fatal("no target property")
			}
			for p, b := range c.ints {
				ps := s.Properties[p]
				if ps == nil || ps.Type != "integer" || ps.Minimum == nil || ps.Maximum == nil || *ps.Minimum != b.min || *ps.Maximum != b.max {
					t.Fatalf("%s: %s", p, jsonOf(t, ps))
				}
			}
			for p, e := range c.enums {
				if ps := s.Properties[p]; ps == nil || jsonOf(t, ps.Enum) != jsonOf(t, e) {
					t.Fatalf("%s: %s", p, jsonOf(t, ps))
				}
			}
			for p, n := range c.strs {
				if ps := s.Properties[p]; ps == nil || ps.MaxLength == nil || *ps.MaxLength != n || ps.Pattern == "" {
					t.Fatalf("%s: %s", p, jsonOf(t, ps))
				}
			}
			for p, ps := range s.Properties {
				if ps.Description == "" {
					t.Fatalf("%s has no description", p)
				}
				if ps.Type == "integer" && (ps.Minimum == nil || ps.Maximum == nil) {
					t.Fatalf("%s: integer without bounds", p)
				}
			}
		})
	}
	args := inputSchema(t, "shell_run_command").Properties["args"]
	if args == nil || args.Type != "array" || args.MaxItems == nil || *args.MaxItems != 64 || args.Items == nil ||
		args.Items.MaxLength == nil || *args.Items.MaxLength != 1024 || args.Items.Pattern == "" || args.Description == "" {
		t.Fatalf("args: %s", jsonOf(t, args))
	}
	for _, p := range []string{"content_b64", "stdin_b64", "confirm"} {
		for _, name := range operatorTools {
			if inputSchema(t, name).Properties[p] != nil {
				t.Fatalf("%s: %s must not be an input", name, p)
			}
		}
	}
}

// --- Validation before the gate --------------------------------------------

// TestOperatorToolsValidation: clearly bad input is a validation_error and
// no gate request is sent; content and stdin are bounded here, before
// anything is sent.
func TestOperatorToolsValidation(t *testing.T) {
	g := newRecordingGate(operatorReplies())
	h := operatorHarness(t, g)
	tooBig := strings.Repeat("a", 1<<20+1)
	many := make([]string, 65)
	for i := range many {
		many[i] = "x"
	}
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"shell_control_service", map[string]any{"unit": "example-*.service", "action": "restart"}},
		{"shell_control_service", map[string]any{"unit": "example-app", "action": "restart"}},
		{"shell_control_service", map[string]any{"unit": "example-app.service", "action": "kill"}},
		{"shell_control_service", map[string]any{"unit": "example-app.service"}},
		{"shell_control_service", map[string]any{"unit": "example-app.service", "action": "restart", "timeout_seconds": 0}},
		{"shell_write_file", map[string]any{"path": "srv/app/config/app.yaml", "content": "x"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/../app.yaml", "content": "x"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": tooBig}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "mode": "rw-r--r--"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "mode": "644 "}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "mode": "06440"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "mode": "0x1a4"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "expected_sha256": strings.ToUpper(shaOld)}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "expected_sha256": shaOld[:63]}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "x", "create": "yes"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content_b64": "eA=="}},
		{"shell_make_directory", map[string]any{"path": "/srv/app/config/conf.d/"}},
		{"shell_make_directory", map[string]any{"path": "/srv/app/config/conf.d", "mode": "abc"}},
		{"shell_copy_path", map[string]any{"source": "app.yaml", "destination": "/srv/app/config/b.yaml"}},
		{"shell_copy_path", map[string]any{"source": "/srv/app/config/app.yaml"}},
		{"shell_move_path", map[string]any{"source": "/srv/app/config/a.yaml", "destination": "/srv/app//config/b.yaml"}},
		{"shell_move_path", map[string]any{"source": "/srv/app/config/a.yaml", "destination": "/srv/app/config/b.yaml", "overwrite": "true"}},
		{"shell_set_permissions", map[string]any{"path": "/srv/app/config/app.yaml"}},
		{"shell_set_permissions", map[string]any{"path": "/srv/app/config/app.yaml", "mode": "999"}},
		{"shell_set_permissions", map[string]any{"path": "/srv/app/config/app.yaml", "mode": "60"}},
		{"shell_git_pull", map[string]any{"repo": "srv/app/deploy"}},
		{"shell_git_pull", map[string]any{"repo": "/srv/app/deploy", "timeout_seconds": 3601}},
		{"shell_run_command", map[string]any{"command_id": "App-Restart"}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "args": many}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "args": []string{"a\nb"}}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "cwd": "srv"}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "stdin": tooBig}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "timeout_seconds": 0}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "max_output_bytes": 0}},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "stdin_b64": "eA=="}},
	}
	for _, c := range cases {
		env, _ := h.call(c.tool, c.args)
		if errCode(env) != "validation_error" {
			t.Fatalf("%s(%v): %v, want validation_error", c.tool, keys(c.args), env)
		}
	}
	if ops := g.ops(); len(ops) != 0 {
		t.Fatalf("validation failures reached the gate: %v", ops)
	}
}

func keys(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// --- Gate op, arguments and ceiling -----------------------------------------

// TestOperatorToolsCallTheirOp: each tool sends exactly one request, of its
// op, with exactly these arguments, at ceiling operator.
func TestOperatorToolsCallTheirOp(t *testing.T) {
	content := "key: value\nmode: example\n"
	stdin := "line one\nline two\n"
	cases := []struct {
		tool     string
		args     map[string]any
		op       string
		gateArgs string
	}{
		{"shell_control_service", map[string]any{"unit": "example-app.service", "action": "reload"}, "service_control",
			`{"action":"reload","unit":"example-app.service"}`},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": content}, "write_file",
			`{"content_b64":"` + base64.StdEncoding.EncodeToString([]byte(content)) + `","create":true,"expected_sha256":"","mode":"","path":"/srv/app/config/app.yaml"}`},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "", "mode": "0600", "create": false, "expected_sha256": shaOld},
			"write_file", `{"content_b64":"","create":false,"expected_sha256":"` + shaOld + `","mode":"0600","path":"/srv/app/config/app.yaml"}`},
		{"shell_make_directory", map[string]any{"path": "/srv/app/config/conf.d"}, "mkdir", `{"mode":"","parents":false,"path":"/srv/app/config/conf.d"}`},
		{"shell_make_directory", map[string]any{"path": "/srv/app/config/a/b", "mode": "750", "parents": true}, "mkdir",
			`{"mode":"750","parents":true,"path":"/srv/app/config/a/b"}`},
		{"shell_copy_path", map[string]any{"source": "/srv/app/config/app.yaml", "destination": "/srv/app/config/app.yaml.bak"}, "copy",
			`{"destination":"/srv/app/config/app.yaml.bak","overwrite":false,"source":"/srv/app/config/app.yaml"}`},
		{"shell_move_path", map[string]any{"source": "/srv/app/config/a.yaml", "destination": "/srv/app/config/b.yaml", "overwrite": true}, "move",
			`{"destination":"/srv/app/config/b.yaml","overwrite":true,"source":"/srv/app/config/a.yaml"}`},
		{"shell_set_permissions", map[string]any{"path": "/srv/app/config/app.yaml", "mode": "0600"}, "chmod", `{"mode":"0600","path":"/srv/app/config/app.yaml"}`},
		{"shell_git_pull", map[string]any{"repo": "/srv/app/deploy"}, "git_pull", `{"repo":"/srv/app/deploy"}`},
		{"shell_run_command", map[string]any{"command_id": "app-restart", "args": []string{"restart"}}, "exec",
			`{"args":["restart"],"command_id":"app-restart","cwd":"","expected_preview_sha256":"` + shaExec + `","max_output_bytes":0,"stdin_b64":""}`},
		{"shell_run_command", map[string]any{"command_id": "app-import", "cwd": "/srv/app", "stdin": stdin, "max_output_bytes": 100}, "exec",
			`{"args":[],"command_id":"app-import","cwd":"/srv/app","expected_preview_sha256":"` + shaExec + `","max_output_bytes":100,"stdin_b64":"` + base64.StdEncoding.EncodeToString([]byte(stdin)) + `"}`},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			g := newRecordingGate(operatorReplies())
			h := operatorHarness(t, g)
			env, _ := h.call(c.tool, c.args)
			if env["ok"] != true {
				t.Fatalf("envelope %v", env)
			}
			reqs := g.requests()
			// shell_run_command resolves the command with exec_preview first
			// (its gating follows the command's tier).
			want := []string{c.op}
			if c.tool == "shell_run_command" {
				want = []string{"exec_preview", "exec"}
			}
			if !slices.Equal(g.ops(), want) || reqs[len(reqs)-1].Ceiling != "operator" {
				t.Fatalf("requests %v, want %v, the last at ceiling operator", g.ops(), want)
			}
			if got := jsonOf(t, g.args(t, c.op)); got != c.gateArgs {
				t.Fatalf("gate args %s\nwant %s", got, c.gateArgs)
			}
		})
	}
}

// TestOperatorToolsTimeoutBudget: timeout_seconds sets the request's
// timeout on the tools that run a process.
func TestOperatorToolsTimeoutBudget(t *testing.T) {
	for _, tool := range []string{"shell_control_service", "shell_git_pull", "shell_run_command"} {
		g := newRecordingGate(operatorReplies())
		h := operatorHarness(t, g)
		args := map[string]any{"timeout_seconds": 42}
		for k, v := range operatorCallArgs[tool] {
			args[k] = v
		}
		if env, _ := h.call(tool, args); env["ok"] != true {
			t.Fatalf("%s: %v", tool, env)
		}
		if r := g.requests(); len(r) == 0 || r[len(r)-1].TimeoutMS != 42000 {
			t.Fatalf("%s: requests %+v", tool, r)
		}
	}
}

// --- Results -------------------------------------------------------------------

// TestWriteFileResult: old and new SHA-256 and a line-count summary, never
// content; verified in the envelope.
func TestWriteFileResult(t *testing.T) {
	tok := randomToken(t)
	g := newRecordingGate(operatorReplies())
	h := operatorHarness(t, g)
	env, res := h.call("shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "token: " + tok + "\n"})
	d := data(t, env)
	want := map[string]any{"path": "/srv/app/config/app.yaml", "created": false, "bytes": 12.0, "mode": "0640",
		"old_sha256": shaOld, "new_sha256": shaNew, "lines_old": 3.0, "lines_new": 5.0, "lines_delta": 2.0, "owner_preserved": true}
	if jsonOf(t, d) != jsonOf(t, want) {
		t.Fatalf("data %s\nwant %s", jsonOf(t, d), jsonOf(t, want))
	}
	if env["verified"] != true {
		t.Fatalf("verified %v", env["verified"])
	}
	if strings.Contains(jsonOf(t, res), tok[7:]) || strings.Contains(jsonOf(t, env), "content") {
		t.Fatalf("the result carries the content: %s", jsonOf(t, res))
	}

	// A created file has no old hash; its delta counts every line.
	r := operatorReplies()
	r["write_file"] = gateReply{data: fakeCreate}
	h = operatorHarness(t, newRecordingGate(r))
	env, _ = h.call("shell_write_file", map[string]any{"path": "/srv/app/config/new.yaml", "content": "new\n"})
	if d := data(t, env); d["created"] != true || d["old_sha256"] != "" || d["new_sha256"] != shaNew || d["lines_delta"] != 1.0 || env["verified"] != true {
		t.Fatalf("created: %v", env)
	}
}

// TestUnverifiedWriteIsFailure: a gate answer with verified false is a
// failure (verify_failed), never a success with a warning.
func TestUnverifiedWriteIsFailure(t *testing.T) {
	for _, c := range []struct {
		tool, op, reply string
		args            map[string]any
	}{
		{"shell_write_file", "write_file", fakeUnverified, map[string]any{"path": "/srv/app/config/app.yaml", "content": "x"}},
		{"shell_copy_path", "copy", strings.Replace(fakeCopy, `"verified":true`, `"verified":false`, 1),
			map[string]any{"source": "/srv/app/config/app.yaml", "destination": "/srv/app/config/app.yaml.bak"}},
	} {
		r := operatorReplies()
		r[c.op] = gateReply{data: c.reply}
		h := operatorHarness(t, newRecordingGate(r))
		env, res := h.call(c.tool, c.args)
		if errCode(env) != "verify_failed" || !res.IsError || env["data"] != nil || env["verified"] != nil {
			t.Fatalf("%s: %v, want verify_failed", c.tool, env)
		}
	}
}

func TestOperatorToolResults(t *testing.T) {
	g := newRecordingGate(operatorReplies())
	h := operatorHarness(t, g)
	cases := []struct {
		tool string
		want string
		env  func(t *testing.T, env map[string]any)
	}{
		{"shell_control_service", `{"action":"restart","status":` + jsonOf(t, mustMap(t, fakeStatus)) + `,"unit":"example-app.service"}`, nil},
		{"shell_make_directory", `{"created":true,"mode":"0750","path":"/srv/app/config/conf.d"}`, nil},
		{"shell_copy_path", `{"bytes":12,"created":true,"destination":"/srv/app/config/app.yaml.bak","mode":"0640","old_sha256":"","sha256":"` + shaNew +
			`","source":"/srv/app/config/app.yaml"}`, func(t *testing.T, env map[string]any) {
			if env["verified"] != true {
				t.Fatalf("copy is read-back verified: %v", env)
			}
		}},
		{"shell_move_path", `{"destination":"/srv/app/config/b.yaml","replaced":false,"source":"/srv/app/config/a.yaml","type":"file"}`, nil},
		{"shell_set_permissions", `{"mode":"0600","old_mode":"0644","path":"/srv/app/config/app.yaml"}`, nil},
		{"shell_git_pull", `{"changed_files":3,"new_head":"` + head2 + `","old_head":"` + head1 + `","repo":"/srv/app/deploy","updated":true}`, nil},
	}
	for _, c := range cases {
		env, _ := h.call(c.tool, operatorCallArgs[c.tool])
		if got := jsonOf(t, data(t, env)); got != c.want {
			t.Fatalf("%s: data %s\nwant %s", c.tool, got, c.want)
		}
		if g, _ := env["gate"].(map[string]any); g["principal"] != "readonly-key" {
			t.Fatalf("%s: gate block %v", c.tool, env["gate"])
		}
		if c.env != nil {
			c.env(t, env)
		}
	}
}

func mustMap(t *testing.T, s string) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestRunCommand: a non-zero exit is ok with exec.exit_code; output is
// redacted and capped as for the read command.
func TestRunCommand(t *testing.T) {
	tok := randomToken(t)
	r := operatorReplies()
	r["exec"] = gateReply{data: fakeExec("restarted with "+tok+"\n", 2)}
	h := operatorHarness(t, newRecordingGate(r))
	withServerPattern(h)
	env, _ := h.call("shell_run_command", map[string]any{"command_id": "app-restart", "args": []string{"restart"}})
	d := data(t, env)
	ex, _ := env["exec"].(map[string]any)
	if ex["exit_code"] != 2.0 || d["stdout"] != "restarted with [REDACTED]\n" || d["command_id"] != "app-status" {
		t.Fatalf("envelope %v", env)
	}
	r["exec"] = gateReply{data: fakeExec(strings.Repeat("x", 300), 0)}
	h = operatorHarness(t, newRecordingGate(r))
	env, _ = h.call("shell_run_command", map[string]any{"command_id": "app-restart", "max_output_bytes": 100})
	if d := data(t, env); len(d["stdout"].(string)) != 100 || d["stdout_truncated"] != true || env["exec"].(map[string]any)["stdout_truncated"] != true {
		t.Fatalf("capped %v", env)
	}
}

// --- Errors ----------------------------------------------------------------------

func TestOperatorToolsGateErrorsPassThrough(t *testing.T) {
	cases := []struct {
		tool  string
		op    string
		reply gateReply
	}{
		{"shell_control_service", "service_control", gateReply{code: "not_authorized", msg: "polkit refused systemctl restart for this unit (exit 4); install the rule from shell-mcp-gate polkit"}},
		{"shell_control_service", "service_control", gateReply{code: "policy_denied", msg: "unit is not in services.control.units"}},
		{"shell_control_service", "service_control", gateReply{code: "exec_failed", msg: "systemctl restart failed (exit 1)"}},
		{"shell_write_file", "write_file", gateReply{code: "path_denied", msg: "path is outside the policy's write roots"}},
		{"shell_write_file", "write_file", gateReply{code: "exists", msg: "the file changed since expected_sha256 was read"}},
		{"shell_write_file", "write_file", gateReply{code: "verify_failed", msg: "read-back SHA-256 does not match what was written"}},
		{"shell_write_file", "write_file", gateReply{code: "too_large", msg: "content exceeds max_write_bytes (4096)"}},
		{"shell_make_directory", "mkdir", gateReply{code: "exists", msg: "already exists"}},
		{"shell_copy_path", "copy", gateReply{code: "exists", msg: "destination exists"}},
		{"shell_move_path", "move", gateReply{code: "path_denied", msg: "path has a .git component"}},
		{"shell_set_permissions", "chmod", gateReply{code: "policy_denied", msg: "setuid, setgid and sticky bits are not allowed"}},
		{"shell_git_pull", "git_pull", gateReply{code: "policy_denied", msg: "the working tree has uncommitted changes to tracked files; commit or discard them first"}},
		{"shell_git_pull", "git_pull", gateReply{code: "policy_denied", msg: "remote.origin.url is not the remote the policy lists for this repo"}},
		{"shell_run_command", "exec", gateReply{code: "tier_denied", msg: "command tier destructive exceeds the request's ceiling operator"}},
		{"shell_run_command", "exec", gateReply{code: "template_mismatch", msg: "arguments match no template"}},
		{"shell_write_file", "write_file", gateReply{code: "install_insecure", msg: "the gate's policy file is group-writable", noID: true}},
		{"shell_write_file", "write_file", gateReply{code: "tier_denied", msg: "operation tier operator exceeds max_tier read"}},
	}
	for _, c := range cases {
		t.Run(c.tool+"_"+c.reply.code, func(t *testing.T) {
			r := operatorReplies()
			r[c.op] = c.reply
			h := operatorHarness(t, newRecordingGate(r))
			env, res := h.call(c.tool, operatorCallArgs[c.tool])
			e, _ := env["error"].(map[string]any)
			if !res.IsError || e["code"] != c.reply.code || e["message"] != c.reply.msg || env["data"] != nil {
				t.Fatalf("envelope %v, want %s %q", env, c.reply.code, c.reply.msg)
			}
		})
	}
}

// --- Approval guard ------------------------------------------------------------

// TestApprovalGuard: with operator in SHELL_MCP_APPROVAL_TIERS and no
// approval method (SHELL_MCP_APPROVAL_METHOD=none, the zero Deps), every
// operator tool refuses with approval_unavailable and sends nothing; read
// tools are unaffected. With the default (destructive) the operator tools
// run.
func TestApprovalGuard(t *testing.T) {
	g := newRecordingGate(operatorReplies())
	h := operatorHarness(t, g)
	h.deps.ApprovalTiers = []string{"operator", "destructive"}
	for _, name := range operatorTools {
		if name == "shell_run_command" {
			continue // gated by the command's tier, after its preview (TestRunCommandPerTierWithoutApprovalMethod)
		}
		for _, args := range []map[string]any{operatorCallArgs[name], {"target": "app-host"}} {
			env, res := h.call(name, args)
			e, _ := env["error"].(map[string]any)
			msg, _ := e["message"].(string)
			if !res.IsError || e["code"] != "approval_unavailable" || !strings.Contains(msg, "SHELL_MCP_APPROVAL_METHOD=none") {
				t.Fatalf("%s: %v, want approval_unavailable", name, env)
			}
		}
	}
	if ops := g.ops(); len(ops) != 0 {
		t.Fatalf("requests reached the gate under the guard: %v", ops)
	}
	if env, _ := h.call("shell_read_file", map[string]any{"path": "/srv/app/config.yaml"}); env["ok"] != true {
		t.Fatalf("read tool under the guard: %v", env)
	}
	h.deps.ApprovalTiers = []string{"destructive"}
	for _, name := range operatorTools {
		if env, _ := h.call(name, operatorCallArgs[name]); env["ok"] != true {
			t.Fatalf("%s with approval tiers [destructive]: %v", name, env)
		}
	}
}

// --- Text block and audit ----------------------------------------------------

func TestOperatorToolsTextSummary(t *testing.T) {
	h := operatorHarness(t, newRecordingGate(operatorReplies()))
	for _, name := range operatorTools {
		_, res := h.call(name, operatorCallArgs[name])
		var tc struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal([]byte(jsonOf(t, res.Content[0])), &tc); err != nil {
			t.Fatal(err)
		}
		first, _, _ := strings.Cut(tc.Text, "\n")
		for _, s := range []string{"/srv", "example-app", "restart", "key: value", shaNew[:8], head2[:8], "app-"} {
			if strings.Contains(first, s) {
				t.Fatalf("%s: summary %q carries host or caller text %q", name, first, s)
			}
		}
		if !strings.HasPrefix(first, "ok") || len(first) > 200 {
			t.Fatalf("%s: summary %q", name, first)
		}
	}
}

// TestOperatorToolsAudit: paths, units, ids, modes and flags only; never
// file content, stdin or command arguments.
func TestOperatorToolsAudit(t *testing.T) {
	tok := randomToken(t)
	h := operatorHarness(t, newRecordingGate(operatorReplies()))
	calls := []struct {
		tool string
		args map[string]any
		want map[string]any
	}{
		{"shell_control_service", map[string]any{"unit": "example-app.service", "action": "restart"}, map[string]any{"unit": "example-app.service", "action": "restart"}},
		{"shell_write_file", map[string]any{"path": "/srv/app/config/app.yaml", "content": "token: " + tok, "mode": "0640", "expected_sha256": shaOld},
			map[string]any{"path": "/srv/app/config/app.yaml", "mode": "0640", "create": true, "content_bytes": float64(len("token: " + tok))}},
		{"shell_make_directory", map[string]any{"path": "/srv/app/config/conf.d", "parents": true}, map[string]any{"path": "/srv/app/config/conf.d", "parents": true}},
		{"shell_copy_path", map[string]any{"source": "/srv/app/config/app.yaml", "destination": "/srv/app/config/app.yaml.bak"},
			map[string]any{"source": "/srv/app/config/app.yaml", "destination": "/srv/app/config/app.yaml.bak", "overwrite": false}},
		{"shell_move_path", map[string]any{"source": "/srv/app/config/a.yaml", "destination": "/srv/app/config/b.yaml", "overwrite": true},
			map[string]any{"source": "/srv/app/config/a.yaml", "destination": "/srv/app/config/b.yaml", "overwrite": true}},
		{"shell_set_permissions", map[string]any{"path": "/srv/app/config/app.yaml", "mode": "0600"}, map[string]any{"path": "/srv/app/config/app.yaml", "mode": "0600"}},
		{"shell_git_pull", map[string]any{"repo": "/srv/app/deploy"}, map[string]any{"repo": "/srv/app/deploy"}},
		{"shell_run_command", map[string]any{"command_id": "app-import", "args": []string{tok}, "stdin": "stdin " + tok, "cwd": "/srv/app"},
			map[string]any{"command_id": "app-import", "args_count": 1.0, "cwd": "/srv/app", "stdin_bytes": float64(len("stdin " + tok))}},
	}
	for _, c := range calls {
		if env, _ := h.call(c.tool, c.args); env["ok"] != true {
			t.Fatalf("%s: %v", c.tool, env)
		}
	}
	lines := []map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err == nil && m["msg"] == "tool call" {
			lines = append(lines, m)
		}
	}
	if len(lines) != len(calls) {
		t.Fatalf("%d audit lines, want %d", len(lines), len(calls))
	}
	for i, c := range calls {
		args, _ := lines[i]["args"].(map[string]any)
		if lines[i]["tool"] != c.tool || lines[i]["outcome"] != "ok" {
			t.Fatalf("line %d: %v", i, lines[i])
		}
		for k, v := range c.want {
			if args[k] != v {
				t.Fatalf("%s: audit args %v lack %s=%v", c.tool, args, k, v)
			}
		}
		for _, k := range []string{"content", "stdin", "args", "expected_sha256"} {
			if _, ok := args[k]; ok {
				t.Fatalf("%s: audit args carry %s: %v", c.tool, k, args)
			}
		}
	}
	if strings.Contains(h.logs.String(), tok[7:]) {
		t.Fatal("the log carries content, stdin or an argument")
	}
}

// operatorHarness is readHarness serving the operator profile, where
// shell_run_command is registered at operator.
func operatorHarness(t *testing.T, g *recordingGate) *harness {
	t.Helper()
	tg, c := sshTarget(t, g.exec)
	h := newHarnessWith(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "", func(d *Deps) { d.Principal.Profile = string(ProfileOperator) })
	h.deps.MaxOutputBytes = 4096
	h.deps.MaxTimeout = 60e9 // 60 s
	return h
}
