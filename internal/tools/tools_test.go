package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// All hosts, names, keys and policy values below are invented test fixtures.

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t    *testing.T
	deps *Deps
	logs *syncBuffer
	cs   *mcp.ClientSession
}

// sshTarget starts a test SSH server with exec as its forced command and
// returns the target and its client.
func sshTarget(t *testing.T, exec sshtest.Exec) (config.Target, *sshx.Client) {
	t.Helper()
	hk, ck := sshtest.Ed25519(t), sshtest.Ed25519(t)
	srv := sshtest.Start(t, sshtest.Config{HostKeys: []ssh.Signer{hk}, ClientKeys: []ssh.PublicKey{ck.PublicKey()}, Exec: exec})
	host, portStr, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(portStr)
	p, _ := config.ParseHostKeyPin(sshtest.Pin(hk))
	tg := config.Target{Name: "app-host", Host: host, Port: port, User: "svc-shell", HostKeys: []config.HostKey{p}, Key: config.PrivateKeyFromSigner(ck)}
	c, err := sshx.New(&tg, sshx.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return tg, c
}

// newHarness serves the catalogue for the admin profile over in-memory
// transports to an SDK client.
func newHarness(t *testing.T, targets []config.Target, clients map[string]*sshx.Client, defaultTarget string) *harness {
	t.Helper()
	return newHarnessWith(t, targets, clients, defaultTarget, nil)
}

// newHarnessWith is newHarness with the Deps adjusted by mod before the
// catalogue is built (schemas depend on the approval settings).
func newHarnessWith(t *testing.T, targets []config.Target, clients map[string]*sshx.Client, defaultTarget string, mod func(*Deps)) *harness {
	t.Helper()
	logs := &syncBuffer{}
	d := &Deps{
		Targets: targets, DefaultTarget: defaultTarget,
		Opener: func(name string) (gateclient.Opener, bool) {
			c, ok := clients[name]
			return c, ok
		},
		Gate:           gateclient.New(gateclient.Options{}),
		Principal:      auth.Principal{Name: auth.PrincipalBearer, Profile: "admin"},
		Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
		DefaultTimeout: 10 * time.Second,
	}
	if mod != nil {
		mod(d)
	}
	reg, err := Catalogue(d)
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "shell-mcp", Version: "test"}, nil)
	for _, r := range reg.ToolsForProfile(Profile(d.Principal.Profile), nil) {
		r.Tool.Install(server)
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
	return &harness{t: t, deps: d, logs: logs, cs: cs}
}

// call calls a tool and returns the envelope (structuredContent) and the
// result.
func (h *harness) call(name string, args any) (map[string]any, *mcp.CallToolResult) {
	h.t.Helper()
	res, err := h.cs.CallTool(h.t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.t.Fatalf("CallTool %s: %v", name, err)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		h.t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		h.t.Fatalf("structuredContent is not an object: %s", raw)
	}
	if len(res.Content) != 1 {
		h.t.Fatalf("content = %v", res.Content)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		h.t.Fatalf("content is %T", res.Content[0])
	}
	// The text block is a one-line summary, then the same envelope JSON.
	summary, body, ok := strings.Cut(text.Text, "\n")
	var fromText map[string]any
	if !ok || summary == "" || strings.HasPrefix(summary, "{") {
		h.t.Fatalf("text content does not start with a summary line: %q", text.Text)
	}
	if err := json.Unmarshal([]byte(body), &fromText); err != nil || fmt.Sprint(fromText) != fmt.Sprint(env) {
		h.t.Fatalf("text content after the summary is not the envelope: %q", text.Text)
	}
	if res.IsError == (env["ok"] == true) {
		h.t.Fatalf("isError %v but ok %v", res.IsError, env["ok"])
	}
	return env, res
}

func errCode(env map[string]any) string {
	e, _ := env["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

var testFP = "SHA256:" + strings.Repeat("A", 43)

func fakeTargets() []config.Target {
	return []config.Target{
		{Name: "app-host", Host: "target-a.example.test", Port: 22, User: "svc-shell", HostKeys: []config.HostKey{{Type: "ssh-ed25519", Fingerprint: testFP}}},
		{Name: "db-host", Host: "192.0.2.20", Port: 2222, User: "svc-shell", HostKeys: []config.HostKey{{Type: "ssh-ed25519", Fingerprint: testFP}}},
	}
}

func TestEveryToolFollowsConventions(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	regs := reg.ToolsForProfile(ProfileAdmin, nil)
	names := map[string]bool{}
	for _, r := range regs {
		names[r.Tool.Def.Name] = true
	}
	for _, want := range []string{"shell_list_targets", "shell_get_policy"} {
		if !names[want] {
			t.Fatalf("%s is not registered (have %v)", want, names)
		}
	}
	host := regexp.MustCompile(`(?i)\b[a-z0-9-]+\.(example|test|local|lan|internal|com|net|org)\b|\b\d{1,3}(\.\d{1,3}){3}\b|/[a-z]+/`)
	for _, r := range regs {
		def := r.Tool.Def
		t.Run(def.Name, func(t *testing.T) {
			if def.Title == "" || def.Annotations == nil || def.Annotations.Title != def.Title {
				t.Fatalf("title %q annotations %+v", def.Title, def.Annotations)
			}
			d := def.Description
			if d == "" || len(d) > 300 || strings.Count(d, ". ") > 1 || strings.Contains(strings.ToUpper(d), "IMPORTANT") ||
				strings.Contains(d, "shell_") || host.MatchString(d) {
				t.Fatalf("description breaks the conventions: %q", d)
			}
			a := def.Annotations
			// The one read-tier tool that changes the host (TOOLS.md, power):
			// never gated, not read-only, not destructive.
			if def.Name == "shell_priv_cancel_power" {
				if a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint {
					t.Fatalf("cancel annotations: %+v", a)
				}
			} else if r.Tier == TierRead && (!a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint || a.OpenWorldHint == nil || !*a.OpenWorldHint) {
				t.Fatalf("read-tier annotations: %+v", a)
			}
			in, ok := def.InputSchema.(*jsonschema.Schema)
			if !ok || in.Type != "object" || in.AdditionalProperties == nil || in.AdditionalProperties.Not == nil {
				t.Fatalf("input schema must be a closed object: %#v", def.InputSchema)
			}
			if slices.Contains(in.Required, "target") {
				t.Fatalf("target must be optional: required %v", in.Required)
			}
			for p, s := range in.Properties {
				if s.Description == "" {
					t.Fatalf("input property %q has no description", p)
				}
				if s.Type == "string" && (s.MaxLength == nil || s.Pattern == "") {
					t.Fatalf("input property %q has no bounds", p)
				}
			}
			if _, ok := def.OutputSchema.(*jsonschema.Schema); !ok {
				t.Fatalf("no output schema")
			}
		})
	}
}

func TestListTargets(t *testing.T) {
	// Nothing is probed: no opener exists.
	h := newHarness(t, fakeTargets(), nil, "")
	env, _ := h.call("shell_list_targets", map[string]any{})
	data, _ := env["data"].(map[string]any)
	got, _ := json.Marshal(data["targets"])
	want := `[{"host":"target-a.example.test","name":"app-host","port":22,"user":"svc-shell"},{"host":"192.0.2.20","name":"db-host","port":2222,"user":"svc-shell"}]`
	if env["ok"] != true || string(got) != want {
		t.Fatalf("envelope %v (targets %s)", env, got)
	}
	if env["target"] != "" {
		t.Fatalf("target = %v", env["target"])
	}
	// Unknown arguments are a validation error, as an envelope.
	env, _ = h.call("shell_list_targets", map[string]any{"verbose": true})
	if errCode(env) != "validation_error" {
		t.Fatalf("unknown argument: %v", env)
	}
}

// fakeGate answers hello and policy with fixed data.
func fakeGate(hello, policy string) sshtest.Exec {
	return func(_ context.Context, s *sshtest.Session) uint32 {
		req, err := protocol.DecodeRequest(s.Stdin)
		if err != nil {
			return 1
		}
		data := hello
		if req.Op == protocol.OpPolicy {
			data = policy
		}
		var one bytes.Buffer // the response is one line
		if err := json.Compact(&one, []byte(data)); err != nil {
			return 1
		}
		_, _ = fmt.Fprintf(s.Stdout, `{"v":2,"id":%q,"ok":true,"data":%s,"warnings":[],"gate":{"version":"0.1.0","principal":"readonly-key","policy_sha256":"ab12","max_tier":"read","duration_ms":2}}`+"\n", req.ID, one.String())
		return 0
	}
}

const fakeHello = `{"gate_version":"0.1.0","protocol":1,"principal":"readonly-key","policy_sha256":"ab12","max_tier":"read",
"ops":["hello","policy","read_file"],"sandbox":{"mode":"required","kernel_abi":7,"effective_abi":7,"required_min_abi":4,"applied":true,
"no_new_privs":true,"enforced":{"fs":true,"net":true,"unix_socket":false,"scope":false},"not_enforced":["unix_socket","scope"],
"unix_socket_control":"file permissions","tcp_connect_ports":[],"extra_files":["/dev/null","/dev/urandom"],"mptcp":"unavailable (seccomp)"},
"privileged":{"enabled":false,"max_tier":"read"}}`

const fakePolicy = `{"version":1,"max_tier":"read","sha256":"ab12","sandbox":{"landlock":"required","system_read_exec":[],"tcp_connect_ports":[]},
"limits":{"DefaultTimeoutS":30,"MaxTimeoutS":300,"MaxOutputBytes":1048576,"MaxStdinBytes":1048576,"MaxReadBytes":1048576,"MaxWriteBytes":1048576,
"MaxFindResults":1000,"MaxFindDepth":8,"MaxDeleteEntries":1000,"MaxProcesses":2000,"MaxMemoryMB":1024},
"paths":{"read":["/srv/app"],"write":[],"deny":[]},"services":{"status":["example-*.service"],"control_units":[],"control_verbs":[]},
"journal":{"units":["example-app.service"],"max_lines":200},"git":{"repos":[{"path":"/srv/app","remote":"https://git.example.test/app.git"}]},
"privileged":{"enabled":false,"max_tier":"read"},"redact_patterns":0,
"commands":[{"id":"app-version","description":"Show the version","tier":"read","root_equivalent":false,"templates":[["--version"]]}]}`

func TestGetPolicy(t *testing.T) {
	tg, c := sshTarget(t, fakeGate(fakeHello, fakePolicy))
	h := newHarness(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "")
	env, _ := h.call("shell_get_policy", map[string]any{}) // one target: target is optional
	if env["ok"] != true || env["target"] != "app-host" {
		t.Fatalf("envelope %v", env)
	}
	b, _ := json.Marshal(env["data"])
	for _, want := range []string{
		`"gate":{"max_tier":"read","ops":["hello","policy","read_file"],"policy_sha256":"ab12","principal":"readonly-key","protocol":1,"version":"0.1.0"}`,
		`"kernel_abi":7`, `"effective_abi":7`, `"mode":"required"`, `"not_enforced":["unix_socket","scope"]`,
		`"privileged":{"enabled":false,"max_tier":"read"}`,
		`"limits":{"default_timeout_s":30,"max_delete_entries":1000,"max_find_depth":8,"max_find_results":1000,"max_memory_mb":1024,"max_output_bytes":1048576,"max_processes":2000,"max_read_bytes":1048576,"max_stdin_bytes":1048576,"max_timeout_s":300,"max_write_bytes":1048576}`,
		`"paths":{"deny":[],"read":["/srv/app"],"write":[]}`,
		`"repos":[{"path":"/srv/app","remote":"https://git.example.test/app.git"}]`,
		`"commands":[{"description":"Show the version","id":"app-version","root_equivalent":false,"templates":[["--version"]],"tier":"read"}]`,
	} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("data lacks %s:\n%s", want, b)
		}
	}
	gate, _ := env["gate"].(map[string]any)
	if gate["principal"] != "readonly-key" || gate["policy_sha256"] != "ab12" {
		t.Fatalf("gate block %v", env["gate"])
	}
}

func TestGetPolicyGateRefusalPassesThrough(t *testing.T) {
	tg, c := sshTarget(t, func(_ context.Context, s *sshtest.Session) uint32 {
		_, _ = io.WriteString(s.Stdout, `{"v":2,"id":"","ok":false,"error":{"code":"sandbox_unavailable","message":"Landlock is unavailable"}}`+"\n")
		return 0
	})
	h := newHarness(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "")
	env, res := h.call("shell_get_policy", map[string]any{"target": "app-host"})
	if errCode(env) != "sandbox_unavailable" || !res.IsError {
		t.Fatalf("envelope %v", env)
	}
	if strings.Contains(fmt.Sprint(env), "data") {
		t.Fatalf("a failure carries data: %v", env)
	}
}

func TestTargetResolution(t *testing.T) {
	two := fakeTargets()
	h := newHarness(t, two, nil, "")
	for name, c := range map[string]struct {
		args map[string]any
		code string
	}{
		"several targets, none named":  {map[string]any{}, "validation_error"},
		"unknown target":               {map[string]any{"target": "other-host"}, "unknown_target"},
		"malformed name":               {map[string]any{"target": "../etc"}, "validation_error"},
		"wrong type":                   {map[string]any{"target": 7}, "validation_error"},
		"unknown argument":             {map[string]any{"target": "app-host", "x": 1}, "validation_error"},
		"no SSH client for the target": {map[string]any{"target": "app-host"}, "target_unreachable"},
	} {
		t.Run(name, func(t *testing.T) {
			h.t = t
			env, _ := h.call("shell_get_policy", c.args)
			if errCode(env) != c.code {
				t.Fatalf("envelope %v, want %s", env, c.code)
			}
		})
	}
	// A default target makes target optional.
	h = newHarness(t, two, nil, "db-host")
	env, _ := h.call("shell_get_policy", map[string]any{})
	if env["target"] != "db-host" {
		t.Fatalf("default target not used: %v", env)
	}
}

func TestAuditLine(t *testing.T) {
	tg, c := sshTarget(t, fakeGate(fakeHello, fakePolicy))
	h := newHarness(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "")
	h.call("shell_get_policy", map[string]any{"target": "app-host"})
	h.call("shell_get_policy", map[string]any{"target": "missing-host"})
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == "tool call" {
			lines = append(lines, m)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("%d audit lines, want 2: %s", len(lines), h.logs.String())
	}
	a := lines[0]
	args, _ := a["args"].(map[string]any)
	if a["tool"] != "shell_get_policy" || a["principal"] != auth.PrincipalBearer || a["target"] != "app-host" ||
		a["outcome"] != "ok" || args["target"] != "app-host" || a["time"] == nil {
		t.Fatalf("audit line %v", a)
	}
	if _, ok := a["duration_ms"].(float64); !ok {
		t.Fatalf("no duration: %v", a)
	}
	if lines[1]["outcome"] != "unknown_target" {
		t.Fatalf("failed call's outcome: %v", lines[1])
	}
	// Tool output never reaches the log.
	for _, s := range []string{"/srv/app", "app-version", "example-app.service", "git.example.test"} {
		if strings.Contains(h.logs.String(), s) {
			t.Fatalf("log contains tool output %q", s)
		}
	}
}
