//go:build linux

package ops_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

// Invented layout and identities; nothing here describes a real host.
type fixture struct {
	t                                    *testing.T
	dir, read, write, secrets, bin, home string
	exe, policyFile, probe               string
	opts                                 ops.Options
	sandboxCalls                         int
}

var groups = map[uint32]string{60123: "svc-shell", 60124: "svc-shell-priv", 101: "systemd-journal", 999: "docker"}

func lookup(gid uint32) (string, error) {
	if n, ok := groups[gid]; ok {
		return n, nil
	}
	return "", fmt.Errorf("unknown gid %d", gid)
}

//nolint:gosec // G101: the remote credential below is invented; the test proves it is redacted
const basePolicy = `version: 1
max_tier: {TIER}
sandbox:
  landlock: best-effort
  system_read_exec: [{BIN}]
limits:
  max_stdin_bytes: 16
paths:
  read: [{R}]
  write: [{W}]
  deny: ["{R}/secrets/**"]
services:
  status: ["example-*.service"]
git:
  repos:
    - path: {R}/deploy
      remote: https://user:not-a-real-token@git.example.test/org/deploy.git
redact:
  patterns: ['api_key=\S+']
{PRIV}commands:
  - id: probe-echo
    path: {BIN}/probe
    tier: read
    description: "Echo arguments"
    templates:
      - ["echo", "{regex:^[A-Za-z0-9 =._-]+$}"]
      - ["echo", "path", "{path:read}"]
      - ["echo", "unit", "{unit}"]
  - id: probe-io
    path: {BIN}/probe
    tier: read
    templates: [["stdin"], ["exit", "{int:0-255}"], ["sleep", "{enum:5s}"], ["pwd"]]
  - id: probe-op
    path: {BIN}/probe
    tier: operator
    templates: [["write", "{path:write}"]]
`

func newFixture(t *testing.T, tier string) *fixture {
	t.Helper()
	d := gatetest.SecureDir(t)
	f := &fixture{t: t, dir: d,
		read: filepath.Join(d, "srv", "app"), write: filepath.Join(d, "srv", "app", "config"),
		secrets: filepath.Join(d, "srv", "app", "secrets"), bin: filepath.Join(d, "bin"), home: filepath.Join(d, "home"),
		exe: filepath.Join(d, "gate", "shell-mcp-gate"), policyFile: filepath.Join(d, "etc", "policy.yaml")}
	for _, p := range []string{f.write, f.secrets, f.bin, f.home, filepath.Join(f.read, "deploy")} {
		gatetest.Mkdir(t, p, 0o755)
	}
	gatetest.WriteFile(t, f.exe, "invented", 0o755)
	gatetest.WriteFile(t, filepath.Join(f.read, "hello.txt"), "hello\nAuthorization: Bearer abc.def\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(f.secrets, "token"), "TOPSECRET", 0o644)
	f.probe = gatetest.BuildProbe(t, f.bin, "probe", "/nonexistent")
	f.writePolicy(tier, "")
	f.opts = ops.Options{
		Version: "test", PolicyPath: f.policyFile, Principal: "readonly-key",
		Identity:    install.Identity{UID: 60123, GIDs: []uint32{60123}, GroupName: lookup},
		Trust:       gatetest.Trust(),
		Executable:  f.exe,
		ServiceHome: f.home,
		ApplySandbox: func(p *policy.Policy) (sandbox.Report, error) {
			f.sandboxCalls++
			return sandbox.Plan(p, 7)
		},
	}
	return f
}

func (f *fixture) writePolicy(tier, priv string) {
	y := strings.NewReplacer("{TIER}", tier, "{PRIV}", priv, "{R}", f.read, "{W}", f.write, "{BIN}", f.bin).Replace(basePolicy)
	gatetest.WriteFile(f.t, f.policyFile, y, 0o644)
}

type response struct {
	V        int             `json:"v"`
	ID       string          `json:"id"`
	OK       bool            `json:"ok"`
	Data     json.RawMessage `json:"data"`
	Warnings []string        `json:"warnings"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Gate *struct {
		Version      string `json:"version"`
		Principal    string `json:"principal"`
		PolicySHA256 string `json:"policy_sha256"`
		MaxTier      string `json:"max_tier"`
	} `json:"gate"`
}

// orderReader records whether the sandbox had been applied when the gate
// first read the request.
type orderReader struct {
	r         io.Reader
	f         *fixture
	readFirst bool
	read      bool
}

func (o *orderReader) Read(p []byte) (int, error) {
	if !o.read {
		o.read = true
		o.readFirst = o.f.sandboxCalls == 0
	}
	return o.r.Read(p)
}

func (f *fixture) serveRaw(in string) (response, *orderReader) {
	f.t.Helper()
	r := &orderReader{r: strings.NewReader(in), f: f}
	var out bytes.Buffer
	if code := ops.Serve(&f.opts, r, &out); code != 0 {
		f.t.Fatalf("exit %d, output %q", code, out.String())
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.HasSuffix(out.String(), "\n") {
		f.t.Fatalf("response is not one line: %q", out.String())
	}
	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		f.t.Fatalf("response %q: %v", out.String(), err)
	}
	return resp, r
}

func (f *fixture) call(op string, args any) response {
	f.t.Helper()
	a, _ := json.Marshal(args)
	resp, _ := f.serveRaw(fmt.Sprintf(`{"v":1,"id":"req-1","op":%q,"args":%s,"timeout_ms":5000}`+"\n", op, a))
	return resp
}

func (f *fixture) ok(op string, args, into any) response {
	f.t.Helper()
	r := f.call(op, args)
	if !r.OK {
		f.t.Fatalf("%s: %+v", op, r.Error)
	}
	if into != nil {
		if err := json.Unmarshal(r.Data, into); err != nil {
			f.t.Fatalf("%s data %s: %v", op, r.Data, err)
		}
	}
	return r
}

func (f *fixture) fail(op string, args any, code string) {
	f.t.Helper()
	r := f.call(op, args)
	if r.OK || r.Error == nil || r.Error.Code != code {
		f.t.Fatalf("%s(%v) = %+v %s, want %s", op, args, r.Error, r.Data, code)
	}
	if r.Error.Message == "" || strings.Contains(r.Error.Message, "\n") {
		f.t.Fatalf("message must be one non-empty line: %q", r.Error.Message)
	}
}

type m = map[string]any

func TestHelloAndGateInfo(t *testing.T) {
	f := newFixture(t, "destructive")
	var hello struct {
		Protocol     int            `json:"protocol"`
		Principal    string         `json:"principal"`
		MaxTier      string         `json:"max_tier"`
		PolicySHA256 string         `json:"policy_sha256"`
		Ops          []string       `json:"ops"`
		Sandbox      sandbox.Report `json:"sandbox"`
		Privileged   struct {
			Enabled bool `json:"enabled"`
		} `json:"privileged"`
	}
	r := f.ok("hello", m{}, &hello)
	if r.V != 1 || r.ID != "req-1" || r.Gate == nil || r.Gate.Version != "test" || r.Gate.Principal != "readonly-key" ||
		r.Gate.MaxTier != "destructive" || len(r.Gate.PolicySHA256) != 64 || r.Warnings == nil {
		t.Fatalf("envelope %+v gate %+v", r, r.Gate)
	}
	if hello.Protocol != 1 || hello.MaxTier != "destructive" || hello.Sandbox.RequiredMinABI != 4 || hello.Privileged.Enabled {
		t.Fatalf("hello %+v", hello)
	}
	for _, op := range []string{"hello", "policy", "read_file", "write_file", "delete", "exec"} {
		if !strings.Contains(strings.Join(hello.Ops, ","), op) {
			t.Fatalf("ops %v lacks %s", hello.Ops, op)
		}
	}
	f.writePolicy("read", "")
	f.ok("hello", m{}, &hello)
	if strings.Contains(strings.Join(hello.Ops, ","), "write_file") {
		t.Fatalf("read-tier gate advertises write_file: %v", hello.Ops)
	}
}

func TestSandboxBeforeRequest(t *testing.T) {
	f := newFixture(t, "read")
	_, rd := f.serveRaw(`{"v":1,"id":"a","op":"hello"}` + "\n")
	if !rd.read || rd.readFirst || f.sandboxCalls != 1 {
		t.Fatalf("request read before the sandbox (read=%v readFirst=%v calls=%d)", rd.read, rd.readFirst, f.sandboxCalls)
	}
	f.opts.ApplySandbox = func(*policy.Policy) (sandbox.Report, error) {
		return sandbox.Report{}, sandbox.ErrUnavailable
	}
	resp, rd := f.serveRaw(`{"v":1,"id":"a","op":"hello"}` + "\n")
	if resp.OK || resp.Error.Code != "sandbox_unavailable" || rd.read {
		t.Fatalf("sandbox failure: %+v read=%v", resp.Error, rd.read)
	}
}

func TestInstallFailuresNeverReadRequest(t *testing.T) {
	cases := map[string]func(f *fixture){
		"root":          func(f *fixture) { f.opts.Identity.UID = 0 },
		"trusted uid":   func(f *fixture) { f.opts.Identity.UID = install.ID(os.Getuid()) },
		"docker group":  func(f *fixture) { f.opts.Identity.GIDs = []uint32{60123, 999} },
		"bad principal": func(f *fixture) { f.opts.Principal = "has space" },
		"ssh command": func(f *fixture) {
			s := "ls"
			f.opts.SSHOriginalCommand = &s
		},
		"insecure policy": func(f *fixture) { _ = os.Chmod(f.policyFile, 0o666) }, //nolint:gosec // G302: deliberately insecure mode under test
		"invalid policy": func(f *fixture) {
			gatetest.WriteFile(f.t, f.policyFile, "version: 1\nmax_tier: read\nsudo: true\n", 0o644)
		},
		"missing policy": func(f *fixture) { f.opts.PolicyPath = filepath.Join(f.dir, "missing.yaml") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "read")
			mutate(f)
			resp, rd := f.serveRaw(`{"v":1,"id":"a","op":"hello"}` + "\n")
			if resp.OK || resp.Error.Code != "install_insecure" || rd.read || f.sandboxCalls != 0 {
				t.Fatalf("%+v read=%v sandbox=%d", resp.Error, rd.read, f.sandboxCalls)
			}
			if strings.Contains(resp.Error.Message, f.dir) {
				t.Fatalf("wire message names a local path: %q", resp.Error.Message)
			}
		})
	}
	// The helper socket group and systemd-journal are allowed.
	f := newFixture(t, "read")
	f.opts.Identity.GIDs = []uint32{60123, 60124, 101}
	f.ok("hello", m{}, nil)
}

func TestDecodeErrors(t *testing.T) {
	f := newFixture(t, "read")
	for in, code := range map[string]string{
		`{"v":1,"id":"a","op":"hello","op":"write_file"}` + "\n":            "bad_request",
		`{"v":1,"id":"a","op":"hello","x":1}` + "\n":                        "bad_request",
		`{"v":2,"id":"a","op":"hello"}` + "\n":                              "protocol_mismatch",
		`{"v":1,"id":"a","op":"hello"} {}` + "\n":                           "bad_request",
		`{"v":1,"id":"a","op":"hello","args":{"x":1}}` + "\n":               "bad_request",
		`{"v":1,"id":"a","op":"hello"}` + strings.Repeat(" ", 2<<20) + "\n": "too_large",
	} {
		resp, _ := f.serveRaw(in)
		if resp.OK || resp.Error.Code != code {
			t.Fatalf("%.60q: %+v, want %s", in, resp.Error, code)
		}
	}
}

func TestTiersAndUnknownOps(t *testing.T) {
	f := newFixture(t, "read")
	f.fail("write_file", m{"path": filepath.Join(f.write, "x"), "content_b64": ""}, "tier_denied")
	f.fail("delete", m{"path": filepath.Join(f.write, "x")}, "tier_denied")
	f.fail("mkdir", m{"path": filepath.Join(f.write, "x")}, "tier_denied")
	// The tier check comes before argument validation.
	f.fail("write_file", m{"bogus": true}, "tier_denied")
	f.fail("exec", m{"command_id": "probe-op", "args": []string{"write", filepath.Join(f.write, "x")}}, "tier_denied")
	f.fail("service_control", m{}, "tier_denied")
	for _, op := range []string{
		"git_status", "git_log", "git_diff", "git_pull", "git_discard", "git_discard_preview", "made_up"} {
		f.fail(op, m{}, "unknown_op")
	}
	f.fail("delete_preview", m{"path": f.write}, "path_denied") // read tier passes; fsx refuses a root
}

func TestPrivileged(t *testing.T) {
	f := newFixture(t, "operator")
	f.fail("priv_read_file", m{"path": "/etc/example-app/x"}, "privileged_disabled")
	f.writePolicy("operator", "privileged:\n  enabled: true\n  socket: /run/shell-mcp/privd.sock\n  max_tier: read\n")
	f.fail("priv_write_file", m{}, "tier_denied")
	f.fail("priv_delete", m{}, "tier_denied")
	f.fail("priv_read_file", m{"path": "/etc/example-app/x"}, "unknown_op")
	f.fail("priv_not_an_op", m{}, "unknown_op")
}

func TestFileOps(t *testing.T) {
	f := newFixture(t, "destructive")
	var rd struct {
		Content string `json:"content"`
		SHA256  string `json:"sha256"`
	}
	f.ok("read_file", m{"path": filepath.Join(f.read, "hello.txt")}, &rd)
	if strings.Contains(rd.Content, "abc.def") || !strings.Contains(rd.Content, "[REDACTED]") {
		t.Fatalf("content not redacted: %q", rd.Content)
	}
	f.fail("read_file", m{"path": filepath.Join(f.secrets, "token")}, "path_denied")
	f.fail("read_file", m{"path": f.read + "/../x"}, "bad_request")
	f.fail("read_file", m{"path": filepath.Join(f.read, "hello.txt"), "extra": 1}, "bad_request")

	target := filepath.Join(f.write, "new.txt")
	var wr struct {
		SHA256   string `json:"sha256"`
		Verified bool   `json:"verified"`
		Created  bool   `json:"created"`
	}
	f.ok("write_file", m{"path": target, "content_b64": base64.StdEncoding.EncodeToString([]byte("v1\n"))}, &wr)
	if !wr.Verified || !wr.Created {
		t.Fatalf("write %+v", wr)
	}
	f.fail("write_file", m{"path": target, "content_b64": "!!!"}, "bad_request")
	f.fail("write_file", m{"path": target, "content_b64": "", "mode": "4755"}, "policy_denied")
	f.fail("write_file", m{"path": target, "content_b64": "", "mode": "0646"}, "policy_denied")
	f.fail("write_file", m{"path": target, "content_b64": "", "create": false, "expected_sha256": strings.Repeat("0", 64)}, "exists")
	f.fail("write_file", m{"path": filepath.Join(f.read, "x"), "content_b64": ""}, "path_denied")
	f.ok("write_file", m{"path": target, "content_b64": base64.StdEncoding.EncodeToString([]byte("v2\n")), "expected_sha256": wr.SHA256}, nil)
	f.ok("mkdir", m{"path": filepath.Join(f.write, "d1", "d2"), "parents": true}, nil)
	f.ok("copy", m{"source": target, "destination": filepath.Join(f.write, "d1", "copy.txt")}, nil)
	f.ok("move", m{"source": filepath.Join(f.write, "d1", "copy.txt"), "destination": filepath.Join(f.write, "moved.txt")}, nil)
	f.ok("chmod", m{"path": filepath.Join(f.write, "moved.txt"), "mode": "0600"}, nil)
	f.fail("chmod", m{"path": filepath.Join(f.write, "moved.txt")}, "bad_request")
	var pv struct {
		Entries int  `json:"entries"`
		Deleted bool `json:"deleted"`
	}
	f.ok("delete_preview", m{"path": filepath.Join(f.write, "d1"), "recursive": true}, &pv)
	if pv.Entries != 2 || pv.Deleted {
		t.Fatalf("preview %+v", pv)
	}
	f.ok("delete", m{"path": filepath.Join(f.write, "d1"), "recursive": true}, &pv)
	if !pv.Deleted {
		t.Fatalf("delete %+v", pv)
	}
	var ls struct {
		Entries []struct{ Name string } `json:"entries"`
	}
	f.ok("list_dir", m{"path": f.read}, &ls)
	for _, e := range ls.Entries {
		if e.Name == "secrets" {
			t.Fatal("denied entry listed")
		}
	}
	f.ok("stat", m{"path": target}, nil)
	f.ok("find", m{"path": f.read, "name_glob": "*.txt"}, nil)
}

func TestReadBackFault(t *testing.T) {
	f := newFixture(t, "operator")
	f.opts.InjectReadBackFault = func(b []byte) []byte { return append(bytes.Clone(b), '!') }
	f.fail("write_file", m{"path": filepath.Join(f.write, "v.txt"), "content_b64": base64.StdEncoding.EncodeToString([]byte("x"))}, "verify_failed")
}

type execData struct {
	ExitCode        *int     `json:"exit_code"`
	Signal          *string  `json:"signal"`
	TimedOut        bool     `json:"timed_out"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	Argv            []string `json:"argv"`
}

func TestExec(t *testing.T) {
	f := newFixture(t, "operator")
	var d execData
	f.ok("exec", m{"command_id": "probe-echo", "args": []string{"echo", "hello world"}}, &d)
	if d.Stdout != "hello world\n" || d.ExitCode == nil || *d.ExitCode != 0 || d.Signal != nil || d.Argv[0] != f.probe {
		t.Fatalf("echo %+v", d)
	}
	f.ok("exec", m{"command_id": "probe-echo", "args": []string{"echo", "api_key=abc123 Bearer tok.en"}}, &d)
	if strings.Contains(d.Stdout, "abc123") || strings.Contains(d.Stdout, "tok.en") {
		t.Fatalf("output not redacted: %q", d.Stdout)
	}
	f.ok("exec", m{"command_id": "probe-echo", "args": []string{"echo", "path", filepath.Join(f.read, "hello.txt")}}, &d)
	f.ok("exec", m{"command_id": "probe-echo", "args": []string{"echo", "unit", "example-app.service"}}, &d)
	f.fail("exec", m{"command_id": "probe-echo", "args": []string{"echo", "unit", "other.service"}}, "template_mismatch")
	f.fail("exec", m{"command_id": "probe-echo", "args": []string{"echo", "path", filepath.Join(f.secrets, "token")}}, "path_denied")
	f.fail("exec", m{"command_id": "probe-echo", "args": []string{"echo", "-rf"}}, "template_mismatch")
	f.fail("exec", m{"command_id": "probe-echo", "args": []string{"echo"}}, "template_mismatch")
	f.fail("exec", m{"command_id": "probe-echo", "args": []string{"echo", "a;b"}}, "template_mismatch")
	f.fail("exec", m{"command_id": "not-declared", "args": []string{}}, "policy_denied")
	var e2 execData
	f.ok("exec", m{"command_id": "probe-io", "args": []string{"exit", "7"}}, &e2)
	if e2.ExitCode == nil || *e2.ExitCode != 7 {
		t.Fatalf("non-zero exit must be data: %+v", e2)
	}
	f.ok("exec", m{"command_id": "probe-io", "args": []string{"stdin"}, "stdin_b64": base64.StdEncoding.EncodeToString([]byte("ping"))}, &e2)
	if e2.Stdout != "ping" {
		t.Fatalf("stdin %+v", e2)
	}
	f.fail("exec", m{"command_id": "probe-io", "args": []string{"stdin"}, "stdin_b64": base64.StdEncoding.EncodeToString(make([]byte, 17))}, "too_large")
	f.ok("exec", m{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": f.write}, &e2)
	if strings.TrimSpace(e2.Stdout) != f.write {
		t.Fatalf("cwd %+v", e2)
	}
	f.fail("exec", m{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": f.secrets}, "path_denied")
	f.ok("exec", m{"command_id": "probe-op", "args": []string{"write", filepath.Join(f.write, "from-probe")}}, &e2)
	f.fail("exec", m{"command_id": "probe-op", "args": []string{"write", filepath.Join(f.read, "x")}}, "path_denied")
}

func TestExecTimeout(t *testing.T) {
	f := newFixture(t, "read")
	resp, _ := f.serveRaw(`{"v":1,"id":"a","op":"exec","args":{"command_id":"probe-io","args":["sleep","5s"]},"timeout_ms":300}` + "\n")
	var d execData
	if !resp.OK || json.Unmarshal(resp.Data, &d) != nil || !d.TimedOut || d.Signal == nil {
		t.Fatalf("timeout %+v %s", resp.Error, resp.Data)
	}
}

func TestPolicySummary(t *testing.T) {
	f := newFixture(t, "read")
	var s struct {
		MaxTier  string `json:"max_tier"`
		Commands []struct {
			ID        string     `json:"id"`
			Tier      string     `json:"tier"`
			Templates [][]string `json:"templates"`
			Path      string     `json:"path"`
		} `json:"commands"`
		Git struct {
			Repos []struct {
				Remote string `json:"remote"`
			} `json:"repos"`
		} `json:"git"`
		Paths struct {
			Read []string `json:"read"`
			Deny []string `json:"deny"`
		} `json:"paths"`
	}
	r := f.ok("policy", m{}, &s)
	if s.MaxTier != "read" || len(s.Commands) != 3 || s.Commands[0].ID != "probe-echo" || len(s.Commands[0].Templates) != 3 {
		t.Fatalf("summary %s", r.Data)
	}
	if strings.Contains(string(r.Data), "not-a-real-token") || strings.Contains(string(r.Data), "sudo") {
		t.Fatalf("summary leaks: %s", r.Data)
	}
	if strings.Contains(string(r.Data), "version: 1") {
		t.Fatal("summary must not be the raw file")
	}
	if len(s.Paths.Read) != 1 {
		t.Fatalf("paths %+v", s.Paths)
	}
}
