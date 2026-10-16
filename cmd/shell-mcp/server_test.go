package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// All hosts, names, keys and policy values below are invented test fixtures.

const fakeHello = `{"gate_version":"0.1.0","protocol":1,"principal":"readonly-key","policy_sha256":"ab12","max_tier":"read",` +
	`"ops":["hello","policy"],"sandbox":{"mode":"required","kernel_abi":7,"effective_abi":7,"required_min_abi":4,"applied":true,` +
	`"no_new_privs":true,"enforced":{"fs":true,"net":true,"unix_socket":false,"scope":false},"not_enforced":["unix_socket","scope"],` +
	`"unix_socket_control":"file permissions","tcp_connect_ports":[],"extra_files":["/dev/null","/dev/urandom"],"mptcp":"unavailable"},` +
	`"privileged":{"enabled":false,"max_tier":"read"}}`

const fakePolicy = `{"version":1,"max_tier":"read","sha256":"ab12","sandbox":{"landlock":"required","system_read_exec":[],"tcp_connect_ports":[]},` +
	`"limits":{"DefaultTimeoutS":30,"MaxTimeoutS":300,"MaxOutputBytes":1048576,"MaxStdinBytes":1048576,"MaxReadBytes":1048576,` +
	`"MaxWriteBytes":1048576,"MaxFindResults":1000,"MaxFindDepth":8,"MaxDeleteEntries":1000,"MaxProcesses":2000},` +
	`"paths":{"read":["/srv/app"],"write":[],"deny":[]},"services":{"status":[],"control_units":[],"control_verbs":[]},` +
	`"journal":{"units":[],"max_lines":200},"git":{"repos":[]},"privileged":{"enabled":false,"max_tier":"read"},` +
	`"redact_patterns":0,"commands":[]}`

func fakeGate(_ context.Context, s *sshtest.Session) uint32 {
	req, err := protocol.DecodeRequest(s.Stdin)
	if err != nil {
		return 1
	}
	data := fakeHello
	if req.Op == protocol.OpPolicy {
		data = fakePolicy
	}
	_, _ = fmt.Fprintf(s.Stdout, `{"v":1,"id":%q,"ok":true,"data":%s,"warnings":[],"gate":{"version":"0.1.0","principal":"readonly-key","policy_sha256":"ab12","max_tier":"read","duration_ms":1}}`+"\n", req.ID, data)
	return 0
}

// gateEnv is a valid configuration for one target served by an in-process
// SSH server whose forced command is exec.
func gateEnv(t *testing.T, exec sshtest.Exec) (env map[string]string, hostKey ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	hk := sshtest.Ed25519(t)
	srv := sshtest.Start(t, sshtest.Config{HostKeys: []ssh.Signer{hk}, ClientKeys: []ssh.PublicKey{client.PublicKey()}, Exec: exec})
	host, port, _ := net.SplitHostPort(srv.Addr)
	return map[string]string{
		"SHELL_MCP_TOKEN":               testToken,
		"SHELL_MCP_TARGET_NAME":         "app-host",
		"SHELL_MCP_TARGET_HOST":         host,
		"SHELL_MCP_TARGET_PORT":         port,
		"SHELL_MCP_TARGET_USER":         "svc-shell",
		"SHELL_MCP_TARGET_HOST_KEYS":    sshtest.Pin(hk),
		"SHELL_MCP_SSH_KEY":             string(pem.EncodeToMemory(block)),
		"SHELL_MCP_SSH_CONNECT_TIMEOUT": "2",
	}, hk
}

type checkOut struct {
	OK      bool `json:"ok"`
	Targets []struct {
		Name     string `json:"name"`
		OK       bool   `json:"ok"`
		HostKey  string `json:"host_key_verified"`
		Protocol int    `json:"protocol"`
		Gate     *struct {
			Version      string `json:"version"`
			Protocol     int    `json:"protocol"`
			Principal    string `json:"principal"`
			PolicySHA256 string `json:"policy_sha256"`
			MaxTier      string `json:"max_tier"`
		} `json:"gate"`
		Sandbox *struct {
			Mode         string `json:"mode"`
			KernelABI    int    `json:"kernel_abi"`
			EffectiveABI int    `json:"effective_abi"`
		} `json:"sandbox"`
		Tools []string `json:"tools"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	} `json:"targets"`
}

func runCheck(t *testing.T, env map[string]string) (code int, report checkOut, raw string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(t.Context(), strings.NewReader(""), []string{"check"}, lookup(env), &out, &errb)
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("check output is not JSON: %v\n%s\nstderr: %s", err, out.String(), errb.String())
	}
	return code, report, out.String()
}

func TestCheckReportsEachTarget(t *testing.T) {
	env, hk := gateEnv(t, fakeGate)
	code, c, raw := runCheck(t, env)
	if code != 0 || !c.OK || len(c.Targets) != 1 {
		t.Fatalf("exit %d: %s", code, raw)
	}
	tg := c.Targets[0]
	if !tg.OK || tg.HostKey != sshtest.Pin(hk) || tg.Gate == nil || tg.Gate.Version != "0.1.0" || tg.Gate.Protocol != 1 ||
		tg.Gate.Principal != "readonly-key" || tg.Gate.PolicySHA256 != "ab12" || tg.Gate.MaxTier != "read" ||
		tg.Sandbox == nil || tg.Sandbox.KernelABI != 7 || tg.Sandbox.EffectiveABI != 7 || tg.Sandbox.Mode != "required" {
		t.Fatalf("target report: %s", raw)
	}
	if strings.Join(withoutDiag(tg.Tools), ",") != "shell_get_policy,shell_list_targets" {
		t.Fatalf("effective tools %v", tg.Tools)
	}
	if strings.Contains(raw, testToken) {
		t.Fatal("check printed the token")
	}
}

func TestCheckFailsOnHostKeyMismatch(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	env["SHELL_MCP_TARGET_HOST_KEYS"] = sshtest.Pin(sshtest.Ed25519(t))
	code, c, raw := runCheck(t, env)
	if code == 0 || c.OK || c.Targets[0].OK || c.Targets[0].Error == nil || c.Targets[0].Error.Code != "host_key_mismatch" {
		t.Fatalf("exit %d: %s", code, raw)
	}
}

func TestCheckFailsOnGateRefusal(t *testing.T) {
	env, _ := gateEnv(t, func(_ context.Context, s *sshtest.Session) uint32 {
		_, _ = io.WriteString(s.Stdout, `{"v":1,"id":"","ok":false,"error":{"code":"install_insecure","message":"policy is group-writable"}}`+"\n")
		return 0
	})
	code, c, raw := runCheck(t, env)
	if code == 0 || c.Targets[0].Error == nil || c.Targets[0].Error.Code != "install_insecure" {
		t.Fatalf("exit %d: %s", code, raw)
	}
}

// --- HTTP: the full serve stack -------------------------------------------

type recorder struct {
	mu      sync.Mutex
	headers []http.Header
	token   string
	base    http.RoundTripper
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	res, err := r.base.RoundTrip(req)
	if err == nil {
		r.mu.Lock()
		r.headers = append(r.headers, res.Header.Clone())
		r.mu.Unlock()
	}
	return res, err
}

func httpStack(t *testing.T, env map[string]string) *httptest.Server {
	t.Helper()
	cfg, err := config.Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	srv, cleanup, err := newHTTPServer(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func connect(t *testing.T, ts *httptest.Server, token, version string) (*mcp.ClientSession, *recorder, error) {
	t.Helper()
	rec := &recorder{token: token, base: http.DefaultTransport}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	tr := &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: rec}, DisableStandaloneSSE: true}
	var opts *mcp.ClientSessionOptions
	if version != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: version}
	}
	cs, err := client.Connect(t.Context(), tr, opts)
	if err == nil {
		t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, rec, err
}

func exercise(t *testing.T, cs *mcp.ClientSession) {
	t.Helper()
	lt, err := cs.ListTools(t.Context(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range lt.Tools {
		names = append(names, tool.Name)
	}
	if strings.Join(withoutDiag(names), ",") != "shell_get_policy,shell_list_targets" {
		t.Fatalf("tools %v", names)
	}
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "shell_get_policy", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if res.IsError || !strings.Contains(string(b), `"principal":"readonly-key"`) {
		t.Fatalf("get policy: %s", b)
	}
	res, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "shell_list_targets", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list targets: %v %+v", err, res)
	}
}

func TestHTTP20260728IsStatelessJSON(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	ts := httpStack(t, env)
	cs, rec, err := connect(t, ts, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if v := cs.InitializeResult(); v == nil || v.ProtocolVersion != "2026-07-28" {
		t.Fatalf("negotiated %+v", v)
	}
	exercise(t, cs)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.headers) == 0 {
		t.Fatal("no responses recorded")
	}
	for _, h := range rec.headers {
		if h.Get("Mcp-Session-Id") != "" {
			t.Fatalf("a response carried a session id: %v", h)
		}
		if ct := h.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("response content type %q, want JSON", ct)
		}
	}
}

func TestHTTP20251125ClientsStillServed(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	ts := httpStack(t, env)
	cs, _, err := connect(t, ts, testToken, "2025-11-25")
	if err != nil {
		t.Fatal(err)
	}
	if v := cs.InitializeResult(); v == nil || v.ProtocolVersion != "2025-11-25" {
		t.Fatalf("negotiated %+v", v)
	}
	exercise(t, cs)
}

func TestHTTPClientWithoutTokenRefused(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	ts := httpStack(t, env)
	for _, v := range []string{"", "2025-11-25"} {
		if _, _, err := connect(t, ts, "", v); err == nil {
			t.Fatalf("protocol %q: connected without a token", v)
		}
		if _, _, err := connect(t, ts, "wrong-"+testToken, v); err == nil {
			t.Fatalf("protocol %q: connected with a wrong token", v)
		}
	}
}

// --- stdio ----------------------------------------------------------------

func TestStdioServesWithNoneAuth(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	delete(env, "SHELL_MCP_TOKEN")
	env["SHELL_MCP_AUTH_MODE"] = "none"
	clientIn, serverOut := io.Pipe()
	serverIn, clientOut := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	var errb bytes.Buffer
	go func() {
		done <- run(ctx, serverIn, []string{"serve", "--transport", "stdio"}, lookup(env), serverOut, &errb)
		_ = serverOut.Close()
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(t.Context(), &mcp.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
	if err != nil {
		t.Fatalf("connect: %v (stderr %s)", err, errb.String())
	}
	exercise(t, cs)
	_ = cs.Close()
	_ = clientOut.Close()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit %d: %s", code, errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stdio server did not stop")
	}
}

func TestStdioRefusesBearer(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	var out, errb bytes.Buffer
	code := run(t.Context(), strings.NewReader(""), []string{"serve", "--transport", "stdio"}, lookup(env), &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "stdio") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

// withoutDiag drops the diagnostic build's tool, so these tests hold in
// both builds.
func withoutDiag(names []string) []string {
	out := []string{}
	for _, n := range names {
		if !strings.HasPrefix(n, "shell_diag_") {
			out = append(out, n)
		}
	}
	return out
}
