package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/transport"
)

// All values below are invented test fixtures.

func TestHealthcheckExitCodes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"ok", http.StatusOK, `{"status":"ok"}`, 0},
		{"wrong body", http.StatusOK, `{"status":"degraded"}`, 1},
		{"body with trailing newline", http.StatusOK, "{\"status\":\"ok\"}\n", 1},
		{"body with prefix", http.StatusOK, `xx{"status":"ok"}`, 1},
		{"server error", http.StatusInternalServerError, `{"status":"ok"}`, 1},
		{"redirect", http.StatusFound, `{"status":"ok"}`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" || r.Method != http.MethodGet {
					http.NotFound(w, r)
					return
				}
				if c.status == http.StatusFound {
					w.Header().Set("Location", "/healthz-elsewhere")
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			if got := healthcheck(context.Background(), srv.URL+"/healthz"); got != c.want {
				t.Fatalf("healthcheck = %d, want %d", got, c.want)
			}
		})
	}
}

func TestHealthcheckUnreachable(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if got := healthcheck(context.Background(), "http://"+addr+"/healthz"); got != 1 {
		t.Fatalf("healthcheck on closed port = %d, want 1", got)
	}
}

func TestHealthcheckURLFromPort(t *testing.T) {
	cases := map[string]string{
		"":      "http://127.0.0.1:8080/healthz",
		"9090":  "http://127.0.0.1:9090/healthz",
		"x":     "",
		"70000": "",
	}
	for port, want := range cases {
		env := map[string]string{}
		if port != "" {
			env["SHELL_MCP_PORT"] = port
		}
		got, err := healthcheckURL(lookup(env))
		if want == "" {
			if err == nil {
				t.Fatalf("port %q accepted", port)
			}
			continue
		}
		if err != nil || got != want {
			t.Fatalf("port %q: got %q, %v", port, got, err)
		}
	}
}

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

const testToken = "tok-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH"

func testEnv(t *testing.T) (env map[string]string, seed []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"SHELL_MCP_TOKEN":            testToken,
		"SHELL_MCP_TARGET_NAME":      "app-host",
		"SHELL_MCP_TARGET_HOST":      "target-a.example.test",
		"SHELL_MCP_TARGET_USER":      "svc-shell",
		"SHELL_MCP_TARGET_HOST_KEYS": "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		"SHELL_MCP_SSH_KEY":          string(pem.EncodeToMemory(block)),
	}, priv.Seed()
}

func TestCheckMasksSecrets(t *testing.T) {
	env, seed := testEnv(t)
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"check"}, lookup(env), &out, &errb); code != 0 {
		t.Fatalf("check exit %d, stderr %q", code, errb.String())
	}
	all := out.String() + errb.String()
	pemBody := strings.Split(env["SHELL_MCP_SSH_KEY"], "\n")[1]
	for _, s := range []string{testToken, pemBody, string(seed), base64.StdEncoding.EncodeToString(seed)} {
		if strings.Contains(all, s) {
			t.Fatalf("check output contains secret material %q", s)
		}
	}
	if !strings.Contains(out.String(), `"token_length": 48`) || !strings.Contains(out.String(), `"SHA256:`) {
		t.Fatalf("check output lacks masked token / fingerprint:\n%s", out.String())
	}
}

func TestCheckInvalidConfigExits1(t *testing.T) {
	env, _ := testEnv(t)
	env["SHELL_MCP_TOKEN"] = "short"
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"check"}, lookup(env), &out, &errb); code != 1 {
		t.Fatalf("check exit %d, want 1", code)
	}
	if strings.Contains(errb.String(), "short") || !strings.Contains(errb.String(), "SHELL_MCP_TOKEN must be at least 43 characters") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestServeRefusesBearer(t *testing.T) {
	env, _ := testEnv(t)
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"serve"}, lookup(env), &out, &errb); code != 1 {
		t.Fatalf("serve exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "bearer auth arrives in Session 2") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestToolsPrintsEmptyList(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"tools"}, lookup(nil), &out, &errb); code != 0 {
		t.Fatalf("tools exit %d", code)
	}
	if out.String() != "[]\n" {
		t.Fatalf("tools output = %q", out.String())
	}
}

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"version"}, lookup(nil), &out, &errb); code != 0 {
		t.Fatalf("version exit %d", code)
	}
	if !strings.Contains(out.String(), "shell-mcp dev") || !strings.Contains(out.String(), "go1.") {
		t.Fatalf("version output = %q", out.String())
	}
}

func TestUnknownSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"shell"}, lookup(nil), &out, &errb); code != 2 {
		t.Fatalf("unknown subcommand exit %d, want 2", code)
	}
}

func TestMCPStatelessServesNoTools(t *testing.T) {
	env, _ := testEnv(t)
	delete(env, "SHELL_MCP_TOKEN")
	env["SHELL_MCP_AUTH_MODE"] = "none"
	env["SHELL_MCP_ALLOW_UNAUTHENTICATED"] = "true"
	cfg, err := config.Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newMCPServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := transport.New(cfg, mcpHTTPHandler(server, slog.New(slog.DiscardHandler)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// Raw request: stateless JSON response, no session header.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") ||
		res.Header.Get("Mcp-Session-Id") != "" || !strings.Contains(string(body), `"tools":[]`) {
		t.Fatalf("status %d, headers %v, body %s", res.StatusCode, res.Header, body)
	}

	// SDK client at its latest protocol revision.
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	lt, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lt.Tools) != 0 {
		t.Fatalf("tools = %v", lt.Tools)
	}
	if v := cs.InitializeResult(); v == nil || v.ProtocolVersion != "2026-07-28" {
		t.Fatalf("negotiated protocol: %+v", v)
	}
}
