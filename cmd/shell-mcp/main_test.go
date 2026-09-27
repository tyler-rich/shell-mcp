package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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

func testEnv(t *testing.T) (map[string]string, []byte) {
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
