//go:build shellmcp_diag

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The diagnostic build's tool: what it reports for each client shape.

type diagOut struct {
	Round               int    `json:"round"`
	ProtocolVersion     string `json:"protocol_version"`
	ElicitationDeclared bool   `json:"elicitation_declared"`
	FormDeclared        bool   `json:"form_declared"`
	Action              string `json:"action"`
	Answer              *bool  `json:"answer"`
	RequestStateEchoed  bool   `json:"request_state_echoed"`
}

func callDiag(t *testing.T, cs *mcp.ClientSession) diagOut {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "shell_diag_elicit", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("diag failed: %+v", res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var env struct {
		OK   bool    `json:"ok"`
		Data diagOut `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil || !env.OK {
		t.Fatalf("envelope %s", b)
	}
	return env.Data
}

func answering(action string, answer bool) func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		if !strings.Contains(req.Params.Message, "Nothing runs") {
			return nil, io.ErrUnexpectedEOF
		}
		r := &mcp.ElicitResult{Action: action}
		if action == "accept" {
			r.Content = map[string]any{"answer": answer}
		}
		return r, nil
	}
}

func diagSession(t *testing.T, ts, version string, handler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
	t.Helper()
	rec := &recorder{token: testToken, base: http.DefaultTransport}
	client := mcp.NewClient(&mcp.Implementation{Name: "diag-test", Version: "0"}, &mcp.ClientOptions{ElicitationHandler: handler})
	var opts *mcp.ClientSessionOptions
	if version != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: version}
	}
	cs, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: ts + "/mcp", HTTPClient: &http.Client{Transport: rec}, DisableStandaloneSSE: true}, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestDiagElicitHTTP20260728(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	ts := httpStack(t, env)
	d := callDiag(t, diagSession(t, ts.URL, "", answering("accept", true)))
	if d.Round != 2 || d.ProtocolVersion != "2026-07-28" || !d.ElicitationDeclared || d.Action != "accept" || d.Answer == nil || !*d.Answer || !d.RequestStateEchoed {
		t.Fatalf("accept: %+v", d)
	}
	d = callDiag(t, diagSession(t, ts.URL, "", answering("decline", false)))
	if d.Round != 2 || d.Action != "decline" || d.Answer != nil {
		t.Fatalf("decline: %+v", d)
	}
	// A client without elicitation is told so, and nothing is asked.
	d = callDiag(t, diagSession(t, ts.URL, "", nil))
	if d.Round != 1 || d.ElicitationDeclared || d.Action != "" {
		t.Fatalf("no elicitation: %+v", d)
	}
}

func TestDiagElicitHTTP20251125(t *testing.T) {
	// Stateless HTTP synthesizes the session for a 2025-11-25 request and
	// cannot carry a server-to-client request: no elicitation reaches it.
	env, _ := gateEnv(t, fakeGate)
	ts := httpStack(t, env)
	d := callDiag(t, diagSession(t, ts.URL, "2025-11-25", answering("accept", true)))
	if d.Round != 1 || d.ProtocolVersion != "2025-11-25" || d.ElicitationDeclared {
		t.Fatalf("2025-11-25 over HTTP: %+v", d)
	}
}

func TestDiagElicitStdio(t *testing.T) {
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
	client := mcp.NewClient(&mcp.Implementation{Name: "diag-test", Version: "0"}, &mcp.ClientOptions{ElicitationHandler: answering("accept", false)})
	cs, err := client.Connect(t.Context(), &mcp.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := callDiag(t, cs)
	t.Logf("stdio: %+v", d)
	if d.Round != 2 || !d.ElicitationDeclared || d.Action != "accept" || d.Answer == nil || *d.Answer {
		t.Fatalf("stdio: %+v", d)
	}
	_ = cs.Close()
	_ = clientOut.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stdio server did not stop")
	}
}

func TestDiagBuildIsMarked(t *testing.T) {
	var out, errb bytes.Buffer
	run(t.Context(), strings.NewReader(""), []string{"version"}, lookup(nil), &out, &errb)
	if !strings.Contains(out.String(), "diagnostic build") {
		t.Fatalf("version: %q", out.String())
	}
	out.Reset()
	run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(nil), &out, &errb)
	if !strings.Contains(out.String(), `"shell_diag_elicit"`) {
		t.Fatal("the diagnostic build lacks its tool")
	}
}
