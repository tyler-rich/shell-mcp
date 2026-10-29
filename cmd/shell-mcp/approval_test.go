//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/approval/totp"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// The approval listener as the server wires it, and an in-process
// simulated human: the approval flow end to end through the real serve
// stack, the approval page and a fake gate. Every value is an invented
// fixture; the approver seed is generated per test.

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func approverFile(t *testing.T) (path string, seed []byte) {
	t.Helper()
	seed = make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "approvers")
	if err := os.WriteFile(path, []byte("alice "+approvers.EncodeSeed(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, seed
}

// webEnv adds a loopback web-method approval configuration to env.
func webEnv(t *testing.T, env map[string]string) (aport int, seed []byte) {
	t.Helper()
	file, seed := approverFile(t)
	aport = freePort(t)
	env["SHELL_MCP_APPROVAL_METHOD"] = "web"
	env["SHELL_MCP_APPROVAL_PORT"] = strconv.Itoa(aport)
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "http://127.0.0.1:" + strconv.Itoa(aport)
	env["SHELL_MCP_APPROVERS_FILE"] = file
	return aport, seed
}

func loadCfg(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func serveReq(h http.Handler, method, target, host, remote string, hdr map[string]string) (code int, body string) {
	r := httptest.NewRequestWithContext(context.Background(), method, target, http.NoBody)
	r.Host, r.RemoteAddr = host, remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestNoApprovalListenerWithoutWeb(t *testing.T) {
	for _, method := range []string{"", "none", "confirm-argument"} {
		env, _ := testEnv(t)
		if method != "" {
			env["SHELL_MCP_APPROVAL_METHOD"] = method
		}
		ar, err := newApprovalRuntime(loadCfg(t, env), slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		if ar.server != nil {
			t.Fatalf("%q: an approval listener exists", method)
		}
		if (method == "confirm-argument") != (ar.store != nil) {
			t.Fatalf("%q: store %v", method, ar.store)
		}
	}
}

func TestListenersNeverServeEachOther(t *testing.T) {
	env, _ := testEnv(t)
	aport, _ := webEnv(t, env)
	cfg := loadCfg(t, env)
	ar, err := newApprovalRuntime(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if ar.server == nil || ar.server.Addr != "127.0.0.1:"+strconv.Itoa(aport) || ar.server.TLSConfig != nil {
		t.Fatalf("approval server %+v", ar.server)
	}
	host := "127.0.0.1:" + strconv.Itoa(aport)
	page := ar.server.Handler
	if code, body := serveReq(page, http.MethodGet, "/", host, "127.0.0.1:5000", nil); code != http.StatusOK || !strings.Contains(body, "Approval page for shell-mcp at http://"+host) {
		t.Fatalf("bookmark page: %d %s", code, body)
	}
	bearer := map[string]string{"Authorization": "Bearer " + testToken}
	for _, p := range []string{"/mcp", "/healthz"} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			if code, _ := serveReq(page, m, p, host, "127.0.0.1:5000", bearer); code != http.StatusNotFound {
				t.Fatalf("approval listener %s %s with the bearer token: %d", m, p, code)
			}
		}
	}
	mcpSrv, cleanup, err := newHTTPServer(cfg, slog.New(slog.DiscardHandler), ar)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	for _, p := range []string{"/", "/approvals/aaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if code, body := serveReq(mcpSrv.Handler, http.MethodGet, p, "localhost", "127.0.0.1:5000", bearer); code != http.StatusNotFound || strings.Contains(body, "Approval page") {
			t.Fatalf("MCP listener GET %s: %d %s", p, code, body)
		}
	}
}

func TestApprovalListenerProxyOnly(t *testing.T) {
	env, _ := testEnv(t)
	webEnv(t, env)
	env["SHELL_MCP_APPROVAL_BIND"] = "0.0.0.0"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "https://approve.example.test"
	env["SHELL_MCP_TRUSTED_PROXIES"] = "192.0.2.5"
	var logs bytes.Buffer
	ar, err := newApprovalRuntime(loadCfg(t, env), slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if code, body := serveReq(ar.server.Handler, http.MethodGet, "/", "approve.example.test", "192.0.2.99:1", nil); code != http.StatusForbidden || strings.Contains(body, "Approval page") {
		t.Fatalf("peer outside the proxies: %d %s", code, body)
	}
	if !strings.Contains(logs.String(), `"reason":"peer_not_proxy"`) {
		t.Fatalf("no refusal line: %s", logs.String())
	}
	if code, _ := serveReq(ar.server.Handler, http.MethodGet, "/", "approve.example.test", "192.0.2.5:1", nil); code != http.StatusOK {
		t.Fatalf("the proxy: %d", code)
	}
}

func TestApprovalListenerTLS(t *testing.T) {
	env, _ := testEnv(t)
	webEnv(t, env)
	certFile, keyFile := tlsFiles(t)
	env["SHELL_MCP_APPROVAL_BIND"] = "0.0.0.0"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "https://approve.example.test"
	env["SHELL_MCP_APPROVAL_TLS_CERT_FILE"] = certFile
	env["SHELL_MCP_APPROVAL_TLS_KEY_FILE"] = keyFile
	ar, err := newApprovalRuntime(loadCfg(t, env), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	c := ar.server.TLSConfig
	if c == nil || c.MinVersion != tls.VersionTLS12 || len(c.Certificates) != 1 {
		t.Fatalf("TLS config %+v", c)
	}
	// Any peer is served under native TLS (no proxy restriction).
	if code, _ := serveReq(ar.server.Handler, http.MethodGet, "/", "approve.example.test", "198.51.100.7:1", nil); code != http.StatusOK {
		t.Fatalf("direct peer under TLS: %d", code)
	}
}

func tlsFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "approve.example.test"},
		DNSNames: []string{"approve.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	c, k := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, k
}

// --- The simulated human, in process ------------------------------------------------

// fileGate is a fake gate holding one file's content: stat, read_file, hash_file and
// write_file act on it, and every write is counted.
type fileGate struct {
	mu      sync.Mutex
	content string
	writes  int
}

func (g *fileGate) exec(_ context.Context, s *sshtest.Session) uint32 {
	req, err := protocol.DecodeRequest(s.Stdin)
	if err != nil {
		return 1
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	sum := sha256hex(g.content)
	var data string
	switch req.Op {
	case protocol.OpStat:
		data = fmt.Sprintf(`{"path":"/srv/app/config.yaml","name":"config.yaml","type":"file","size":%d,"mode":"0640","uid":1000,"gid":1000,"mtime":"2026-10-01T00:00:00Z"}`, len(g.content))
	case protocol.OpReadFile:
		data = fmt.Sprintf(`{"path":"/srv/app/config.yaml","size":%d,"sha256":%q,"binary":false,"content":%q,"offset":0,"truncated":false}`, len(g.content), sum, g.content)
	case protocol.OpHashFile:
		data = fmt.Sprintf(`{"path":"/srv/app/config.yaml","size":%d,"sha256":%q,"binary":false,"lines":%d,"private_key":false}`,
			len(g.content), sum, strings.Count(g.content, "\n"))
	case protocol.OpWriteFile:
		var a struct {
			ContentB64     string `json:"content_b64"`
			ExpectedSHA256 string `json:"expected_sha256"`
		}
		_ = json.Unmarshal(req.Args, &a)
		if a.ExpectedSHA256 != "" && a.ExpectedSHA256 != sum {
			_, _ = fmt.Fprintf(s.Stdout, `{"v":2,"id":%q,"ok":false,"error":{"code":"exists","message":"changed"},"warnings":[]}`+"\n", req.ID)
			return 0
		}
		g.writes++
		data = fmt.Sprintf(`{"path":"/srv/app/config.yaml","sha256":%q,"old_sha256":%q,"bytes":1,"created":false,"mode":"0640","lines_old":1,"lines_new":1,"owner_preserved":true,"verified":true}`, sum, sum)
	default:
		data = `{}`
	}
	_, _ = fmt.Fprintf(s.Stdout, `{"v":2,"id":%q,"ok":true,"data":%s,"warnings":[],"gate":{"version":"0.1.0","principal":"operator-key","policy_sha256":"ab12","max_tier":"operator","duration_ms":1}}`+"\n", req.ID, data)
	return 0
}

func sha256hex(s string) string { return approval.SHA256Hex([]byte(s)) }

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestSimulatedHumanInProcess(t *testing.T) {
	g := &fileGate{content: "key: value\n"}
	env, _ := gateEnv(t, g.exec)
	aport, seed := webEnv(t, env)
	env["SHELL_MCP_PROFILE"] = "operator"
	env["SHELL_MCP_APPROVAL_TIERS"] = "operator,destructive"
	cfg := loadCfg(t, env)
	var logs syncBuf
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ar, err := newApprovalRuntime(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	mcpSrv, cleanup, err := newHTTPServer(cfg, logger, ar)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ts := httptest.NewServer(mcpSrv.Handler)
	t.Cleanup(ts.Close)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:"+strconv.Itoa(aport))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ar.server.Serve(ln) }()
	t.Cleanup(func() { _ = ar.server.Close() })
	cs, _, err := connect(t, ts, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"path": "/srv/app/config.yaml", "content": "key: value2\n"}
	call := func(a map[string]any) map[string]any {
		res, cerr := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "shell_write_file", Arguments: a})
		if cerr != nil {
			t.Fatal(cerr)
		}
		b, _ := json.Marshal(res.StructuredContent)
		var env map[string]any
		_ = json.Unmarshal(b, &env)
		return env
	}
	env1 := call(args)
	ap, _ := env1["approval"].(map[string]any)
	pageURL, _ := ap["url"].(string)
	id, _ := ap["id"].(string)
	if !strings.HasPrefix(pageURL, "http://127.0.0.1:"+strconv.Itoa(aport)+"/approvals/") || g.writes != 0 {
		t.Fatalf("first call: %v (writes %d)", env1, g.writes)
	}
	// The human opens the page from the bookmark (with the id), reads the
	// CSRF token and approves with a code from their authenticator.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get("http://127.0.0.1:" + strconv.Itoa(aport) + "/?id=" + id) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("bookmark id submit: %d", res.StatusCode)
	}
	res, err = client.Get(pageURL) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	m := csrfRE.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token on the page: %s", body)
	}
	code := totp.Generate(seed, time.Now().Add(totp.Period))                                                 // the next step: within the ±1 window
	res, err = client.PostForm(pageURL+"/approve", url.Values{"code": {code}, "csrf_token": {string(m[1])}}) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "Approved by alice") {
		t.Fatalf("approve: %d %s", res.StatusCode, b)
	}
	args["approval_id"] = id
	if env2 := call(args); env2["ok"] != true || g.writes != 1 {
		t.Fatalf("re-call: %v (writes %d)", env2, g.writes)
	}
	if env3 := call(args); fmt.Sprint(env3["error"]) == "" || g.writes != 1 {
		t.Fatalf("second re-call: %v (writes %d)", env3, g.writes)
	}
	// The decision is logged with the approver's name; the code and the
	// seed never are.
	l := logs.String()
	if !strings.Contains(l, `"msg":"approval decided"`) || !strings.Contains(l, `"approver":"alice"`) ||
		strings.Contains(l, code) || strings.Contains(l, approvers.EncodeSeed(seed)) || strings.Contains(l, string(m[1])) {
		t.Fatalf("log: %s", l)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
