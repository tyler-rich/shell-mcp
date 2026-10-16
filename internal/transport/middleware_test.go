package transport

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// All hosts, origins, addresses and tokens below are invented test fixtures.

const testToken = "tok-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH"

func bearerConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := noneConfig()
	cfg.AuthMode = "bearer"
	cfg.Bind = "0.0.0.0"
	cfg.Token = config.NewSecret(testToken)
	cfg.AllowedHosts = []string{"localhost", "127.0.0.1", "mcp.example.test", "[::1]:8080"}
	cfg.RateLimitPerMin = 1000
	return cfg
}

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countingMCP is the real SDK handler (stateless, JSON responses, no tools)
// wrapped so a test can see whether any request reached MCP processing.
type countingMCP struct {
	calls atomic.Int64
	h     http.Handler
}

func newCountingMCP() *countingMCP {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	return &countingMCP{h: mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: MaxBodyBytes})}
}

func (c *countingMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.calls.Add(1)
	c.h.ServeHTTP(w, r)
}

type env struct {
	t     *testing.T
	h     http.Handler
	mcp   *countingMCP
	clock *fakeClock
	logs  *bytes.Buffer
}

func newEnv(t *testing.T, cfg *config.Config) *env {
	t.Helper()
	e := &env{t: t, mcp: newCountingMCP(), clock: newClock(), logs: &bytes.Buffer{}}
	srv, err := New(cfg, e.mcp, &Options{Now: e.clock.Now, Logger: slog.New(slog.NewJSONHandler(e.logs, nil))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.h = srv.Handler
	return e
}

const toolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

// req is one request; zero fields take the defaults of a valid call.
type req struct {
	method, path, host, origin, remote, auth, body string
	headers                                        map[string]string
	contentLength                                  int64
	chunked                                        bool
	noAuth                                         bool
	emptyHost                                      bool
}

func (e *env) do(r req) *http.Response {
	e.t.Helper()
	if r.method == "" {
		r.method = http.MethodPost
	}
	if r.path == "" {
		r.path = "/mcp"
	}
	if r.body == "" && r.method == http.MethodPost {
		r.body = toolsList
	}
	var body io.Reader = strings.NewReader(r.body)
	if r.chunked {
		body = io.MultiReader(strings.NewReader(r.body)) // unknown length: no Content-Length
	}
	hr := httptest.NewRequestWithContext(e.t.Context(), r.method, r.path, body)
	if r.chunked {
		hr.ContentLength = -1
	}
	if r.contentLength != 0 {
		hr.ContentLength = r.contentLength
	}
	hr.Host = "127.0.0.1:8080"
	if r.host != "" {
		hr.Host = r.host
	}
	if r.emptyHost {
		hr.Host = ""
	}
	hr.RemoteAddr = "192.0.2.10:51000"
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	if r.origin != "" {
		hr.Header.Set("Origin", r.origin)
	}
	switch {
	case r.noAuth:
	case r.auth != "":
		hr.Header.Set("Authorization", r.auth)
	default:
		hr.Header.Set("Authorization", "Bearer "+testToken)
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json, text/event-stream")
	hr.Header.Set("MCP-Protocol-Version", "2025-11-25")
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, hr)
	return rec.Result()
}

func body(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return string(b)
}

// want checks status and body, and that the refusal never reached MCP.
func (e *env) wantRefused(res *http.Response, status int, wantBody string) {
	e.t.Helper()
	before := e.mcp.calls.Load()
	b := body(e.t, res)
	if res.StatusCode != status || b != wantBody {
		e.t.Fatalf("status %d body %q, want %d %q", res.StatusCode, b, status, wantBody)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		e.t.Fatalf("Content-Type = %q", ct)
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		e.t.Fatalf("refusal lacks hardening headers: %v", res.Header)
	}
	if e.mcp.calls.Load() != before {
		e.t.Fatal("a refused request reached the MCP handler")
	}
}

const (
	bodyUnauthorized = `{"error":"unauthorized"}`
	bodyTooLarge     = `{"error":"request_too_large"}`
	bodyRateLimited  = `{"error":"rate_limited"}`
	bodyHost         = `{"error":"host_not_allowed"}`
	bodyOrigin       = `{"error":"origin_not_allowed"}`
)

func TestUnauthenticatedToolsListGets401BeforeMCP(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	for name, r := range map[string]req{
		"no header":        {noAuth: true},
		"wrong token":      {auth: "Bearer " + strings.Repeat("x", len(testToken))},
		"prefix of token":  {auth: "Bearer " + testToken[:len(testToken)-1]},
		"token plus extra": {auth: "Bearer " + testToken + "x"},
		"basic scheme":     {auth: "Basic " + testToken},
		"no scheme":        {auth: testToken},
		"two spaces":       {auth: "Bearer  " + testToken},
		"trailing space":   {auth: "Bearer " + testToken + " "},
		"empty token":      {auth: "Bearer "},
		"discovery":        {body: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}`, noAuth: true},
		"initialize":       {body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`, noAuth: true},
		"get":              {method: http.MethodGet, noAuth: true},
		"unknown path":     {path: "/metrics", method: http.MethodGet, noAuth: true},
		"well-known":       {path: "/.well-known/oauth-protected-resource", method: http.MethodGet, noAuth: true},
	} {
		t.Run(name, func(t *testing.T) {
			e.t = t
			res := e.do(r)
			if got := res.Header.Get("WWW-Authenticate"); got != `Bearer realm="shell-mcp"` {
				t.Fatalf("WWW-Authenticate = %q", got)
			}
			e.wantRefused(res, http.StatusUnauthorized, bodyUnauthorized)
		})
		// Keep the failure counter below the lockout for the next case.
		e.clock.Advance(6 * time.Minute)
	}
}

func TestTwoAuthorizationHeadersRefused(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	hr := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader(toolsList))
	hr.Host = "127.0.0.1"
	hr.RemoteAddr = "192.0.2.10:51000"
	hr.Header.Add("Authorization", "Bearer "+testToken)
	hr.Header.Add("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, hr)
	e.wantRefused(rec.Result(), http.StatusUnauthorized, bodyUnauthorized)
}

func TestValidTokenReachesMCP(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	for _, auth := range []string{"Bearer " + testToken, "bearer " + testToken, "BEARER " + testToken} {
		res := e.do(req{auth: auth})
		b := body(t, res)
		if res.StatusCode != http.StatusOK || !strings.Contains(b, `"tools":[]`) {
			t.Fatalf("%q: status %d body %s", auth, res.StatusCode, b)
		}
	}
	if e.mcp.calls.Load() != 3 {
		t.Fatalf("mcp calls = %d", e.mcp.calls.Load())
	}
}

func TestHostAllowList(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	for _, h := range []string{"evil.example.test", "mcp.example.test.evil.example.test", "localhost.", "127.0.0.2:8080",
		"[::1]:9090", "MCP.example.test:443x", "user@mcp.example.test", "localhost:", ":8080"} {
		e.wantRefused(e.do(req{host: h}), http.StatusMisdirectedRequest, bodyHost)
	}
	e.wantRefused(e.do(req{emptyHost: true}), http.StatusMisdirectedRequest, bodyHost)
	for _, h := range []string{"localhost", "localhost:8080", "127.0.0.1:1234", "MCP.Example.Test", "mcp.example.test:443", "[::1]:8080"} {
		if res := e.do(req{host: h}); res.StatusCode != http.StatusOK {
			t.Fatalf("host %q refused: %d %s", h, res.StatusCode, body(t, res))
		}
	}
}

func TestOriginAllowList(t *testing.T) {
	cfg := bearerConfig(t)
	e := newEnv(t, cfg)
	// Empty allow-list: any Origin is refused, even with a valid token.
	for _, o := range []string{"http://localhost:8080", "null", "https://mcp.example.test"} {
		e.wantRefused(e.do(req{origin: o}), http.StatusForbidden, bodyOrigin)
	}
	cfg.AllowedOrigins = []string{"https://app.example.test"}
	e = newEnv(t, cfg)
	e.wantRefused(e.do(req{origin: "https://evil.example.test"}), http.StatusForbidden, bodyOrigin)
	e.wantRefused(e.do(req{origin: "https://app.example.test.evil.example.test"}), http.StatusForbidden, bodyOrigin)
	for _, o := range []string{"https://app.example.test", "HTTPS://APP.EXAMPLE.TEST"} {
		if res := e.do(req{origin: o}); res.StatusCode != http.StatusOK {
			t.Fatalf("origin %q refused: %d", o, res.StatusCode)
		}
	}
	if res := e.do(req{}); res.StatusCode != http.StatusOK {
		t.Fatalf("request without Origin refused: %d", res.StatusCode)
	}
}

func TestBodyCap(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	// Declared too large: refused before anything else, authenticated or not.
	e.wantRefused(e.do(req{contentLength: MaxBodyBytes + 1, noAuth: true}), http.StatusRequestEntityTooLarge, bodyTooLarge)
	e.wantRefused(e.do(req{contentLength: MaxBodyBytes + 1}), http.StatusRequestEntityTooLarge, bodyTooLarge)
	// Unknown length (chunked), authenticated: the cap holds while reading.
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"` + strings.Repeat("a", MaxBodyBytes) + `"}}`
	res := e.do(req{body: big, chunked: true})
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized body: status %d %s", res.StatusCode, body(t, res))
	}
	// Exactly at the cap is accepted by the middleware.
	small := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"` + strings.Repeat("a", 1000) + `"}}`
	if res := e.do(req{body: small}); res.StatusCode != http.StatusOK {
		t.Fatalf("small body: %d", res.StatusCode)
	}
}

// TestMiddlewareOrder: body cap → global rate limit → Host/Origin → auth.
func TestMiddlewareOrder(t *testing.T) {
	cfg := bearerConfig(t)
	cfg.RateLimitPerMin = 1
	e := newEnv(t, cfg)
	limited := "192.0.2.20:1000"
	if res := e.do(req{remote: limited}); res.StatusCode != http.StatusOK { // uses the IP's only token
		t.Fatalf("first request: %d", res.StatusCode)
	}
	cases := []struct {
		name   string
		r      req
		status int
		body   string
	}{
		{"oversized beats rate limit, host, origin and auth", req{remote: limited, contentLength: MaxBodyBytes + 1, host: "evil.example.test", origin: "https://evil.example.test", noAuth: true}, 413, bodyTooLarge},
		{"rate limit beats host, origin and auth", req{remote: limited, host: "evil.example.test", origin: "https://evil.example.test", noAuth: true}, 429, bodyRateLimited},
		{"host beats origin and auth", req{remote: "192.0.2.21:1", host: "evil.example.test", origin: "https://evil.example.test", noAuth: true}, 421, bodyHost},
		{"origin beats auth", req{remote: "192.0.2.22:1", origin: "https://evil.example.test", noAuth: true}, 403, bodyOrigin},
		{"auth", req{remote: "192.0.2.23:1", noAuth: true}, 401, bodyUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.t = t
			e.wantRefused(e.do(c.r), c.status, c.body)
		})
	}
}

func TestGlobalRateLimit(t *testing.T) {
	cfg := bearerConfig(t)
	cfg.RateLimitPerMin = 3
	e := newEnv(t, cfg)
	for i := range 3 {
		if res := e.do(req{}); res.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %d", i, res.StatusCode)
		}
	}
	res := e.do(req{})
	if ra, err := strconv.Atoi(res.Header.Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After = %q", res.Header.Get("Retry-After"))
	}
	e.wantRefused(res, http.StatusTooManyRequests, bodyRateLimited)
	// Another client is unaffected; unauthenticated requests use tokens too.
	if res := e.do(req{remote: "192.0.2.99:1"}); res.StatusCode != http.StatusOK {
		t.Fatalf("other client: %d", res.StatusCode)
	}
	// One token every 20 s (3 per minute).
	e.clock.Advance(21 * time.Second)
	if res := e.do(req{}); res.StatusCode != http.StatusOK {
		t.Fatalf("after refill: %d", res.StatusCode)
	}
	e.wantRefused(e.do(req{}), http.StatusTooManyRequests, bodyRateLimited)
	// /healthz is outside the chain.
	for range 10 {
		if res := e.do(req{method: http.MethodGet, path: "/healthz"}); res.StatusCode != http.StatusOK {
			t.Fatalf("/healthz rate limited: %d", res.StatusCode)
		}
	}
}

func TestIPv6ClientsShareTheir64(t *testing.T) {
	cfg := bearerConfig(t)
	cfg.RateLimitPerMin = 2
	e := newEnv(t, cfg)
	for _, a := range []string{"[2001:db8:1:2::1]:1", "[2001:db8:1:2::ffff]:1"} {
		if res := e.do(req{remote: a}); res.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", a, res.StatusCode)
		}
	}
	e.wantRefused(e.do(req{remote: "[2001:db8:1:2:aaaa::1]:1"}), http.StatusTooManyRequests, bodyRateLimited)
	if res := e.do(req{remote: "[2001:db8:1:3::1]:1"}); res.StatusCode != http.StatusOK {
		t.Fatalf("another /64: %d", res.StatusCode)
	}
	// An IPv4-mapped address is the IPv4 client.
	for range 2 {
		_ = e.do(req{remote: "192.0.2.50:1"})
	}
	e.wantRefused(e.do(req{remote: "[::ffff:192.0.2.50]:1"}), http.StatusTooManyRequests, bodyRateLimited)
}

func TestAuthFailureLockout(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	bad := req{auth: "Bearer wrong-token-0123456789abcdefghijklmnopqrstuvwxyz"}
	for i := range 10 {
		e.wantRefused(e.do(bad), http.StatusUnauthorized, bodyUnauthorized)
		_ = i
	}
	// Locked for 5 minutes: even the valid token is refused, before auth runs.
	res := e.do(req{})
	if ra, err := strconv.Atoi(res.Header.Get("Retry-After")); err != nil || ra < 290 || ra > 300 {
		t.Fatalf("Retry-After = %q", res.Header.Get("Retry-After"))
	}
	e.wantRefused(res, http.StatusTooManyRequests, bodyRateLimited)
	e.wantRefused(e.do(bad), http.StatusTooManyRequests, bodyRateLimited)
	// Another client is not locked.
	if res := e.do(req{remote: "192.0.2.77:1"}); res.StatusCode != http.StatusOK {
		t.Fatalf("other client: %d", res.StatusCode)
	}
	e.clock.Advance(4*time.Minute + 50*time.Second)
	e.wantRefused(e.do(req{}), http.StatusTooManyRequests, bodyRateLimited)
	e.clock.Advance(15 * time.Second)
	if res := e.do(req{}); res.StatusCode != http.StatusOK {
		t.Fatalf("after lockout: %d %s", res.StatusCode, body(t, res))
	}
	if strings.Contains(e.logs.String(), testToken) || strings.Contains(e.logs.String(), "wrong-token") {
		t.Fatalf("log contains a token: %s", e.logs.String())
	}
	if !strings.Contains(e.logs.String(), "192.0.2.10") {
		t.Fatalf("lockout not logged with the client address: %s", e.logs.String())
	}
}

func TestAuthFailuresOutsideWindowDoNotCount(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	bad := req{noAuth: true}
	for range 9 {
		e.wantRefused(e.do(bad), http.StatusUnauthorized, bodyUnauthorized)
	}
	e.clock.Advance(5*time.Minute + time.Second)
	for range 9 {
		e.wantRefused(e.do(bad), http.StatusUnauthorized, bodyUnauthorized)
	}
	if res := e.do(req{}); res.StatusCode != http.StatusOK {
		t.Fatalf("9+9 failures across two windows locked the client: %d", res.StatusCode)
	}
}

func TestTrustProxy(t *testing.T) {
	cfg := bearerConfig(t)
	cfg.RateLimitPerMin = 1
	proxy := "192.0.2.1:4000"
	xff := func(v string) map[string]string { return map[string]string{"X-Forwarded-For": v} }

	// Off: X-Forwarded-For is ignored; every request is the proxy's.
	e := newEnv(t, cfg)
	_ = e.do(req{remote: proxy, headers: xff("198.51.100.1")})
	e.wantRefused(e.do(req{remote: proxy, headers: xff("198.51.100.2")}), http.StatusTooManyRequests, bodyRateLimited)

	// On: the entry the proxy appended (the last one) is the client.
	cfg.TrustProxy = true
	e = newEnv(t, cfg)
	if res := e.do(req{remote: proxy, headers: xff("203.0.113.9, 198.51.100.1")}); res.StatusCode != http.StatusOK {
		t.Fatalf("first client: %d", res.StatusCode)
	}
	// A client cannot escape by prepending a forged entry.
	e.wantRefused(e.do(req{remote: proxy, headers: xff("203.0.113.10, 198.51.100.1")}), http.StatusTooManyRequests, bodyRateLimited)
	if res := e.do(req{remote: proxy, headers: xff("198.51.100.2")}); res.StatusCode != http.StatusOK {
		t.Fatalf("second client: %d", res.StatusCode)
	}
	// Unparsable: the connection's own address.
	if res := e.do(req{remote: proxy, headers: xff("not-an-ip")}); res.StatusCode != http.StatusOK {
		t.Fatalf("garbage XFF: %d", res.StatusCode)
	}
	e.wantRefused(e.do(req{remote: proxy}), http.StatusTooManyRequests, bodyRateLimited)
}

func TestLimiterMemoryIsBounded(t *testing.T) {
	cfg := bearerConfig(t)
	e := newEnv(t, cfg)
	for i := range maxTrackedClients + 500 {
		_ = e.do(req{remote: fmt.Sprintf("198.%d.%d.%d:1", 18+(i>>16&1), i>>8&0xff, i&0xff), noAuth: true})
	}
	if n := trackedClients(e.h); n > 2*maxTrackedClients {
		t.Fatalf("tracking %d clients, bound is %d per limiter", n, maxTrackedClients)
	}
}

func TestHealthzOutsideChain(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	res := e.do(req{method: http.MethodGet, path: "/healthz", host: "evil.example.test", origin: "https://evil.example.test", noAuth: true})
	if b := body(t, res); res.StatusCode != http.StatusOK || b != `{"status":"ok"}` {
		t.Fatalf("/healthz: %d %q", res.StatusCode, b)
	}
}

func TestNoneModePassesWithoutToken(t *testing.T) {
	e := newEnv(t, noneConfig())
	if res := e.do(req{noAuth: true}); res.StatusCode != http.StatusOK {
		t.Fatalf("none mode: %d", res.StatusCode)
	}
	// The Host allow-list still applies on loopback (DNS rebinding).
	cfg := noneConfig()
	cfg.AllowedHosts = []string{"localhost", "127.0.0.1"}
	e = newEnv(t, cfg)
	e.wantRefused(e.do(req{noAuth: true, host: "rebind.example.test"}), http.StatusMisdirectedRequest, bodyHost)
}

func TestServeAcceptsBearerMode(t *testing.T) {
	srv, err := New(bearerConfig(t), mcpStub, nil)
	if err != nil || srv == nil {
		t.Fatalf("New refused bearer mode: %v", err)
	}
}

func TestBearerModeNeedsAToken(t *testing.T) {
	cfg := bearerConfig(t)
	cfg.Token = config.Secret{}
	if _, err := New(cfg, mcpStub, nil); err == nil {
		t.Fatal("New accepted bearer mode without a token")
	}
}

// trackedClients is the number of client entries both limiters hold.
func trackedClients(h http.Handler) int {
	s := h.(*handler)
	return s.rate.tracked() + s.auth.Tracked()
}
