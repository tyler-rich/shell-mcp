package transport

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

func noneConfig() *config.Config {
	return &config.Config{
		Transport:  "http",
		AuthMode:   "none",
		Bind:       "127.0.0.1",
		Port:       8080,
		Path:       "/mcp",
		MaxTimeout: 300 * time.Second,
	}
}

var mcpStub = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-Test-Mcp", "1")
	w.WriteHeader(http.StatusTeapot)
})

func newTestServer(t *testing.T) *http.Server {
	t.Helper()
	srv, err := New(noneConfig(), mcpStub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestHealthzExactResponse(t *testing.T) {
	srv := newTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, "/healthz", http.NoBody))
		res := rec.Result()
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s /healthz status = %d", method, res.StatusCode)
		}
		if method == http.MethodGet && string(body) != `{"status":"ok"}` {
			t.Fatalf("GET /healthz body = %q", body)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q", ct)
		}
		for _, h := range []string{"Server", "X-Powered-By", "X-Version", "X-Test-Mcp"} {
			if v := res.Header.Get(h); v != "" {
				t.Fatalf("unexpected header %s: %q", h, v)
			}
		}
		for name, vals := range res.Header {
			for _, v := range vals {
				if strings.Contains(strings.ToLower(v), "shell-mcp") || strings.Contains(v, "go1.") {
					t.Fatalf("version-revealing header %s: %q", name, v)
				}
			}
		}
		if res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("missing hardening headers: %v", res.Header)
		}
	}
}

func TestHealthzRejectsOtherMethods(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/healthz", strings.NewReader("{}")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz status = %d", rec.Code)
	}
}

func TestHealthzBypassesMCPHandler(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", http.NoBody))
	if rec.Header().Get("X-Test-Mcp") != "" {
		t.Fatal("/healthz was routed through the MCP handler")
	}
}

func TestMCPPathRoutesToHandlerAndOthersAre404(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader("{}")))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("/mcp not routed to MCP handler: %d", rec.Code)
	}
	for _, p := range []string{"/", "/mcp/extra", "/healthz/x", "/metrics"} {
		rec = httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, p, http.NoBody))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", p, rec.Code)
		}
	}
}

func TestServeRefusesBearerMode(t *testing.T) {
	cfg := noneConfig()
	cfg.AuthMode = "bearer"
	cfg.Bind = "0.0.0.0"
	srv, err := New(cfg, mcpStub)
	if srv != nil || err == nil {
		t.Fatalf("New accepted bearer mode (srv=%v, err=%v)", srv, err)
	}
	if !errors.Is(err, ErrBearerNotImplemented) || err.Error() != "bearer auth arrives in Session 2" {
		t.Fatalf("error = %q", err)
	}
}

func TestServeRefusesNonLoopbackEvenIfNone(t *testing.T) {
	// Defence in depth: config validation already forbids this combination.
	cfg := noneConfig()
	cfg.Bind = "0.0.0.0"
	if _, err := New(cfg, mcpStub); err == nil {
		t.Fatal("New accepted unauthenticated non-loopback bind")
	}
}

func TestServerTimeoutsSet(t *testing.T) {
	srv := newTestServer(t)
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("timeouts/limits not set: rh=%v r=%v w=%v i=%v mhb=%d",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
	if srv.WriteTimeout <= noneConfig().MaxTimeout {
		t.Fatalf("WriteTimeout %v must exceed the maximum tool timeout", srv.WriteTimeout)
	}
	if srv.MaxHeaderBytes > 1<<16 {
		t.Fatalf("MaxHeaderBytes too large: %d", srv.MaxHeaderBytes)
	}
	if srv.Addr != "127.0.0.1:8080" {
		t.Fatalf("Addr = %q", srv.Addr)
	}
}
