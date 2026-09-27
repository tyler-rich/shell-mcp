// Package transport builds the HTTP server: /healthz outside every
// middleware, and the MCP handler at the configured path. Session 2 adds the
// body cap, rate limits, Host/Origin allow-list and bearer auth in front of
// the MCP handler.
package transport

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// ErrBearerNotImplemented is returned for bearer mode until Session 2 adds
// the auth middleware. Refusing to start is what keeps the scaffold from ever
// serving an unauthenticated, non-loopback endpoint.
var ErrBearerNotImplemented = errors.New("bearer auth arrives in Session 2")

// ErrUnauthenticatedNonLoopback guards the same invariant as config
// validation, in case a Config is built by other means.
var ErrUnauthenticatedNonLoopback = errors.New("refusing unauthenticated HTTP on a non-loopback address")

// Server limits. WriteTimeout covers the longest tool call plus headroom.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	idleTimeout       = 120 * time.Second
	writeHeadroom     = 30 * time.Second
	maxHeaderBytes    = 16 << 10
)

// HealthzPath is the unauthenticated liveness endpoint.
const HealthzPath = "/healthz"

var healthzBody = []byte(`{"status":"ok"}`)

// New returns the HTTP server for cfg with mcp mounted at cfg.Path.
func New(cfg *config.Config, mcp http.Handler) (*http.Server, error) {
	if cfg.AuthMode != "none" {
		return nil, ErrBearerNotImplemented
	}
	if !config.IsLoopbackBind(cfg.Bind) {
		return nil, ErrUnauthenticatedNonLoopback
	}

	mux := http.NewServeMux()
	mux.HandleFunc(HealthzPath, healthz)
	mux.Handle(cfg.Path, mcp)
	mux.HandleFunc("/", http.NotFound)

	return &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      cfg.MaxTimeout + writeHeadroom,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}, nil
}

// healthz reports liveness only: no version, configuration or target state.
func healthz(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(healthzBody)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(healthzBody)
	}
}
