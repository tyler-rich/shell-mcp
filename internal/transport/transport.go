// Package transport builds the HTTP server: /healthz outside every
// middleware, and everything else behind the chain of ARCHITECTURE §3, in
// this order: body cap (413) → global per-client rate limit (429) →
// Host/Origin allow-list (421/403) → bearer auth (401; repeated failures
// 429) → the MCP handler at the configured path (404 elsewhere).
package transport

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
)

// ErrUnauthenticatedNonLoopback guards the same invariant as config
// validation, in case a Config is built by other means.
var ErrUnauthenticatedNonLoopback = errors.New("refusing unauthenticated HTTP on a non-loopback address")

// MaxBodyBytes caps a request body (S-03).
const MaxBodyBytes = 1 << 20

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

// Refusal codes written by this package (auth writes its own).
const (
	codeTooLarge = "request_too_large"
	codeHost     = "host_not_allowed"
	codeOrigin   = "origin_not_allowed"
)

var healthzBody = []byte(`{"status":"ok"}`)

// Options are optional dependencies of New; nil means the defaults (the
// wall clock and a logger that discards).
type Options struct {
	Now    func() time.Time
	Logger *slog.Logger
}

// handler is the server's root handler: /healthz, then the chain.
type handler struct {
	mux  http.Handler
	rate *ipLimiter
	auth *auth.Middleware
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// New returns the HTTP server for cfg with mcp mounted at cfg.Path behind
// the middleware chain.
func New(cfg *config.Config, mcp http.Handler, opts *Options) (*http.Server, error) {
	if cfg.AuthMode == "none" && !config.IsLoopbackBind(cfg.Bind) {
		return nil, ErrUnauthenticatedNonLoopback
	}
	o := Options{Now: time.Now, Logger: slog.New(slog.DiscardHandler)}
	if opts != nil {
		if opts.Now != nil {
			o.Now = opts.Now
		}
		if opts.Logger != nil {
			o.Logger = opts.Logger
		}
	}
	clientKey := func(r *http.Request) clientID { return keyOf(clientAddr(r, cfg.TrustedProxies)) }
	am, err := auth.New(auth.Config{Mode: cfg.AuthMode, Token: cfg.Token, ClientKey: clientKey, Now: o.Now, Logger: o.Logger})
	if err != nil {
		return nil, err
	}
	rate := newIPLimiter(cfg.RateLimitPerMin, o.Now)

	protected := http.NewServeMux()
	protected.Handle(cfg.Path, mcp)
	protected.HandleFunc("/", http.NotFound)

	var chain http.Handler = protected
	chain = am.Handler(chain)
	chain = hostOrigin(cfg.AllowedHosts, cfg.AllowedOrigins, clientKey, o.Logger, chain)
	chain = rateLimit(rate, clientKey, chain)
	chain = bodyCap(chain)

	mux := http.NewServeMux()
	mux.HandleFunc(HealthzPath, healthz)
	mux.Handle("/", chain)

	return &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)),
		Handler:           &handler{mux: mux, rate: rate, auth: am},
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      cfg.MaxTimeout + writeHeadroom,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(o.Logger.Handler(), slog.LevelWarn),
	}, nil
}

// bodyCap refuses a declared body over MaxBodyBytes before anything else
// runs, and bounds every other body while it is read (a body of unknown
// length that turns out too large fails the read; the SDK answers 413).
// Nothing reads a body before authentication.
func bodyCap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxBodyBytes {
			auth.Refuse(w, http.StatusRequestEntityTooLarge, codeTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func rateLimit(l *ipLimiter, key func(*http.Request) clientID, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := l.allow(key(r)); !ok {
			auth.RetryAfter(w, wait)
			auth.Refuse(w, http.StatusTooManyRequests, auth.CodeRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostOrigin is the DNS-rebinding defence (S-02), applied whatever the
// SDK's own defaults are: a Host not on the allow-list is 421 Misdirected
// Request (this server does not answer for that name); a request carrying
// an Origin not on the allow-list (or several Origin headers) is 403. A
// refusal is logged by reason and client only: the header values are the
// requester's and never reach the log.
func hostOrigin(hosts, origins []string, key func(*http.Request) clientID, logger *slog.Logger, next http.Handler) http.Handler {
	allowedHosts := parseHostList(hosts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, allowedHosts) {
			logger.Warn("request refused", "reason", codeHost, "client", key(r).String())
			auth.Refuse(w, http.StatusMisdirectedRequest, codeHost)
			return
		}
		if vals := r.Header.Values("Origin"); len(vals) > 0 && (len(vals) > 1 || !originAllowed(vals[0], origins)) {
			logger.Warn("request refused", "reason", codeOrigin, "client", key(r).String())
			auth.Refuse(w, http.StatusForbidden, codeOrigin)
			return
		}
		next.ServeHTTP(w, r)
	})
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
