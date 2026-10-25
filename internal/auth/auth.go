package auth

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// Principal is the authenticated MCP caller. v1 has one principal per
// server instance (plan §3): one bearer token, one profile.
type Principal struct {
	Name    string
	Profile string
}

// Principal names. The bearer principal is the holder of the one configured
// token; "none" mode (stdio, or loopback HTTP with
// SHELL_MCP_ALLOW_UNAUTHENTICATED=true) has no authenticated caller.
const (
	PrincipalBearer          = "bearer-token"
	PrincipalUnauthenticated = "unauthenticated"
)

// Auth-failure limits (S-03): MaxFailures failures by one client within
// FailureWindow lock that client out for Lockout. A failure counts only when
// the request presented a credential that did not authenticate (a wrong
// token, another scheme, a malformed value, several Authorization headers);
// a request without an Authorization header does not count. While locked,
// every request from it is refused with 429 before its token is looked at.
const (
	MaxFailures   = 10
	FailureWindow = 5 * time.Minute
	Lockout       = 5 * time.Minute
	// MaxTrackedClients bounds the failure table.
	MaxTrackedClients = 4096
)

// Refusal codes, written as {"error":"<code>"}.
const (
	CodeUnauthorized = "unauthorized"
	CodeRateLimited  = "rate_limited"
)

// Config configures the middleware.
type Config struct {
	// Mode is "bearer" or "none".
	Mode  string
	Token config.Secret
	// ClientKey identifies the client a failure is counted against.
	ClientKey func(*http.Request) netip.Prefix
	Now       func() time.Time
	Logger    *slog.Logger
}

// Middleware is the bearer-auth middleware with its failure limiter.
type Middleware struct {
	cfg      Config
	mu       sync.Mutex
	failures map[netip.Prefix]*record
}

type record struct {
	times       []time.Time // failures within the window, oldest first
	lockedUntil time.Time
	seen        time.Time
}

// New returns the middleware for cfg. Bearer mode needs a token.
func New(cfg Config) (*Middleware, error) {
	switch cfg.Mode {
	case "bearer":
		if cfg.Token.IsZero() {
			return nil, errors.New("auth: bearer mode needs a token")
		}
	case "none":
	default:
		return nil, errors.New("auth: unknown mode")
	}
	if cfg.ClientKey == nil || cfg.Now == nil || cfg.Logger == nil {
		return nil, errors.New("auth: ClientKey, Now and Logger are required")
	}
	return &Middleware{cfg: cfg, failures: map[netip.Prefix]*record{}}, nil
}

// Handler wraps next. In "none" mode it passes every request through.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	if m.cfg.Mode == "none" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := m.cfg.ClientKey(r)
		now := m.cfg.Now()
		if wait := m.lockedFor(key, now); wait > 0 {
			RetryAfter(w, wait)
			Refuse(w, http.StatusTooManyRequests, CodeRateLimited)
			return
		}
		if reason := m.check(r); reason != "" {
			m.fail(key, now, reason, reason != reasonMissing)
			w.Header().Set("WWW-Authenticate", `Bearer realm="shell-mcp"`)
			Refuse(w, http.StatusUnauthorized, CodeUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// reasonMissing is the failure reason of a request without any
// Authorization header. It is the one failure that does not count toward
// the lockout: the lockout stops token guessing, and a request that
// presents nothing guesses nothing (clients probe OAuth discovery without
// credentials before they connect). Such requests still get the 401 and
// still pass the global per-client rate limit.
const reasonMissing = "missing"

// check returns "" for a request carrying exactly one Authorization header
// of the form "Bearer <token>" (scheme case-insensitive, one space) whose
// token equals the configured one, else a fixed reason for the log.
func (m *Middleware) check(r *http.Request) string {
	vals := r.Header.Values("Authorization")
	switch len(vals) {
	case 0:
		return reasonMissing
	case 1:
	default:
		return "several Authorization headers"
	}
	scheme, token, ok := strings.Cut(vals[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "not a bearer credential"
	}
	if !m.cfg.Token.Equal(token) {
		return "invalid token"
	}
	return ""
}

func (m *Middleware) lockedFor(key netip.Prefix, now time.Time) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.failures[key]; ok && now.Before(rec.lockedUntil) {
		return rec.lockedUntil.Sub(now)
	}
	return 0
}

// fail logs an authentication failure and, when counts is set (a credential
// was presented and did not authenticate), records it toward the lockout.
func (m *Middleware) fail(key netip.Prefix, now time.Time, reason string, counts bool) {
	client := key.String()
	m.cfg.Logger.Warn("authentication failed", "client", client, "reason", reason, "counts_toward_lockout", counts)
	if !counts {
		return
	}
	m.mu.Lock()
	rec, ok := m.failures[key]
	if !ok {
		m.makeRoom(now)
		rec = &record{}
		m.failures[key] = rec
	}
	rec.seen = now
	cut := 0
	for cut < len(rec.times) && now.Sub(rec.times[cut]) >= FailureWindow {
		cut++
	}
	rec.times = append(rec.times[cut:], now)
	locked := len(rec.times) >= MaxFailures
	if locked {
		rec.times = nil
		rec.lockedUntil = now.Add(Lockout)
	}
	m.mu.Unlock()

	if locked {
		m.cfg.Logger.Warn("client locked out after repeated authentication failures",
			"client", client, "failures", MaxFailures, "window_s", int(FailureWindow.Seconds()), "lockout_s", int(Lockout.Seconds()))
	}
}

// makeRoom keeps the table below MaxTrackedClients: first it drops clients
// with no failure in the window and no lockout, then the least recently
// seen client that is not locked, then the least recently seen one.
// Called with m.mu held.
func (m *Middleware) makeRoom(now time.Time) {
	if len(m.failures) < MaxTrackedClients {
		return
	}
	for k, rec := range m.failures {
		if !now.Before(rec.lockedUntil) && (len(rec.times) == 0 || now.Sub(rec.times[len(rec.times)-1]) >= FailureWindow) {
			delete(m.failures, k)
		}
	}
	for len(m.failures) >= MaxTrackedClients {
		var oldest netip.Prefix
		var oldestSeen time.Time
		found := false
		for _, preferUnlocked := range []bool{true, false} {
			for k, rec := range m.failures {
				if preferUnlocked && now.Before(rec.lockedUntil) {
					continue
				}
				if !found || rec.seen.Before(oldestSeen) {
					oldest, oldestSeen, found = k, rec.seen, true
				}
			}
			if found {
				break
			}
		}
		delete(m.failures, oldest)
	}
}

// Tracked is the number of clients in the failure table.
func (m *Middleware) Tracked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.failures)
}

// Refuse writes a refusal: status and the body {"error":"<code>"}, with no
// caching and no content sniffing. code is a fixed identifier.
func Refuse(w http.ResponseWriter, status int, code string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	b := `{"error":"` + code + `"}`
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b))
}

// RetryAfter sets Retry-After to d rounded up to whole seconds (at least 1).
func RetryAfter(w http.ResponseWriter, d time.Duration) {
	s := max(1, int(math.Ceil(d.Seconds())))
	w.Header().Set("Retry-After", strconv.Itoa(s))
}
