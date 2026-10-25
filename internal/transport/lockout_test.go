package transport

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The lockout exists to stop token guessing, so only a presented credential
// that does not authenticate counts toward it; a request without any
// Authorization header gets the same 401 and counts toward nothing but the
// global rate limit. Addresses and tokens are invented test fixtures.

const wrongToken = "Bearer wrong-token-0123456789abcdefghijklmnopqrstuvwxyz"

// logLines decodes the JSON log written so far.
func (e *env) logLines() []map[string]any {
	e.t.Helper()
	var lines []map[string]any
	sc := bufio.NewScanner(strings.NewReader(e.logs.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			e.t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		lines = append(lines, m)
	}
	return lines
}

// authFailures returns the "authentication failed" lines.
func (e *env) authFailures() []map[string]any {
	e.t.Helper()
	var out []map[string]any
	for _, l := range e.logLines() {
		if l["msg"] == "authentication failed" {
			out = append(out, l)
		}
	}
	return out
}

func (e *env) lockoutLogged() bool {
	e.t.Helper()
	for _, l := range e.logLines() {
		if m, _ := l["msg"].(string); strings.Contains(m, "locked out") {
			return true
		}
	}
	return false
}

// want401 checks the documented 401: status, body, WWW-Authenticate, and
// that MCP was never reached.
func (e *env) want401(res *result) {
	e.t.Helper()
	if got := res.Header.Get("WWW-Authenticate"); got != `Bearer realm="shell-mcp"` {
		e.t.Fatalf("WWW-Authenticate = %q (status %d)", got, res.StatusCode)
	}
	e.wantRefused(res, http.StatusUnauthorized, bodyUnauthorized)
}

func (e *env) wantOK(res *result, what string) {
	e.t.Helper()
	if res.StatusCode != http.StatusOK {
		e.t.Fatalf("%s: status %d body %s", what, res.StatusCode, res.Body)
	}
}

// wantFailureLines checks that every auth-failure line keeps its reason and
// says whether it counted, and that n of them counted.
func (e *env) wantFailureLines(total, counted int) {
	e.t.Helper()
	lines := e.authFailures()
	if len(lines) != total {
		e.t.Fatalf("%d authentication-failure lines, want %d: %s", len(lines), total, e.logs.String())
	}
	n := 0
	for _, l := range lines {
		if r, _ := l["reason"].(string); r == "" {
			e.t.Fatalf("failure line without a reason: %v", l)
		}
		c, ok := l["counts_toward_lockout"].(bool)
		if !ok {
			e.t.Fatalf("failure line does not say whether it counted: %v", l)
		}
		if c != (l["reason"] != "missing") {
			e.t.Fatalf("counts_toward_lockout = %v for reason %q", c, l["reason"])
		}
		if c {
			n++
		}
	}
	if n != counted {
		e.t.Fatalf("%d failures counted toward the lockout, want %d", n, counted)
	}
}

// TestCredentialLessRequestsDoNotCountTowardLockout: a client that probes
// without credentials (OAuth discovery, a bridge starting twice) is never
// locked out, and its first real request succeeds.
func TestCredentialLessRequestsDoNotCountTowardLockout(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	for i := range 20 {
		r := req{noAuth: true}
		if i%2 == 1 {
			r = req{method: http.MethodGet, path: "/.well-known/oauth-protected-resource", noAuth: true}
		}
		e.want401(e.do(&r))
	}
	e.wantOK(e.do(&req{}), "valid token after 20 credential-less requests")
	e.wantFailureLines(20, 0)
	if e.lockoutLogged() {
		t.Fatalf("lockout logged: %s", e.logs.String())
	}
}

// TestWrongTokenLockoutControl: ten wrong tokens still lock the client out.
func TestWrongTokenLockoutControl(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	for range 10 {
		e.want401(e.do(&req{auth: wrongToken}))
	}
	res := e.do(&req{})
	if ra, err := strconv.Atoi(res.Header.Get("Retry-After")); err != nil || ra < 290 || ra > 300 {
		t.Fatalf("Retry-After = %q", res.Header.Get("Retry-After"))
	}
	e.wantRefused(res, http.StatusTooManyRequests, bodyRateLimited)
	// While locked, a credential-less request is refused by the lockout too.
	e.wantRefused(e.do(&req{noAuth: true}), http.StatusTooManyRequests, bodyRateLimited)
	e.wantFailureLines(10, 10)
	if !e.lockoutLogged() {
		t.Fatalf("lockout not logged: %s", e.logs.String())
	}
}

// TestMixedFailuresOnlyWrongCredentialsCount: 15 credential-less and 9
// wrong-token requests, interleaved, do not lock out; the 10th wrong token
// does.
func TestMixedFailuresOnlyWrongCredentialsCount(t *testing.T) {
	e := newEnv(t, bearerConfig(t))
	wrong := 0
	for i := range 24 {
		if i%8 < 3 && wrong < 9 { // 3 wrong, 5 none, repeated
			e.want401(e.do(&req{auth: wrongToken}))
			wrong++
			continue
		}
		e.want401(e.do(&req{noAuth: true}))
	}
	if wrong != 9 {
		t.Fatalf("sent %d wrong tokens, want 9", wrong)
	}
	e.wantOK(e.do(&req{}), "valid token after 15 credential-less and 9 wrong-token requests")
	e.wantFailureLines(24, 9)
	if e.lockoutLogged() {
		t.Fatalf("locked out before the 10th wrong token: %s", e.logs.String())
	}
	e.want401(e.do(&req{auth: wrongToken}))
	e.wantRefused(e.do(&req{}), http.StatusTooManyRequests, bodyRateLimited)
	if !e.lockoutLogged() {
		t.Fatalf("the 10th wrong token did not lock out: %s", e.logs.String())
	}
}

// TestPresentedBadCredentialsCount: anything in an Authorization header that
// does not authenticate counts, whatever its shape.
func TestPresentedBadCredentialsCount(t *testing.T) {
	for name, r := range map[string]req{
		"malformed, no token":   {auth: "Bearer"},
		"malformed, empty":      {authHeaders: []string{""}},
		"malformed, two spaces": {auth: "Bearer  " + testToken},
		"non-Bearer scheme":     {auth: "Basic " + testToken},
		"no scheme":             {auth: testToken},
		"two headers":           {authHeaders: []string{"Bearer " + testToken, "Bearer " + testToken}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, bearerConfig(t))
			for range 10 {
				e.want401(e.do(&r))
			}
			e.wantRefused(e.do(&req{}), http.StatusTooManyRequests, bodyRateLimited)
			e.wantFailureLines(10, 10)
		})
	}
}

// TestCredentialLessBeyondRateLimitIsTheRateLimiter: credential-less requests
// past the global per-client limit get 429 from the rate limiter, the log
// says so, and nothing is counted toward or logged as a lockout.
func TestCredentialLessBeyondRateLimitIsTheRateLimiter(t *testing.T) {
	cfg := bearerConfig(t)
	cfg.RateLimitPerMin = 5
	e := newEnv(t, cfg)
	for range 5 {
		e.want401(e.do(&req{noAuth: true}))
	}
	for range 5 {
		res := e.do(&req{noAuth: true})
		if ra, err := strconv.Atoi(res.Header.Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
			t.Fatalf("Retry-After = %q", res.Header.Get("Retry-After"))
		}
		if res.Header.Get("WWW-Authenticate") != "" {
			t.Fatal("a rate-limited request reached auth")
		}
		e.wantRefused(res, http.StatusTooManyRequests, bodyRateLimited)
	}
	limited := 0
	for _, l := range e.logLines() {
		if l["msg"] == "request refused" && l["reason"] == "rate_limited" {
			if l["client"] != "192.0.2.10/32" {
				t.Fatalf("rate-limit line without the client: %v", l)
			}
			limited++
		}
	}
	// One line when the client starts being refused, not one per refusal.
	if limited != 1 {
		t.Fatalf("%d rate-limiter lines, want 1: %s", limited, e.logs.String())
	}
	if e.lockoutLogged() {
		t.Fatalf("lockout logged: %s", e.logs.String())
	}
	e.wantFailureLines(5, 0)
	// Once the bucket refills the client is served: it was never locked out.
	e.clock.Advance(61 * time.Second)
	e.wantOK(e.do(&req{}), "valid token after the rate limit")
}
