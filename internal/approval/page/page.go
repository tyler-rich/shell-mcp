// Package page serves the approval page (docs/handoff/S4B-APPROVAL.md §6.5)
// on its own listener: the bookmark page, one record's page, and POST-only
// approve and decline, each needing the record's CSRF token and a current
// TOTP code of an enrolled approver. It never accepts the bearer token, sets
// no cookie, serves no script and no external resource, and pins its one
// inline style by hash in a strict Content-Security-Policy.
package page

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/approval/totp"
)

// MaxBodyBytes caps a decision's body.
const MaxBodyBytes = 4096

// Config configures the page.
type Config struct {
	// PublicURL is SHELL_MCP_APPROVAL_PUBLIC_URL: the page's fixed origin
	// (scheme, host and optional port; config validated it).
	PublicURL string
	Store     *approval.Store
	Verifier  *totp.Verifier
	// Approvers are the enrolled approvers' names. With one, the form has
	// no name field.
	Approvers []string
	// TrustedProxies derive the client as on /mcp; with ProxyOnly the
	// listener serves only peers inside them.
	TrustedProxies []netip.Prefix
	ProxyOnly      bool
	// RateLimitPerMin is the per-client rate limit.
	RateLimitPerMin int
	Logger          *slog.Logger
	Now             func() time.Time
	// OnLockout, when set, is called when an approver is locked out (the
	// notifier).
	OnLockout func(approver string, until time.Time, consecutive int)
}

// New returns the page's handler.
func New(c Config) (http.Handler, error) { return http.NotFoundHandler(), nil }

// NewServer returns the approval listener's server on addr, serving TLS 1.2
// or later with cert when it is not nil.
func NewServer(c Config, addr string, cert *tls.Certificate) (*http.Server, error) {
	h, err := New(c)
	if err != nil {
		return nil, err
	}
	return &http.Server{Addr: addr, Handler: h}, nil
}

// StyleHash is the CSP source for the page's inline style:
// 'sha256-<base64>'.
func StyleHash() string { return "" }

// pageCSS is the page's one inline style, pinned by StyleHash.
const pageCSS = ""
