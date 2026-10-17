// Package page serves the approval page (docs/handoff/S4B-APPROVAL.md §6.5)
// on its own listener: the bookmark page, one record's page, and POST-only
// approve and decline, each needing the record's CSRF token and a current
// TOTP code of an enrolled approver. It never accepts the bearer token, sets
// no cookie, serves no script and no external resource, and pins its one
// inline style by hash in a strict Content-Security-Policy.
//
// Order of checks on every request: the peer (proxy-only listeners) → the
// per-client rate limit → Host → Origin and cross-site requests → the
// route. A decision then checks the body, the record, the CSRF token and
// the record's state before the code, so that no code is spent on a
// request that could not decide. A wrong code, a reused code and a code of
// a locked-out approver get the same answer; only the audit log tells them
// apart.
package page

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/approval/totp"
	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/transport"
)

// MaxBodyBytes caps a decision's body.
const MaxBodyBytes = 4096

// defaultRatePerMin applies when the configuration gives none.
const defaultRatePerMin = 120

// Server limits.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 8 << 10
)

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

// pageCSS is the page's one inline style, pinned by StyleHash. No
// comments, no url(): the CSP allows nothing else.
const pageCSS = "body{font-family:system-ui,sans-serif;margin:0;color:#111;background:#fff}" +
	".banner{background:#fff3cd;border-bottom:3px solid #8a6d00;padding:12px 16px}" +
	".banner p{margin:4px 0}" +
	"main{padding:16px;max-width:64em}" +
	"table{border-collapse:collapse;margin:8px 0 16px;width:100%}" +
	"th,td{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top}" +
	"th{width:14em;font-weight:600}" +
	"td.v{font-family:ui-monospace,monospace;white-space:pre-wrap;word-break:break-all}" +
	".msg{background:#f8d7da;border:1px solid #c66;padding:8px}" +
	".status{font-weight:600}" +
	"input,select,button{font-size:1.1em;margin:4px 8px 4px 0}"

// StyleHash is the CSP source for the page's inline style:
// 'sha256-<base64>'.
func StyleHash() string {
	s := sha256.Sum256([]byte(pageCSS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(s[:]) + "'"
}

// securityHeaders are set on every response (handoff §6.5).
func securityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; style-src "+StyleHash()+"; img-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

type handler struct {
	c          Config
	origin     string
	host, port string
	limiter    *transport.Limiter
	cop        *http.CrossOriginProtection
	approvers  []string
	tmpl       *template.Template
}

// New returns the page's handler.
func New(c Config) (http.Handler, error) {
	if c.Store == nil || c.Verifier == nil {
		return nil, errors.New("page: a store and a verifier are required")
	}
	if len(c.Approvers) == 0 {
		return nil, errors.New("page: no approvers")
	}
	for _, a := range c.Approvers {
		if !approvers.ValidName(a) {
			return nil, errors.New("page: an approver name is not valid")
		}
	}
	if c.ProxyOnly && len(c.TrustedProxies) == 0 {
		return nil, errors.New("page: proxy-only without trusted proxies")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("page: the public URL must be an origin (scheme://host[:port])")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.RateLimitPerMin <= 0 {
		c.RateLimitPerMin = defaultRatePerMin
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	h := &handler{
		c: c, origin: strings.ToLower(u.Scheme + "://" + u.Host), host: strings.ToLower(u.Hostname()), port: port,
		limiter: transport.NewLimiter(c.RateLimitPerMin, c.Now), cop: http.NewCrossOriginProtection(),
		approvers: slices.Sorted(slices.Values(c.Approvers)),
	}
	h.tmpl, err = template.New("page").Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// NewServer returns the approval listener's server on addr, serving TLS 1.2
// or later with cert when it is not nil.
func NewServer(c Config, addr string, cert *tls.Certificate) (*http.Server, error) {
	h, err := New(c)
	if err != nil {
		return nil, err
	}
	logger := c.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	srv := &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout,
		IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if cert != nil {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}}
	}
	return srv, nil
}

func (h *handler) refused(r *http.Request, reason, id, approver string) {
	attrs := []any{slog.String("reason", reason), slog.String("client", transport.ClientKey(r, h.c.TrustedProxies).String())}
	if id != "" {
		attrs = append(attrs, slog.String("approval_id", id))
	}
	attrs = append(attrs, slog.String("approver", approver))
	h.c.Logger.Warn("approval attempt refused", attrs...)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w.Header())
	if h.c.ProxyOnly {
		peer := netip.Addr{}
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			peer = ap.Addr().WithZone("").Unmap()
		}
		if !peer.IsValid() || !slices.ContainsFunc(h.c.TrustedProxies, func(p netip.Prefix) bool { return p.Contains(peer) }) {
			attrs := []any{slog.String("reason", "peer_not_proxy"), slog.String("client", peerKey(peer))}
			h.c.Logger.Warn("approval attempt refused", attrs...)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden\n"))
			return
		}
	}
	key := transport.ClientKey(r, h.c.TrustedProxies)
	if ok, wait, first := h.limiter.Allow(key); !ok {
		if first {
			h.c.Logger.Warn("request refused", slog.String("reason", auth.CodeRateLimited), slog.String("client", key.String()), slog.String("listener", "approval"))
		}
		auth.RetryAfter(w, wait)
		h.render(w, http.StatusTooManyRequests, view{Message: "Too many requests. Wait a minute and try again."})
		return
	}
	if !h.hostMatches(r.Host) {
		h.refused(r, "host", "", "")
		h.render(w, http.StatusMisdirectedRequest, view{Message: "This request was not addressed to this page's configured origin; nothing was done."})
		return
	}
	if vals := r.Header.Values("Origin"); len(vals) > 1 || len(vals) == 1 && strings.ToLower(vals[0]) != h.origin {
		h.refused(r, "cross_origin", "", "")
		h.render(w, http.StatusForbidden, view{Message: "Cross-origin request refused; nothing was done."})
		return
	}
	if err := h.cop.Check(r); err != nil {
		h.refused(r, "cross_origin", "", "")
		h.render(w, http.StatusForbidden, view{Message: "Cross-origin request refused; nothing was done."})
		return
	}
	h.route(w, r)
}

func peerKey(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return netip.Prefix{}.String()
	case a.Is4():
		return netip.PrefixFrom(a, 32).String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// hostMatches compares the request's Host with the configured origin's
// host and port (a missing port is the scheme's default).
func (h *handler) hostMatches(hostport string) bool {
	host, port := hostport, ""
	if strings.HasPrefix(hostport, "[") || strings.Count(hostport, ":") == 1 {
		hh, pp, err := net.SplitHostPort(hostport)
		if err != nil {
			if !strings.HasPrefix(hostport, "[") || !strings.HasSuffix(hostport, "]") {
				return false
			}
			hh, pp = hostport[1:len(hostport)-1], ""
		}
		host, port = hh, pp
	}
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[strings.HasPrefix(h.origin, "https:")]
	}
	return host != "" && strings.EqualFold(strings.Trim(host, "[]"), strings.Trim(h.host, "[]")) && port == h.port
}

func (h *handler) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/" {
		if !methodIs(w, r, http.MethodGet, http.MethodHead) {
			h.render(w, http.StatusMethodNotAllowed, view{Message: "Method not allowed."})
			return
		}
		h.bookmark(w, r)
		return
	}
	rest, ok := strings.CutPrefix(p, "/approvals/")
	if !ok || rest == "" {
		h.notFound(w)
		return
	}
	id, verb, hasVerb := strings.Cut(rest, "/")
	switch {
	case !hasVerb:
		if !methodIs(w, r, http.MethodGet, http.MethodHead) {
			h.render(w, http.StatusMethodNotAllowed, view{Message: "Method not allowed."})
			return
		}
		h.recordPage(w, id)
	case verb == "approve" || verb == "decline":
		if !methodIs(w, r, http.MethodPost) {
			h.render(w, http.StatusMethodNotAllowed, view{Message: "Method not allowed: decisions are made with the form on the approval page."})
			return
		}
		h.decide(w, r, id, verb == "approve")
	default:
		h.notFound(w)
	}
}

func methodIs(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	if slices.Contains(allowed, r.Method) {
		return true
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	return false
}

func (h *handler) notFound(w http.ResponseWriter) {
	h.render(w, http.StatusNotFound, view{Message: "Not found."})
}

func (h *handler) bookmark(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !q.Has("id") {
		h.render(w, http.StatusOK, view{Bookmark: true})
		return
	}
	id := strings.ToLower(strings.TrimSpace(q.Get("id")))
	if len(q["id"]) != 1 || !approval.ParseID(id) {
		h.render(w, http.StatusBadRequest, view{Bookmark: true, Message: "That is not an approval id: 26 letters a–z and digits 2–7."})
		return
	}
	w.Header().Set("Location", "/approvals/"+id)
	w.WriteHeader(http.StatusSeeOther)
}

func (h *handler) recordPage(w http.ResponseWriter, id string) {
	rec, ok := h.lookup(id)
	if !ok {
		h.render(w, http.StatusNotFound, view{Message: noRecord})
		return
	}
	h.render(w, http.StatusOK, view{Record: h.recView(rec)})
}

const noRecord = "No approval with this id: it expired, was never issued, or the server restarted."

func (h *handler) lookup(id string) (approval.Record, bool) {
	if !approval.ParseID(id) {
		return approval.Record{}, false
	}
	return h.c.Store.Get(id)
}

// Generic answers to a decision that was not accepted.
const (
	msgCode = "Code not accepted."
	msgCSRF = "Request not accepted: reload the approval page and try again."
)

func (h *handler) decide(w http.ResponseWriter, r *http.Request, id string, approve bool) {
	if r.ContentLength > MaxBodyBytes {
		h.render(w, http.StatusRequestEntityTooLarge, view{Message: "Request too large."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		h.render(w, http.StatusBadRequest, view{Message: "Bad request."})
		return
	}
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			h.render(w, http.StatusRequestEntityTooLarge, view{Message: "Request too large."})
			return
		}
		h.render(w, http.StatusBadRequest, view{Message: "Bad request."})
		return
	}
	for _, v := range r.PostForm {
		if len(v) != 1 {
			h.render(w, http.StatusBadRequest, view{Message: "Bad request."})
			return
		}
	}
	rec, ok := h.lookup(id)
	if !ok {
		h.refused(r, "unknown", "", "")
		h.render(w, http.StatusNotFound, view{Message: noRecord})
		return
	}
	if tok := r.PostForm.Get("csrf_token"); tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(rec.CSRFToken)) != 1 {
		h.refused(r, "csrf_token", rec.ID, "")
		h.render(w, http.StatusForbidden, view{Message: msgCSRF})
		return
	}
	switch rec.Status {
	case approval.StatusPending:
	case approval.StatusExpired:
		h.refused(r, "expired", rec.ID, "")
		h.render(w, http.StatusGone, view{Record: h.recView(rec)})
		return
	default:
		h.refused(r, "not_pending", rec.ID, "")
		h.render(w, http.StatusConflict, view{Record: h.recView(rec)})
		return
	}
	name, logName := h.approvers[0], h.approvers[0]
	if len(h.approvers) > 1 {
		name = r.PostForm.Get("approver")
		logName = ""
		if approvers.ValidName(name) {
			logName = name
		}
	}
	out := h.c.Verifier.Verify(name, r.PostForm.Get("code"))
	if out.Result != totp.Accepted {
		h.refused(r, out.Result.String(), rec.ID, logName)
		if out.Lockout != nil && out.Lockout.Started && logName != "" {
			h.c.Logger.Warn("approval lockout", slog.String("approver", logName),
				slog.String("until", out.Lockout.Until.UTC().Format(time.RFC3339)), slog.Int("consecutive", out.Lockout.Consecutive))
			if h.c.OnLockout != nil {
				h.c.OnLockout(logName, out.Lockout.Until, out.Lockout.Consecutive)
			}
		}
		h.render(w, http.StatusForbidden, view{Record: h.recView(rec), Message: msgCode})
		return
	}
	decided, err := h.c.Store.Decide(rec.ID, approve, name, transport.ClientAddr(r, h.c.TrustedProxies).String())
	switch {
	case errors.Is(err, approval.ErrExpired):
		h.refused(r, "expired", rec.ID, logName)
		h.render(w, http.StatusGone, view{Message: "This approval expired before the decision; nothing was done."})
		return
	case err != nil:
		h.refused(r, "not_pending", rec.ID, logName)
		h.render(w, http.StatusConflict, view{Message: "This approval was already decided."})
		return
	}
	h.render(w, http.StatusOK, view{Record: h.recView(decided)})
}

// --- Rendering --------------------------------------------------------------------

type view struct {
	Origin    string
	Message   string
	Bookmark  bool
	Record    *recView
	Multi     bool
	Approvers []string
}

type fieldView struct{ Key, Value string }

type recView struct {
	ID, ToolTitle, Tool, Target, TargetHost, Principal, Description, Expires, Status string
	Args, Preview                                                                    []fieldView
	CSRF                                                                             string
	Open                                                                             bool
	Decision                                                                         string
}

func fields(fs []approval.Field) []fieldView {
	out := make([]fieldView, 0, len(fs))
	for _, f := range fs {
		out = append(out, fieldView{Key: approval.Visible(f.Key), Value: approval.Visible(f.Value)})
	}
	return out
}

// recView renders a record: every string through approval.Visible, so
// control and bidi characters show as escapes; html/template escapes the
// markup.
func (h *handler) recView(r approval.Record) *recView {
	v := &recView{
		ID: r.ID, ToolTitle: approval.Visible(r.ToolTitle), Tool: approval.Visible(r.Tool), Target: approval.Visible(r.Target),
		TargetHost: approval.Visible(r.TargetHost), Principal: approval.Visible(r.Principal), Description: approval.Visible(r.Description),
		Expires: r.ExpiresAt.UTC().Format(time.RFC3339), Status: string(r.Status), Args: fields(r.Args), Preview: fields(r.Preview),
	}
	switch r.Status {
	case approval.StatusPending:
		v.Open, v.CSRF = true, r.CSRFToken
	case approval.StatusApproved, approval.StatusUsed:
		v.Decision = "Approved by " + approval.Visible(r.Approver) + "."
	case approval.StatusDeclined:
		v.Decision = "Declined by " + approval.Visible(r.Approver) + "."
	case approval.StatusExpired:
		v.Decision = "This approval has expired; nothing was done."
	}
	return v
}

func (h *handler) render(w http.ResponseWriter, status int, v view) {
	v.Origin = h.origin
	v.Multi = len(h.approvers) > 1
	v.Approvers = h.approvers
	var b bytes.Buffer
	if err := h.tmpl.Execute(&b, v); err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error\n"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

// pageTemplate is the only markup the listener serves. Nothing in it loads
// anything; its one style element is pageCSS.
const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>shell-mcp approval</title>
<style>` + pageCSS + `</style>
</head>
<body>
<div class="banner">
<p><strong>Approval page for shell-mcp at {{.Origin}}.</strong> Check that your address bar shows exactly this origin. Open approvals only from your bookmark or this server's own notification, never from a link in a chat.</p>
<p>This page can be opened on any device; only the code must come from your authenticator.</p>
</div>
<main>
{{if .Message}}<p class="msg">{{.Message}}</p>
{{end}}{{if .Bookmark}}<h1>Open an approval</h1>
<form method="get" action="/">
<label>Approval id <input name="id" required minlength="26" maxlength="26" autocomplete="off" autocapitalize="none" spellcheck="false"></label>
<button type="submit">Open</button>
</form>
{{end}}{{with .Record}}<h1>Approval requested</h1>
<p class="description">{{.Description}}</p>
<table class="meta">
<tr><th>Tool</th><td class="v">{{.ToolTitle}} ({{.Tool}})</td></tr>
<tr><th>Target</th><td class="v">{{.Target}} ({{.TargetHost}})</td></tr>
<tr><th>Principal</th><td class="v">{{.Principal}}</td></tr>
<tr><th>Expires</th><td class="v">{{.Expires}}</td></tr>
<tr><th>Approval id</th><td class="v">{{.ID}}</td></tr>
<tr><th>Status</th><td class="v">{{.Status}}</td></tr>
</table>
<h2>Arguments</h2>
<table class="args">
{{range .Args}}<tr><th>{{.Key}}</th><td class="v">{{.Value}}</td></tr>
{{end}}</table>
<h2>Preview</h2>
<table class="preview">
{{range .Preview}}<tr><th>{{.Key}}</th><td class="v">{{.Value}}</td></tr>
{{end}}</table>
{{if .Open}}<form method="post" action="/approvals/{{.ID}}/approve">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
{{if $.Multi}}<label>Approver <select name="approver">{{range $.Approvers}}<option>{{.}}</option>{{end}}</select></label>
{{end}}<label>Code from your authenticator <input name="code" required inputmode="numeric" autocomplete="one-time-code" maxlength="7"></label>
<button type="submit">Approve</button>
<button type="submit" formaction="/approvals/{{.ID}}/decline">Decline</button>
</form>
{{else}}<p class="status">{{.Decision}}</p>
{{end}}{{end}}</main>
</body>
</html>
`
