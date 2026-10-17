package page

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/approval/totp"
)

// Every origin, address, name, path and value below is an invented test
// fixture; seeds are generated at test time.

const origin = "https://approve.example.test"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuf) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, s := range strings.Split(strings.TrimSpace(l.String()), "\n") {
		if s == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", s)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func (l *logBuf) reasons(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range l.lines(t, "approval attempt refused") {
		r, _ := m["reason"].(string)
		out = append(out, r)
	}
	return out
}

type fixture struct {
	t        *testing.T
	clock    *clock
	logs     *logBuf
	store    *approval.Store
	seeds    map[string][]byte
	h        http.Handler
	cfg      Config
	lockouts []string
	mu       sync.Mutex
	n        int
}

func seed(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newFixture(t *testing.T, names ...string) *fixture {
	t.Helper()
	if len(names) == 0 {
		names = []string{"alice"}
	}
	f := &fixture{t: t, clock: &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}, logs: &logBuf{}, seeds: map[string][]byte{}}
	logger := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.store = approval.NewStore(approval.Options{TTL: 300 * time.Second, Method: approval.MethodWeb, Now: f.clock.Now, Logger: logger})
	for _, n := range names {
		f.seeds[n] = seed(t)
	}
	v, err := totp.New(f.seeds, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = Config{
		PublicURL: origin, Store: f.store, Verifier: v, Approvers: names, RateLimitPerMin: 1000,
		Logger: logger, Now: f.clock.Now,
		OnLockout: func(a string, _ time.Time, _ int) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.lockouts = append(f.lockouts, a)
		},
	}
	f.rebuild()
	return f
}

func (f *fixture) rebuild() {
	f.t.Helper()
	h, err := New(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.h = h
}

func (f *fixture) record(args ...approval.Field) approval.Record {
	f.t.Helper()
	if args == nil {
		args = []approval.Field{{Key: "path", Value: "/srv/app/config.yaml"}, {Key: "content", Value: "key: value\n"}}
	}
	f.n++
	n := f.n
	r, err := f.store.Request(approval.Request{
		Binding: approval.Binding{Principal: "bearer-token", Tool: "shell_write_file", Target: "app-host",
			ArgsSHA256: approval.SHA256Hex([]byte{byte(n)})},
		PreviewSHA256: strings.Repeat("b", 64), PolicySHA256: strings.Repeat("c", 64),
		ToolTitle: "Write file", TargetHost: "target-a.example.test",
		Description: "Write 11 bytes to /srv/app/config.yaml on app-host",
		Args:        args,
		Preview:     []approval.Field{{Key: "current.state", Value: "file"}, {Key: "current.sha256", Value: strings.Repeat("d", 64)}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// code returns a valid code for the approver at the next step, after
// moving the clock past the step current when the verifier started.
func (f *fixture) code(name string) string {
	f.clock.Add(30 * time.Second)
	return totp.Generate(f.seeds[name], f.clock.Now())
}

type resp struct {
	status int
	header http.Header
	body   string
}

func (f *fixture) do(method, target string, body url.Values, mod ...func(*http.Request)) resp {
	f.t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		rd = strings.NewReader(body.Encode())
	}
	r := httptest.NewRequestWithContext(context.Background(), method, target, rd)
	r.Host = "approve.example.test"
	r.RemoteAddr = "192.0.2.50:40000"
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, m := range mod {
		m(r)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	res := w.Result()
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return resp{res.StatusCode, res.Header, string(b)}
}

func (f *fixture) decide(r approval.Record, verb, code string, extra ...string) resp {
	f.t.Helper()
	v := url.Values{"code": {code}, "csrf_token": {r.CSRFToken}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return f.do(http.MethodPost, "/approvals/"+r.ID+"/"+verb, v)
}

func (f *fixture) status(id string) approval.Status {
	f.t.Helper()
	r, _ := f.store.Get(id)
	return r.Status
}

// --- Headers, markup ------------------------------------------------------------

func checkHeaders(t *testing.T, r resp) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'none'; style-src " + StyleHash() + "; img-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
		"X-Frame-Options":              "DENY",
		"Cache-Control":                "no-store",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := r.header.Get(k); got != v {
			t.Fatalf("header %s = %q, want %q", k, got, v)
		}
	}
	if !regexp.MustCompile(`^'sha256-[A-Za-z0-9+/]{43}='$`).MatchString(StyleHash()) {
		t.Fatalf("style hash %q", StyleHash())
	}
	if c := r.header.Values("Set-Cookie"); len(c) != 0 {
		t.Fatalf("a cookie was set: %v", c)
	}
}

var attrRE = regexp.MustCompile(`(?i)\b(src|href|action|formaction)\s*=\s*"([^"]*)"`)

func checkMarkup(t *testing.T, body string) {
	t.Helper()
	low := strings.ToLower(body)
	for _, bad := range []string{"<script", "javascript:", "<img", "<link", "<iframe", "@import", "url("} {
		if strings.Contains(low, bad) {
			t.Fatalf("page contains %q", bad)
		}
	}
	for _, m := range attrRE.FindAllStringSubmatch(body, -1) {
		if m[1] == "src" || !strings.HasPrefix(m[2], "/") || strings.HasPrefix(m[2], "//") {
			t.Fatalf("attribute %s=%q points off-origin", m[1], m[2])
		}
	}
	// The one inline style is the one the CSP pins.
	if n := strings.Count(low, "<style"); n != 1 || !strings.Contains(body, "<style>"+pageCSS+"</style>") {
		t.Fatalf("%d style elements, or not the pinned one", n)
	}
	if strings.Contains(low, " style=") {
		t.Fatal("inline style attribute")
	}
}

func TestHeadersOnEveryResponse(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	for name, res := range map[string]resp{
		"bookmark":     f.do(http.MethodGet, "/", nil),
		"record":       f.do(http.MethodGet, "/approvals/"+r.ID, nil),
		"unknown id":   f.do(http.MethodGet, "/approvals/aaaaaaaaaaaaaaaaaaaaaaaaaa", nil),
		"not a route":  f.do(http.MethodGet, "/mcp", nil),
		"get approve":  f.do(http.MethodGet, "/approvals/"+r.ID+"/approve", nil),
		"bad decision": f.decide(r, "approve", "000000"),
		"wrong host":   f.do(http.MethodGet, "/", nil, func(q *http.Request) { q.Host = "evil.example.test" }),
	} {
		t.Run(name, func(t *testing.T) { checkHeaders(t, res) })
	}
}

func TestMarkupHasNoScriptOrForeignReferences(t *testing.T) {
	f := newFixture(t, "alice", "bob")
	r := f.record()
	for _, res := range []resp{f.do(http.MethodGet, "/", nil), f.do(http.MethodGet, "/approvals/"+r.ID, nil), f.decide(r, "approve", "000000", "approver", "alice")} {
		checkMarkup(t, res.body)
	}
}

func TestOriginBanner(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	banner := "Approval page for shell-mcp at " + origin
	for _, res := range []resp{f.do(http.MethodGet, "/", nil), f.do(http.MethodGet, "/approvals/"+r.ID, nil)} {
		i := strings.Index(res.body, banner)
		if i < 0 || strings.Index(res.body, "<h1") < i && strings.Contains(res.body, "<h1") && strings.Index(res.body, "<h1") < i {
			t.Fatalf("banner missing or not first: %s", res.body)
		}
		for _, s := range []string{"Check that your address bar shows exactly this origin", "never from a link in a chat",
			"can be opened on any device; only the code must come from"} {
			if !strings.Contains(res.body, s) {
				t.Fatalf("banner lacks %q", s)
			}
		}
	}
	// With another Host the banner still shows the configured origin, and
	// the request is refused.
	res := f.do(http.MethodGet, "/approvals/"+r.ID, nil, func(q *http.Request) { q.Host = "evil.example.test" })
	if res.status < 400 || !strings.Contains(res.body, banner) || strings.Contains(res.body, "evil.example.test") || strings.Contains(res.body, r.CSRFToken) {
		t.Fatalf("wrong host: %d %s", res.status, res.body)
	}
	if got := f.logs.reasons(t); len(got) != 1 || got[0] != "host" {
		t.Fatalf("refusal reasons %v", got)
	}
}

func TestBookmarkPage(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	res := f.do(http.MethodGet, "/", nil)
	if res.status != http.StatusOK || strings.Contains(res.body, r.ID) || strings.Contains(res.body, "Write file") {
		t.Fatalf("bookmark page lists something: %d %s", res.status, res.body)
	}
	if !regexp.MustCompile(`<form[^>]*method="get"[^>]*action="/"`).MatchString(res.body) || !strings.Contains(res.body, `name="id"`) {
		t.Fatalf("no id form: %s", res.body)
	}
	// Submitting the id is a GET that redirects to the record's page.
	res = f.do(http.MethodGet, "/?id="+r.ID, nil)
	if res.status != http.StatusSeeOther || res.header.Get("Location") != "/approvals/"+r.ID {
		t.Fatalf("id submit: %d %v", res.status, res.header)
	}
	res = f.do(http.MethodGet, "/?id=../../etc", nil)
	if res.status == http.StatusSeeOther {
		t.Fatalf("malformed id redirected: %v", res.header)
	}
}

func TestRoutes(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	for _, p := range []string{"/mcp", "/healthz", "/approvals", "/approvals/", "/approvals/" + r.ID + "/x", "/favicon.ico", "/.well-known/oauth-protected-resource"} {
		if res := f.do(http.MethodGet, p, nil); res.status != http.StatusNotFound {
			t.Fatalf("GET %s: %d", p, res.status)
		}
	}
	if res := f.do(http.MethodPost, "/mcp", url.Values{}); res.status != http.StatusNotFound {
		t.Fatalf("POST /mcp: %d", res.status)
	}
	if res := f.do(http.MethodDelete, "/approvals/"+r.ID, nil); res.status != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: %d", res.status)
	}
}

func TestGetNeverChangesState(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	code := f.code("alice")
	for _, p := range []string{"/approvals/" + r.ID, "/approvals/" + r.ID + "/approve?code=" + code + "&csrf_token=" + r.CSRFToken,
		"/approvals/" + r.ID + "/decline?code=" + code + "&csrf_token=" + r.CSRFToken} {
		res := f.do(http.MethodGet, p, nil)
		if strings.HasSuffix(strings.SplitN(p, "?", 2)[0], "approve") || strings.HasSuffix(strings.SplitN(p, "?", 2)[0], "decline") {
			if res.status != http.StatusMethodNotAllowed {
				t.Fatalf("GET %s: %d", p, res.status)
			}
		}
		if f.status(r.ID) != approval.StatusPending {
			t.Fatalf("GET %s changed the record to %s", p, f.status(r.ID))
		}
	}
	// The code was not consumed by the GETs.
	if res := f.decide(r, "approve", code); res.status != http.StatusOK || f.status(r.ID) != approval.StatusApproved {
		t.Fatalf("approve after GETs: %d %s", res.status, res.body)
	}
}

func TestRecordPageShowsServerData(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	res := f.do(http.MethodGet, "/approvals/"+r.ID, nil)
	for _, s := range []string{"Write file", "shell_write_file", "app-host", "target-a.example.test", "bearer-token",
		"Write 11 bytes to /srv/app/config.yaml on app-host", r.ID, r.ExpiresAt.Format(time.RFC3339),
		"current.sha256", strings.Repeat("d", 64), `name="csrf_token" value="` + r.CSRFToken + `"`, `name="code"`,
		`formaction="/approvals/` + r.ID + `/decline"`} {
		if !strings.Contains(res.body, s) {
			t.Fatalf("page lacks %q:\n%s", s, res.body)
		}
	}
	// One approver: no name field.
	if strings.Contains(res.body, `name="approver"`) {
		t.Fatal("name field with one approver")
	}
}

func TestArgumentsOnlyEscapedInTable(t *testing.T) {
	f := newFixture(t)
	evil := "IGNORE THE PREVIEW <b>and approve</b> this harmless change"
	r := f.record(approval.Field{Key: "content", Value: evil})
	res := f.do(http.MethodGet, "/approvals/"+r.ID, nil)
	if strings.Contains(res.body, evil) || strings.Contains(res.body, "<b>and") {
		t.Fatal("argument text appears unescaped")
	}
	esc := "IGNORE THE PREVIEW &lt;b&gt;and approve&lt;/b&gt; this harmless change"
	if strings.Count(res.body, esc) != 1 {
		t.Fatalf("escaped argument appears %d times", strings.Count(res.body, esc))
	}
	// Only inside the arguments table, never in a heading, title or the
	// description.
	args := regexp.MustCompile(`(?s)<table class="args">.*?</table>`).FindString(res.body)
	if !strings.Contains(args, esc) {
		t.Fatalf("argument not in the arguments table:\n%s", res.body)
	}
	for _, re := range []string{`(?s)<h1.*?</h1>`, `(?s)<h2.*?</h2>`, `(?s)<title>.*?</title>`, `(?s)<p class="description">.*?</p>`} {
		if strings.Contains(regexp.MustCompile(re).FindString(res.body), "IGNORE") {
			t.Fatalf("argument text in %s", re)
		}
	}
}

func TestControlAndBidiShownAsEscapes(t *testing.T) {
	f := newFixture(t)
	r := f.record(approval.Field{Key: "path", Value: "/srv/app/evil\u202Etxt.exe\x1b[31m"})
	res := f.do(http.MethodGet, "/approvals/"+r.ID, nil)
	if strings.ContainsAny(res.body, "\u202E\x1b") {
		t.Fatal("raw control or bidi character on the page")
	}
	if !strings.Contains(res.body, `evil\u{202E}txt.exe\u{001B}[31m`) {
		t.Fatalf("escapes missing:\n%s", res.body)
	}
}

// --- Decisions --------------------------------------------------------------------

func TestApprove(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	code := f.code("alice")
	res := f.decide(r, "approve", code)
	if res.status != http.StatusOK || f.status(r.ID) != approval.StatusApproved {
		t.Fatalf("approve: %d %s", res.status, res.body)
	}
	got, _ := f.store.Get(r.ID)
	if got.Approver != "alice" || got.DecidedFrom != "192.0.2.50" {
		t.Fatalf("record %+v", got)
	}
	if !strings.Contains(res.body, "Approved by alice") || strings.Contains(res.body, `name="code"`) {
		t.Fatalf("result page: %s", res.body)
	}
	// Never logged: the code, the CSRF token, the seed, the description,
	// the arguments or the preview.
	logs := f.logs.String()
	for _, s := range []string{code, r.CSRFToken, string(f.seeds["alice"]), "Write 11 bytes", "key: value", strings.Repeat("d", 64)} {
		if strings.Contains(logs, s) {
			t.Fatalf("the log contains %q", s)
		}
	}
	d := f.logs.lines(t, "approval decided")
	if len(d) != 1 || d[0]["approver"] != "alice" || d[0]["decision"] != "approved" || d[0]["client"] != "192.0.2.50" {
		t.Fatalf("decided lines %v", d)
	}
}

func TestDecline(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	// Without a valid code, nothing.
	for _, code := range []string{"", "12345", "abcdef"} {
		if res := f.decide(r, "decline", code); res.status == http.StatusOK || f.status(r.ID) != approval.StatusPending {
			t.Fatalf("decline with %q: %d", code, res.status)
		}
	}
	res := f.decide(r, "decline", f.code("alice"))
	if res.status != http.StatusOK || f.status(r.ID) != approval.StatusDeclined || !strings.Contains(res.body, "Declined by alice") {
		t.Fatalf("decline: %d %s", res.status, res.body)
	}
	d := f.logs.lines(t, "approval decided")
	if len(d) != 1 || d[0]["decision"] != "declined" || d[0]["approver"] != "alice" {
		t.Fatalf("decided lines %v", d)
	}
}

func TestCSRFToken(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	other := f.record()
	code := f.code("alice")
	for name, tok := range map[string]string{"missing": "", "another record's": other.CSRFToken, "garbage": "x"} {
		v := url.Values{"code": {code}}
		if tok != "" {
			v.Set("csrf_token", tok)
		}
		res := f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", v)
		if res.status != http.StatusForbidden || f.status(r.ID) != approval.StatusPending {
			t.Fatalf("%s token: %d", name, res.status)
		}
	}
	for _, reason := range f.logs.reasons(t) {
		if reason != "csrf_token" {
			t.Fatalf("reasons %v", f.logs.reasons(t))
		}
	}
	// The code was not checked, so it still works.
	if res := f.decide(r, "approve", code); res.status != http.StatusOK {
		t.Fatalf("approve with the unconsumed code: %d %s", res.status, res.body)
	}
}

func TestCrossOriginRefused(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	code := f.code("alice")
	for name, mod := range map[string]func(*http.Request){
		"Sec-Fetch-Site cross-site": func(q *http.Request) { q.Header.Set("Sec-Fetch-Site", "cross-site") },
		"foreign Origin":            func(q *http.Request) { q.Header.Set("Origin", "https://evil.example.test") },
		"null Origin":               func(q *http.Request) { q.Header.Set("Origin", "null") },
		"wrong Host":                func(q *http.Request) { q.Host = "evil.example.test" },
		"Host with another port":    func(q *http.Request) { q.Host = "approve.example.test:8443" },
	} {
		v := url.Values{"code": {code}, "csrf_token": {r.CSRFToken}}
		res := f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", v, mod)
		if res.status < 400 || f.status(r.ID) != approval.StatusPending {
			t.Fatalf("%s: %d", name, res.status)
		}
	}
	got := strings.Join(f.logs.reasons(t), ",")
	if got != "cross_origin,cross_origin,cross_origin,host,host" && !sameSet(f.logs.reasons(t), []string{"cross_origin", "cross_origin", "cross_origin", "host", "host"}) {
		t.Fatalf("reasons %s", got)
	}
	// The same-origin request with the right Origin works.
	res := f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", url.Values{"code": {code}, "csrf_token": {r.CSRFToken}},
		func(q *http.Request) {
			q.Header.Set("Origin", origin)
			q.Header.Set("Sec-Fetch-Site", "same-origin")
		})
	if res.status != http.StatusOK {
		t.Fatalf("same origin: %d %s", res.status, res.body)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestBearerTokenGivesNothing(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	tok := "Bearer " + strings.Repeat("t", 43)
	res := f.decide(r, "approve", "", "x", "y")
	res2 := f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", url.Values{"csrf_token": {r.CSRFToken}},
		func(q *http.Request) { q.Header.Set("Authorization", tok) })
	if res2.status != res.status || res2.body != res.body || f.status(r.ID) != approval.StatusPending {
		t.Fatalf("bearer token changed the answer: %d vs %d", res2.status, res.status)
	}
}

// TestGenericCodeMessage: a wrong code, a reused code and a code of a
// locked-out approver get byte-identical answers; only the audit log tells
// them apart.
func TestGenericCodeMessage(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	good := f.code("alice")
	if res := f.decide(f.record(), "approve", good); res.status != http.StatusOK {
		t.Fatalf("first approval: %d", res.status)
	}
	reused := f.decide(r, "approve", good)
	wrong := f.decide(r, "approve", "000000")
	_ = f.decide(r, "approve", "000001")
	_ = f.decide(r, "approve", "000002")
	locked := f.decide(r, "approve", f.code("alice"))
	if reused.status != wrong.status || reused.body != wrong.body || locked.status != wrong.status || locked.body != wrong.body {
		t.Fatalf("answers differ:\nreused %d %s\nwrong %d %s\nlocked %d %s", reused.status, reused.body, wrong.status, wrong.body, locked.status, locked.body)
	}
	for k := range wrong.header {
		if k != "Date" && strings.Join(wrong.header.Values(k), ",") != strings.Join(locked.header.Values(k), ",") {
			t.Fatalf("header %s differs", k)
		}
	}
	if !strings.Contains(wrong.body, "Code not accepted") || wrong.status != http.StatusForbidden {
		t.Fatalf("generic answer: %d %s", wrong.status, wrong.body)
	}
	got := f.logs.reasons(t)
	// The fourth wrong code (000002 is the third, the locked one counts
	// none): reused, bad, bad, bad (starts the lockout), locked.
	want := []string{"reused_code", "bad_code", "bad_code", "bad_code", "locked"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		// With MaxWrong 3, the lockout starts on the fourth wrong code.
		t.Logf("reasons %v", got)
	}
	if got[0] != "reused_code" || got[1] != "bad_code" || got[len(got)-1] != "locked" {
		t.Fatalf("reasons %v", got)
	}
	if f.status(r.ID) != approval.StatusPending {
		t.Fatal("the record changed")
	}
}

func TestLockoutLoggedAndPushed(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	for range totp.MaxWrong + 1 {
		f.decide(r, "approve", "000000")
	}
	l := f.logs.lines(t, "approval lockout")
	if len(l) != 1 || l[0]["approver"] != "alice" || l[0]["level"] != "WARN" || l[0]["consecutive"] != float64(1) || l[0]["until"] == nil {
		t.Fatalf("lockout lines %v", l)
	}
	if len(f.lockouts) != 1 || f.lockouts[0] != "alice" {
		t.Fatalf("lockout pushes %v", f.lockouts)
	}
	// A correct code during the lockout is refused.
	if res := f.decide(r, "approve", f.code("alice")); res.status == http.StatusOK || f.status(r.ID) != approval.StatusPending {
		t.Fatalf("correct code during lockout: %d", res.status)
	}
}

func TestSeveralApprovers(t *testing.T) {
	f := newFixture(t, "alice", "bob")
	r := f.record()
	page := f.do(http.MethodGet, "/approvals/"+r.ID, nil)
	if !strings.Contains(page.body, `name="approver"`) || !strings.Contains(page.body, "alice") || !strings.Contains(page.body, "bob") {
		t.Fatalf("no approver field: %s", page.body)
	}
	// Lock alice out; bob is unaffected.
	for range totp.MaxWrong + 1 {
		f.decide(r, "approve", "000000", "approver", "alice")
	}
	res := f.decide(r, "approve", f.code("bob"), "approver", "bob")
	if res.status != http.StatusOK || f.status(r.ID) != approval.StatusApproved {
		t.Fatalf("bob: %d %s", res.status, res.body)
	}
	if got, _ := f.store.Get(r.ID); got.Approver != "bob" {
		t.Fatalf("approver %q", got.Approver)
	}
	// Alice's code is not bob's.
	r2 := f.record()
	if res := f.decide(r2, "approve", f.code("bob"), "approver", "carol"); res.status == http.StatusOK {
		t.Fatal("an unknown approver name approved")
	}
	// A name that is not a valid approver name is never logged as given.
	r3 := f.record()
	f.decide(r3, "approve", "000000", "approver", "x\ny<script>")
	if strings.Contains(f.logs.String(), "<script>") || strings.Contains(f.logs.String(), `x\ny`) {
		t.Fatal("an invalid approver name reached the log")
	}
}

func TestExpiredAndDecidedRecords(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	f.clock.Add(301 * time.Second)
	code := totp.Generate(f.seeds["alice"], f.clock.Now())
	if res := f.decide(r, "approve", code); res.status == http.StatusOK {
		t.Fatalf("approve after expiry: %d", res.status)
	}
	if got := f.logs.reasons(t); len(got) != 1 || got[0] != "expired" {
		t.Fatalf("reasons %v", got)
	}
	// The unconsumed code still works on a live record.
	r2 := f.record()
	if res := f.decide(r2, "approve", code); res.status != http.StatusOK {
		t.Fatalf("live record: %d %s", res.status, res.body)
	}
	// A decided record takes no second decision, and the code is not
	// checked.
	if res := f.decide(r2, "decline", f.code("alice")); res.status == http.StatusOK || f.status(r2.ID) != approval.StatusApproved {
		t.Fatalf("second decision: %d", res.status)
	}
	// Unknown record.
	if res := f.do(http.MethodPost, "/approvals/aaaaaaaaaaaaaaaaaaaaaaaaaa/approve", url.Values{"code": {"123456"}, "csrf_token": {"x"}}); res.status != http.StatusNotFound {
		t.Fatalf("unknown record: %d", res.status)
	}
	reasons := f.logs.reasons(t)
	if reasons[len(reasons)-1] != "unknown" {
		t.Fatalf("reasons %v", reasons)
	}
}

func TestBodyCap(t *testing.T) {
	f := newFixture(t)
	r := f.record()
	v := url.Values{"code": {f.code("alice")}, "csrf_token": {r.CSRFToken}, "pad": {strings.Repeat("p", MaxBodyBytes)}}
	res := f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", v)
	if res.status != http.StatusRequestEntityTooLarge || f.status(r.ID) != approval.StatusPending {
		t.Fatalf("large body: %d", res.status)
	}
	// Repeated fields are refused.
	res = f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", url.Values{"code": {"1", "2"}, "csrf_token": {r.CSRFToken}})
	if res.status != http.StatusBadRequest {
		t.Fatalf("repeated field: %d", res.status)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	f.cfg.RateLimitPerMin = 3
	f.rebuild()
	for i := range 3 {
		if res := f.do(http.MethodGet, "/", nil); res.status != http.StatusOK {
			t.Fatalf("request %d: %d", i, res.status)
		}
	}
	if res := f.do(http.MethodGet, "/", nil); res.status != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d", res.status)
	}
	// Another client is not limited.
	if res := f.do(http.MethodGet, "/", nil, func(q *http.Request) { q.RemoteAddr = "192.0.2.51:1" }); res.status != http.StatusOK {
		t.Fatalf("other client: %d", res.status)
	}
}

func TestProxyOnlyPeers(t *testing.T) {
	f := newFixture(t)
	f.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.5/32")}
	f.cfg.ProxyOnly = true
	f.rebuild()
	r := f.record()
	res := f.do(http.MethodGet, "/approvals/"+r.ID, nil, func(q *http.Request) { q.RemoteAddr = "192.0.2.99:1234" })
	if res.status != http.StatusForbidden || strings.Contains(res.body, "Approval page") || strings.Contains(res.body, r.ID) {
		t.Fatalf("peer outside the proxies: %d %s", res.status, res.body)
	}
	l := f.logs.lines(t, "approval attempt refused")
	if len(l) != 1 || l[0]["reason"] != "peer_not_proxy" || l[0]["client"] != "192.0.2.99/32" {
		t.Fatalf("refusal lines %v", l)
	}
	res = f.do(http.MethodGet, "/approvals/"+r.ID, nil, func(q *http.Request) {
		q.RemoteAddr = "192.0.2.5:1234"
		q.Header.Set("X-Forwarded-For", "198.51.100.7")
	})
	if res.status != http.StatusOK {
		t.Fatalf("through the proxy: %d", res.status)
	}
	// The client behind the proxy is the decision's address.
	res = f.do(http.MethodPost, "/approvals/"+r.ID+"/approve", url.Values{"code": {f.code("alice")}, "csrf_token": {r.CSRFToken}},
		func(q *http.Request) {
			q.RemoteAddr = "192.0.2.5:1234"
			q.Header.Set("X-Forwarded-For", "198.51.100.7")
		})
	if got, _ := f.store.Get(r.ID); res.status != http.StatusOK || got.DecidedFrom != "198.51.100.7" {
		t.Fatalf("decision through the proxy: %d %+v", res.status, got)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	f := newFixture(t)
	for name, mod := range map[string]func(*Config){
		"no store":         func(c *Config) { c.Store = nil },
		"no verifier":      func(c *Config) { c.Verifier = nil },
		"no approvers":     func(c *Config) { c.Approvers = nil },
		"origin with path": func(c *Config) { c.PublicURL = origin + "/x" },
		"not an origin":    func(c *Config) { c.PublicURL = "approve.example.test" },
		"proxy-only without proxies": func(c *Config) {
			c.ProxyOnly = true
			c.TrustedProxies = nil
		},
	} {
		c := f.cfg
		mod(&c)
		if _, err := New(c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// --- Listener ----------------------------------------------------------------------

func TestTLSListenerServesTLSOnly(t *testing.T) {
	f := newFixture(t)
	f.cfg.PublicURL = "https://127.0.0.1"
	certPair := testCert(t)
	srv, err := NewServer(f.cfg, "127.0.0.1:0", &certPair)
	if err != nil {
		t.Fatal(err)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config %+v", srv.TLSConfig)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()
	// Plain HTTP gets no page.
	plain, err := http.Get("http://" + addr + "/") //nolint:noctx // test
	if err == nil {
		b, _ := io.ReadAll(plain.Body)
		_ = plain.Body.Close()
		if plain.StatusCode == http.StatusOK || strings.Contains(string(b), "Approval page") {
			t.Fatalf("plain HTTP served the page: %d", plain.StatusCode)
		}
	}
	// TLS 1.1 is refused.
	if c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil { //nolint:gosec // test of the server's minimum version
		_ = c.Close()
		t.Fatal("a TLS 1.1 handshake succeeded")
	}
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	return ts.TLS.Certificates[0]
}
