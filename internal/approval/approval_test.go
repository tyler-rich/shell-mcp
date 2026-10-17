package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every principal, tool, target, path and hash below is an invented test
// fixture.

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)} }

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

// lines returns the log lines whose msg is msg.
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

func newTestStore(t *testing.T, c *clock, logs *logBuf, method Method) *Store {
	t.Helper()
	return NewStore(Options{
		TTL: 300 * time.Second, Method: method, Now: c.Now, Wait: 200 * time.Millisecond,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
}

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func binding() Binding {
	return Binding{Principal: "bearer-token", Tool: "shell_write_file", Target: "app-host", ArgsSHA256: hashA}
}

func request() Request {
	return Request{
		Binding: binding(), PreviewSHA256: hashB, PolicySHA256: hashC,
		ToolTitle: "Write file", TargetHost: "target-a.example.test",
		Description: "Write 12 bytes to /srv/app/config.yaml on app-host",
		Args:        []Field{{"path", "/srv/app/config.yaml"}, {"content", "key: value\n"}},
		Preview:     []Field{{"current.state", "file"}},
	}
}

// --- Ids ---------------------------------------------------------------------

func TestNewIDFormat(t *testing.T) {
	re := regexp.MustCompile(IDPattern)
	seen := map[string]bool{}
	for range 200 {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(id) || len(id) != IDLength || !ParseID(id) {
			t.Fatalf("id %q is not a canonical approval id", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestParseIDRefuses(t *testing.T) {
	id, _ := NewID()
	for _, bad := range []string{
		"", "a", strings.Repeat("a", 25), strings.Repeat("a", 27), strings.ToUpper(id),
		strings.Repeat("a", 25) + "1", strings.Repeat("a", 25) + "8", " " + id[1:], id[:25] + "=",
		// 26 characters carry 130 bits; the last character's two low bits
		// must be zero in canonical form.
		strings.Repeat("a", 25) + "b",
	} {
		if ParseID(bad) {
			t.Fatalf("ParseID accepted %q", bad)
		}
	}
	if !ParseID(strings.Repeat("a", 26)) {
		t.Fatal("ParseID refused a canonical id")
	}
}

// --- Canonical arguments -------------------------------------------------------

func TestCanonicalJSONSortsAndIsStable(t *testing.T) {
	type in struct {
		Z string         `json:"z"`
		A int64          `json:"a"`
		M map[string]any `json:"m"`
	}
	b1, err := CanonicalJSON(in{Z: "x", A: 1 << 60, M: map[string]any{"b": true, "a": []int{3, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1152921504606846976,"m":{"a":[3,1],"b":true},"z":"x"}`
	if string(b1) != want {
		t.Fatalf("canonical %s, want %s", b1, want)
	}
	b2, err := CanonicalJSON(json.RawMessage(b1))
	if err != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("canonical form of the canonical form differs: %s vs %s (%v)", b1, b2, err)
	}
	h1, _ := HashOf(in{Z: "x", A: 1 << 60, M: map[string]any{"a": []int{3, 1}, "b": true}})
	if h1 != SHA256Hex(b1) || len(h1) != 64 {
		t.Fatalf("hash %q", h1)
	}
	h2, _ := HashOf(in{Z: "y"})
	if h1 == h2 {
		t.Fatal("different arguments hash the same")
	}
}

func TestFieldsFlattenAndBound(t *testing.T) {
	v := map[string]any{
		"path": "/srv/app/x", "mode": "0640", "create": true, "n": 3,
		"args": []string{"a", "b"}, "nested": map[string]any{"k": "v"},
		"big": strings.Repeat("é", MaxFieldBytes),
	}
	f, err := Fields(v, MaxArgsBytes)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range f {
		got[x.Key] = x.Value
		if len(x.Value) > MaxFieldBytes+64 {
			t.Fatalf("field %s is %d bytes", x.Key, len(x.Value))
		}
	}
	for k, want := range map[string]string{
		"path": "/srv/app/x", "mode": "0640", "create": "true", "n": "3", "args[0]": "a", "args[1]": "b", "nested.k": "v",
	} {
		if got[k] != want {
			t.Fatalf("field %s = %q, want %q (all: %v)", k, got[k], want, got)
		}
	}
	if !strings.Contains(got["big"], "bytes") || !strings.HasPrefix(got["big"], "é") {
		t.Fatalf("the long field is not cut and marked: %.40q…", got["big"])
	}
	// The total bound holds, and says what was left out.
	many := map[string]any{}
	for i := range 100 {
		many[strings.Repeat("k", 3)+string(rune('a'+i%26))+string(rune('a'+i/26))] = strings.Repeat("x", 1000)
	}
	f, _ = Fields(many, 8192)
	total := 0
	for _, x := range f {
		total += len(x.Value)
	}
	if total > 8192+256 || !strings.Contains(f[len(f)-1].Value, "left out") {
		t.Fatalf("total %d bytes in %d fields; last %+v", total, len(f), f[len(f)-1])
	}
}

func TestVisibleEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"plain text /srv/app":   "plain text /srv/app",
		"a\x00b":                `a\u{0000}b`,
		"line\nbreak\r\t":       `line\u{000A}break\u{000D}\u{0009}`,
		"evil\u202Etxt.exe":     `evil\u{202E}txt.exe`,
		"\u2066iso\u2069":       `\u{2066}iso\u{2069}`,
		"zero\u200Bwidth\uFEFF": `zero\u{200B}width\u{FEFF}`,
		"sep\u2028par\u2029":    `sep\u{2028}par\u{2029}`,
		`back\slash`:            `back\\slash`,
		`fake \u{202E}`:         `fake \\u{202E}`,
		"bad\xffbyte":           `bad\x{FF}byte`,
		"\x1b[31mred":           `\u{001B}[31mred`,
		"café ünïcode 日本":       "café ünïcode 日本",
		"del\x7f":               `del\u{007F}`,
	} {
		if got := Visible(in); got != want {
			t.Fatalf("Visible(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- Store ---------------------------------------------------------------------

func TestRequestCreatesPendingRecord(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	var created []Record
	s.o.OnCreate = func(r Record) { created = append(created, r) }
	r, err := s.Request(request())
	if err != nil {
		t.Fatal(err)
	}
	if !ParseID(r.ID) || r.Status != StatusPending || !r.ExpiresAt.Equal(c.Now().Add(300*time.Second)) ||
		len(r.CSRFToken) < 22 || r.CSRFToken == r.ID || r.Approver != "" {
		t.Fatalf("record %+v", r)
	}
	got, ok := s.Get(r.ID)
	if !ok || got.ID != r.ID || got.CSRFToken != r.CSRFToken || got.Description != r.Description {
		t.Fatalf("get: %+v %v", got, ok)
	}
	if len(created) != 1 || created[0].ID != r.ID {
		t.Fatalf("OnCreate calls: %v", created)
	}
	l := logs.lines(t, "approval requested")
	if len(l) != 1 {
		t.Fatalf("approval requested lines: %s", logs.String())
	}
	for k, want := range map[string]any{
		"approval_id": r.ID, "principal": "bearer-token", "tool": "shell_write_file", "target": "app-host",
		"args_sha256": hashA, "preview_sha256": hashB, "policy_sha256": hashC, "method": "web",
		"expires_at": r.ExpiresAt.Format(time.RFC3339),
	} {
		if l[0][k] != want {
			t.Fatalf("approval requested %s = %v, want %v (%v)", k, l[0][k], want, l[0])
		}
	}
	// Never logged: the CSRF token, the description, argument or preview text.
	for _, secret := range []string{r.CSRFToken, r.Description, "key: value", "/srv/app/config.yaml", "current.state"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("the log contains %q", secret)
		}
	}
}

func TestRequestDeduplicates(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	r1, _ := s.Request(request())
	c.Add(10 * time.Second)
	r2, err := s.Request(request())
	if err != nil || r2.ID != r1.ID || r2.CSRFToken != r1.CSRFToken {
		t.Fatalf("identical pending request: %v, %s vs %s", err, r2.ID, r1.ID)
	}
	if n := len(logs.lines(t, "approval requested")); n != 1 {
		t.Fatalf("%d approval requested lines", n)
	}
	// Another preview or policy hash is another request.
	req := request()
	req.PreviewSHA256 = hashA
	r3, _ := s.Request(req)
	req = request()
	req.PolicySHA256 = hashA
	r4, _ := s.Request(req)
	if r3.ID == r1.ID || r4.ID == r1.ID || r3.ID == r4.ID {
		t.Fatal("different preview or policy deduplicated")
	}
	// Once decided, an identical request makes a new record.
	if _, err := s.Decide(r1.ID, false, "alice", "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	r5, _ := s.Request(request())
	if r5.ID == r1.ID {
		t.Fatal("a decided record was returned for a new request")
	}
}

func TestPendingCapPerPrincipal(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	for i := range MaxPendingPerPrincipal {
		req := request()
		req.ArgsSHA256 = strings.Repeat(string(rune('0'+i)), 64)
		if _, err := s.Request(req); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	req := request()
	req.ArgsSHA256 = strings.Repeat("f", 64)
	if _, err := s.Request(req); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("sixth pending request: %v", err)
	}
	// Another principal is not affected.
	req.Principal = "unauthenticated"
	if _, err := s.Request(req); err != nil {
		t.Fatalf("other principal: %v", err)
	}
}

func TestGlobalBound(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	for i := range MaxRecords {
		req := request()
		req.Principal = "p" + strings.Repeat("x", i%7) + string(rune('a'+i/7%26)) + string(rune('a'+i/182))
		req.ArgsSHA256 = SHA256Hex([]byte{byte(i), byte(i >> 8)})
		r, err := s.Request(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		// Decided records still occupy the store until they expire.
		if _, err := s.Decide(r.ID, false, "alice", "192.0.2.50"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Request(request()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("request beyond the bound: %v", err)
	}
	// Expiry frees the store.
	c.Add(301 * time.Second)
	s.Sweep()
	if _, err := s.Request(request()); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestRestartForgetsRecords(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	r, _ := s.Request(request())
	_, _ = s.Decide(r.ID, true, "alice", "192.0.2.50")
	s2 := newTestStore(t, c, logs, MethodWeb)
	if _, ok := s2.Get(r.ID); ok {
		t.Fatal("a new store knows an old id")
	}
	res := s2.Use(t.Context(), r.ID, binding(), "", "")
	if res.Outcome != OutcomeInvalid || res.Known || !strings.Contains(res.Reason, "unknown") {
		t.Fatalf("use after restart: %+v", res)
	}
}

func TestDecide(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	r, _ := s.Request(request())
	d, err := s.Decide(r.ID, true, "alice", "192.0.2.50")
	if err != nil || d.Status != StatusApproved || d.Approver != "alice" || d.DecidedFrom != "192.0.2.50" || !d.DecidedAt.Equal(c.Now()) {
		t.Fatalf("decide: %+v %v", d, err)
	}
	if _, err := s.Decide(r.ID, false, "alice", "192.0.2.50"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second decision: %v", err)
	}
	if _, err := s.Decide("aaaaaaaaaaaaaaaaaaaaaaaaaa", true, "alice", ""); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown id: %v", err)
	}
	r2, _ := s.Request(func() Request { q := request(); q.ArgsSHA256 = hashC; return q }())
	c.Add(301 * time.Second)
	if _, err := s.Decide(r2.ID, true, "alice", ""); !errors.Is(err, ErrExpired) {
		t.Fatalf("decision after expiry: %v", err)
	}
	l := logs.lines(t, "approval decided")
	if len(l) != 1 || l[0]["approval_id"] != r.ID || l[0]["decision"] != "approved" || l[0]["approver"] != "alice" ||
		l[0]["client"] != "192.0.2.50" || l[0]["method"] != "web" {
		t.Fatalf("approval decided lines: %v", l)
	}
}

// --- The execution check (handoff §6.3) ------------------------------------------

func approved(t *testing.T, s *Store) Record {
	t.Helper()
	r, err := s.Request(request())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(r.ID, true, "alice", "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUseApprovedMarksUsedOnce(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	r := approved(t, s)
	res := s.Use(t.Context(), r.ID, binding(), "", "")
	if res.Outcome != OutcomeUsed || res.Record.Status != StatusUsed || res.Record.PreviewSHA256 != hashB || res.Record.PolicySHA256 != hashC {
		t.Fatalf("first use: %+v", res)
	}
	if got, _ := s.Get(r.ID); got.Status != StatusUsed {
		t.Fatalf("record after use: %s", got.Status)
	}
	res = s.Use(t.Context(), r.ID, binding(), "", "")
	if res.Outcome != OutcomeInvalid || !res.Known || res.Record.Status != StatusUsed {
		t.Fatalf("second use: %+v", res)
	}
}

func TestUseBindingMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*Binding){
		"principal": func(b *Binding) { b.Principal = "unauthenticated" },
		"tool":      func(b *Binding) { b.Tool = "shell_copy_path" },
		"target":    func(b *Binding) { b.Target = "db-host" },
		"arguments": func(b *Binding) { b.ArgsSHA256 = hashC },
	} {
		t.Run(name, func(t *testing.T) {
			c, logs := newClock(), &logBuf{}
			s := newTestStore(t, c, logs, MethodWeb)
			r := approved(t, s)
			b := binding()
			mutate(&b)
			res := s.Use(t.Context(), r.ID, b, "", "")
			if res.Outcome != OutcomeInvalid || res.Reason == "" {
				t.Fatalf("mismatched %s: %+v", name, res)
			}
			// A mismatch does not consume the record.
			if got, _ := s.Get(r.ID); got.Status != StatusApproved {
				t.Fatalf("record after a mismatch: %s", got.Status)
			}
			if res := s.Use(t.Context(), r.ID, binding(), "", ""); res.Outcome != OutcomeUsed {
				t.Fatalf("matching call after the mismatch: %+v", res)
			}
		})
	}
}

func TestUseExpiredUnknownDeclined(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	r := approved(t, s)
	c.Add(301 * time.Second)
	if res := s.Use(t.Context(), r.ID, binding(), "", ""); res.Outcome != OutcomeInvalid {
		t.Fatalf("expired: %+v", res)
	}
	if res := s.Use(t.Context(), "aaaaaaaaaaaaaaaaaaaaaaaaaa", binding(), "", ""); res.Outcome != OutcomeInvalid || res.Known {
		t.Fatalf("unknown: %+v", res)
	}
	s2 := newTestStore(t, c, logs, MethodWeb)
	r2, _ := s2.Request(request())
	_, _ = s2.Decide(r2.ID, false, "alice", "192.0.2.50")
	res := s2.Use(t.Context(), r2.ID, binding(), "", "")
	if res.Outcome != OutcomeDeclined || res.Record.Approver != "alice" {
		t.Fatalf("declined: %+v", res)
	}
	// Declined stays declined.
	if res := s2.Use(t.Context(), r2.ID, binding(), "", ""); res.Outcome != OutcomeDeclined {
		t.Fatalf("declined twice: %+v", res)
	}
}

func TestUsePendingWaits(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	s.o.Wait = 300 * time.Millisecond
	r, _ := s.Request(request())

	// No decision: waits the bound, then pending.
	start := time.Now()
	res := s.Use(t.Context(), r.ID, binding(), "", "")
	if el := time.Since(start); res.Outcome != OutcomePending || el < 250*time.Millisecond || el > 3*time.Second {
		t.Fatalf("pending: %+v after %s", res, el)
	}

	// A decision ends the wait early.
	s.o.Wait = 10 * time.Second
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = s.Decide(r.ID, true, "alice", "192.0.2.50")
	}()
	start = time.Now()
	res = s.Use(t.Context(), r.ID, binding(), "", "")
	if el := time.Since(start); res.Outcome != OutcomeUsed || el > 5*time.Second {
		t.Fatalf("decided during the wait: %+v after %s", res, el)
	}

	// Context cancellation ends the wait early.
	r2, _ := s.Request(func() Request { q := request(); q.ArgsSHA256 = hashC; return q }())
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	b := binding()
	b.ArgsSHA256 = hashC
	start = time.Now()
	res = s.Use(ctx, r2.ID, b, "", "")
	if el := time.Since(start); res.Outcome != OutcomePending || el > 5*time.Second {
		t.Fatalf("cancelled wait: %+v after %s", res, el)
	}

	// A mismatched call against a pending record is invalid at once.
	b.Tool = "shell_copy_path"
	start = time.Now()
	res = s.Use(t.Context(), r2.ID, b, "", "")
	if el := time.Since(start); res.Outcome != OutcomeInvalid || el > 2*time.Second {
		t.Fatalf("mismatched pending: %+v after %s", res, el)
	}
}

func TestUsePendingWaitNeverPastExpiry(t *testing.T) {
	logs := &logBuf{}
	s := NewStore(Options{TTL: 60 * time.Second, Method: MethodWeb, Now: time.Now,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), Wait: 30 * time.Second})
	r, _ := s.Request(request())
	// Shorten this record's life for the test.
	s.expireAt(r.ID, time.Now().Add(200*time.Millisecond))
	start := time.Now()
	res := s.Use(t.Context(), r.ID, binding(), "", "")
	if el := time.Since(start); el > 5*time.Second || res.Outcome == OutcomeUsed {
		t.Fatalf("wait past expiry: %+v after %s", res, el)
	}
}

func TestConfirmArgument(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodConfirm)
	r, _ := s.Request(request())
	// Without confirm the record stays pending, at once (nobody else decides).
	start := time.Now()
	if res := s.Use(t.Context(), r.ID, binding(), "", ""); res.Outcome != OutcomePending || time.Since(start) > time.Second {
		t.Fatalf("no confirm: %+v", res)
	}
	// A mismatched confirm approves nothing.
	b := binding()
	b.Target = "db-host"
	if res := s.Use(t.Context(), r.ID, b, ConfirmApprover, "model"); res.Outcome != OutcomeInvalid {
		t.Fatalf("mismatched confirm: %+v", res)
	}
	if got, _ := s.Get(r.ID); got.Status != StatusPending {
		t.Fatalf("mismatched confirm changed the record: %s", got.Status)
	}
	res := s.Use(t.Context(), r.ID, binding(), ConfirmApprover, "model")
	if res.Outcome != OutcomeUsed || res.Record.Approver != ConfirmApprover {
		t.Fatalf("confirm: %+v", res)
	}
	d := logs.lines(t, "approval decided")
	if len(d) != 1 || d[0]["approver"] != ConfirmApprover || d[0]["method"] != "confirm-argument" || d[0]["decision"] != "approved" {
		t.Fatalf("decided lines %v", d)
	}
	var warned bool
	for _, l := range logs.lines(t, "approval by the model (confirm-argument): human approval is not enforced") {
		warned = warned || l["level"] == "WARN"
	}
	if !warned {
		t.Fatalf("no WARN on the confirm-argument use: %s", logs.String())
	}
}

func TestSweepLogsExpiry(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	pending, _ := s.Request(request())
	q := request()
	q.ArgsSHA256 = hashC
	ap, _ := s.Request(q)
	_, _ = s.Decide(ap.ID, true, "alice", "")
	c.Add(301 * time.Second)
	s.Sweep()
	ids := map[any]bool{}
	for _, l := range logs.lines(t, "approval expired") {
		ids[l["approval_id"]] = true
	}
	if !ids[pending.ID] || !ids[ap.ID] {
		t.Fatalf("expiry lines for %v; want %s and %s", ids, pending.ID, ap.ID)
	}
	if got, ok := s.Get(pending.ID); ok && got.Status != StatusExpired {
		t.Fatalf("expired record status %s", got.Status)
	}
	// Swept once: a second sweep logs nothing new.
	n := len(logs.lines(t, "approval expired"))
	s.Sweep()
	if len(logs.lines(t, "approval expired")) != n {
		t.Fatal("a second sweep logged the expiry again")
	}
}

func TestConcurrentUseOnlyOnce(t *testing.T) {
	c, logs := newClock(), &logBuf{}
	s := newTestStore(t, c, logs, MethodWeb)
	r := approved(t, s)
	var wg sync.WaitGroup
	var mu sync.Mutex
	used := 0
	for range 32 {
		wg.Go(func() {
			if res := s.Use(context.Background(), r.ID, binding(), "", ""); res.Outcome == OutcomeUsed {
				mu.Lock()
				used++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if used != 1 {
		t.Fatalf("%d concurrent uses succeeded", used)
	}
}
