package page

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// Regression guards for go/log-injection on the approval page (they pass on
// the current code; they are not failing-test evidence). The only request
// value that can reach an approver field of a log line is the form's
// "approver" (several approvers); it is logged only when it is a valid
// approver name, and a decision records only an enrolled name that passed
// TOTP. Ids, reasons and clients are server-generated, fixed or netip-built.

var injectedNames = []string{
	"alice\napproval decided approver=mallory decision=approved",
	"alice\r\n{\"msg\":\"approval decided\",\"approver\":\"mallory\"}",
	"alice\" approver=mallory x=\"",
	"bob\n",
	"ALICE",
	strings.Repeat("a", 33),
}

// logLines splits a log into lines and checks each is one entry in its
// format: a JSON object, or a text line starting with time=.
func logLines(t *testing.T, format, out string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for _, l := range lines {
		switch format {
		case "json":
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("json: a line is not one JSON object: %q", l)
			}
		case "text":
			if !strings.HasPrefix(l, "time=") {
				t.Fatalf("text: a line does not start an entry: %q", l)
			}
		}
	}
	return lines
}

// TestApproverFieldCannotInjectLogLines: in both log formats, hostile
// approver names, a hostile X-Forwarded-For from the trusted proxy and a
// malformed path id each produce exactly one well-formed entry, with an
// empty approver and a netip-built client; then the real approver's
// decision logs that enrolled name only.
func TestApproverFieldCannotInjectLogLines(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			f := newFixture(t, "alice", "bob")
			logs := &logBuf{}
			var h slog.Handler = slog.NewJSONHandler(logs, nil)
			if format == "text" {
				h = slog.NewTextHandler(logs, nil)
			}
			logger := slog.New(h)
			f.store = approval.NewStore(approval.Options{TTL: 300 * time.Second, Method: approval.MethodWeb, Now: f.clock.Now, Logger: logger})
			f.cfg.Store, f.cfg.Logger = f.store, logger
			f.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.5/32")}
			f.rebuild()
			r := f.record()

			viaProxy := func(xff string) func(*http.Request) {
				return func(q *http.Request) {
					q.RemoteAddr = "192.0.2.5:40000"
					q.Header.Set("X-Forwarded-For", xff)
				}
			}
			hostileXFF := "198.51.100.7\napproval decided approver=mallory"
			for _, name := range injectedNames {
				f.do(http.MethodPost, "/approvals/"+r.ID+"/approve",
					url.Values{"code": {"000000"}, "csrf_token": {r.CSRFToken}, "approver": {name}}, viaProxy(hostileXFF))
			}
			f.do(http.MethodPost, "/approvals/"+url.PathEscape("x\napproval decided")+"/approve",
				url.Values{"code": {"000000"}, "csrf_token": {r.CSRFToken}, "approver": {"alice"}})
			before := len(logLines(t, format, logs.String()))
			// The record's own "approval requested" entry, then one entry per
			// refused attempt.
			if want := 1 + len(injectedNames) + 1; before != want {
				t.Fatalf("%d log entries, want %d:\n%s", before, want, logs.String())
			}
			out := logs.String()
			for _, s := range []string{"mallory", "ALICE", strings.Repeat("a", 33), "198.51.100.7\\n", "x\\napproval"} {
				if strings.Contains(out, s) {
					t.Fatalf("a request value reached the log: %q in\n%s", s, out)
				}
			}
			for _, l := range logLines(t, format, out)[1:] {
				if !strings.Contains(l, "approval attempt refused") || strings.Contains(l, "approval decided") {
					t.Fatalf("unexpected entry: %q", l)
				}
				if format == "json" {
					var m map[string]any
					_ = json.Unmarshal([]byte(l), &m)
					if m["approver"] != "" {
						t.Fatalf("approver logged as %q", m["approver"])
					}
				} else if !strings.Contains(l, ` approver=""`) {
					t.Fatalf("approver not empty: %q", l)
				}
			}

			// The real approver, still through the proxy with the hostile
			// header: one decision entry naming the enrolled approver; the
			// unparsable forwarded entry falls back to the peer.
			if res := f.decide(r, "approve", f.code("bob"), "approver", "bob"); res.status != http.StatusOK {
				t.Fatalf("approve: %d %s", res.status, res.body)
			}
			lines := logLines(t, format, logs.String())
			last := lines[len(lines)-1]
			if len(lines) != before+1 || !strings.Contains(last, "approval decided") || !strings.Contains(last, "bob") || strings.Contains(last, "mallory") {
				t.Fatalf("decision entries: %q", lines[before:])
			}
		})
	}
}
