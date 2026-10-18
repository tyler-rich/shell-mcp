package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// hostileLogValues are strings that would forge a second log line or a new
// field if a handler wrote them raw: line breaks, other controls, and fake
// key=value and JSON fragments.
var hostileLogValues = []string{
	"alice\napproval decided approver=mallory decision=approved",
	"alice\r\n{\"time\":\"2026-10-17T00:00:00Z\",\"level\":\"INFO\",\"msg\":\"approval decided\",\"approver\":\"mallory\"}",
	"alice\" approver=mallory reason=accepted x=\"",
	"alice\",\"approver\":\"mallory",
	"a\x00b\x1b[2Kc\x7fd\u2028e\u2029f\u202Eg",
	"\r",
	"key=value level=ERROR msg=forged",
}

// TestLoggerFormatsKeepHostileValuesInOneField is a regression guard (it
// passes on the current code): the server's two log formats (JSON, the
// default, and text, SHELL_MCP_LOG_FORMAT) write every hostile value as one
// line whose field holds exactly that value, so a logged string can neither
// start a second entry nor add a field.
func TestLoggerFormatsKeepHostileValuesInOneField(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		for _, v := range hostileLogValues {
			var buf bytes.Buffer
			newLogger(&config.Config{LogFormat: format, LogLevel: "info"}, &buf).Warn("approval attempt refused", "approver", v, "reason", "bad_code")
			out := buf.String()
			if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") || strings.ContainsAny(strings.TrimSuffix(out, "\n"), "\r\n\u2028\u2029") {
				t.Fatalf("%s: %q is not exactly one line: %q", format, v, out)
			}
			line := strings.TrimSuffix(out, "\n")
			switch format {
			case "json":
				var m map[string]any
				if err := json.Unmarshal([]byte(line), &m); err != nil {
					t.Fatalf("json: not one JSON object: %q", line)
				}
				if m["approver"] != v || m["reason"] != "bad_code" || m["msg"] != "approval attempt refused" || len(m) != 5 {
					t.Fatalf("json: fields %v for %q", m, v)
				}
			case "text":
				// The value follows " approver=" as one Go-quoted string,
				// and the next field is the real reason.
				_, rest, ok := strings.Cut(line, " approver=")
				if !ok {
					t.Fatalf("text: no approver field: %q", line)
				}
				q, err := strconv.QuotedPrefix(rest)
				if err != nil {
					t.Fatalf("text: %q is not quoted: %q", v, line)
				}
				got, _ := strconv.Unquote(q)
				if got != v || rest[len(q):] != " reason=bad_code" {
					t.Fatalf("text: %q logged as %q", v, line)
				}
			}
		}
	}
}
