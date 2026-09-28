// Package audit writes one syslog audit line per gate request (D-009,
// S-11): principal, client address, op, sanitized arguments, outcome and
// duration. It never records file contents, stdin, command output, command
// arguments or environment values, and a syslog failure never blocks or
// fails the request.
package audit

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// DevLog is the system syslog socket (a symlink into journald's directory
// on systemd hosts).
const DevLog = "/dev/log"

// Bounds and timeouts.
const (
	maxText      = 512 // free-text fields (SECURITY §2, log injection)
	dialTimeout  = 250 * time.Millisecond
	writeTimeout = 250 * time.Millisecond
	tag          = "shell-mcp-gate"
	// Priorities: facility authpriv (10), severity info (6) for a success
	// and notice (5) for any refusal or failure.
	priOK   = 10<<3 | 6
	priFail = 10<<3 | 5
)

// Record is one request's audit data.
type Record struct {
	Principal  string
	Client     string
	Op         string
	Args       map[string]any
	Outcome    string // "ok" or the gate error code
	DurationMS int64
}

// Sink receives audit records.
type Sink interface{ Log(r *Record) }

func truncate(s string) string {
	if len(s) <= maxText {
		return s
	}
	s = s[:maxText]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + "..."
}

type line struct {
	Principal  string         `json:"principal"`
	Client     string         `json:"client"`
	Op         string         `json:"op"`
	Args       map[string]any `json:"args"`
	Outcome    string         `json:"outcome"`
	DurationMS int64          `json:"duration_ms"`
}

// Line renders r as one JSON object on one line; every string is bounded.
func Line(r *Record) string {
	args := make(map[string]any, len(r.Args))
	for k, v := range r.Args {
		if s, ok := v.(string); ok {
			v = truncate(s)
		}
		args[truncate(k)] = v
	}
	b, err := json.Marshal(line{
		Principal: truncate(r.Principal), Client: truncate(r.Client), Op: truncate(r.Op),
		Args: args, Outcome: truncate(r.Outcome), DurationMS: r.DurationMS,
	}, json.Deterministic(true), jsontext.AllowInvalidUTF8(true))
	if err != nil {
		return `{"error":"audit record could not be encoded"}`
	}
	return string(b)
}

// Client returns the SSH client address from SSH_CONNECTION ("client_ip
// client_port server_ip server_port"): "ip:port", "local" when the variable
// is unset, "invalid" when it is malformed.
func Client(sshConnection *string) string {
	if sshConnection == nil {
		return "local"
	}
	f := strings.Fields(*sshConnection)
	if len(f) != 4 || net.ParseIP(f[0]) == nil {
		return "invalid"
	}
	if p, err := strconv.ParseUint(f[1], 10, 16); err != nil || p == 0 {
		return "invalid"
	}
	return net.JoinHostPort(f[0], f[1])
}

// loggedArgs are the argument names whose scalar values may be logged:
// paths, unit names, repo and command ids, flags and bounds. Everything
// else — content, stdin, command arguments, unknown names — is dropped.
var loggedArgs = map[string]bool{
	"path": true, "source": true, "destination": true, "repo": true, "unit": true, "action": true,
	"verb": true, "command_id": true, "cwd": true, "recursive": true, "staged": true, "lines": true,
	"since": true, "until": true, "priority": true, "limit": true, "include_pseudo": true,
	"sort_by": true, "user": true, "name_contains": true, "overwrite": true, "parents": true,
	"mode": true, "create": true, "max_bytes": true, "offset": true, "tail_lines": true,
	"name_glob": true, "type": true, "max_depth": true, "modified_within_s": true,
	"include_hidden": true, "failed_only": true, "max_output_bytes": true,
}

// SanitizeArgs keeps the loggable scalar arguments of a request, and for a
// command's argument list only its length ("arg_count").
func SanitizeArgs(_ string, raw []byte) map[string]any {
	out := map[string]any{}
	var in map[string]jsontext.Value
	if len(raw) == 0 || json.Unmarshal(raw, &in) != nil {
		return out
	}
	for k, v := range in {
		switch {
		case k == "args" && v.Kind() == '[':
			var list []jsontext.Value
			if json.Unmarshal(v, &list) == nil {
				out["arg_count"] = len(list)
			}
		case !loggedArgs[k]:
		case v.Kind() == '"':
			var s string
			if json.Unmarshal(v, &s) == nil {
				out[k] = truncate(s)
			}
		case v.Kind() == 't' || v.Kind() == 'f':
			out[k] = v.Kind() == 't'
		case v.Kind() == '0':
			var n float64
			if json.Unmarshal(v, &n) == nil {
				out[k] = n
			}
		}
	}
	return out
}

// Syslog sends records to a local syslog socket as RFC 3164 datagrams
// ("<PRI>Mmm dd hh:mm:ss shell-mcp-gate[pid]: {json}"). Each Log dials
// once with a short timeout, writes once with a short deadline, and gives
// up silently: a missing socket or a full queue never blocks the request.
// (log/syslog is not used: it also tries other socket paths, reconnects and
// retries, and its writes have no deadline.)
type Syslog struct {
	path string
}

// NewSyslog returns a sink for the socket at path (production: DevLog).
func NewSyslog(path string) *Syslog { return &Syslog{path: path} }

// Log writes one line; errors are ignored by design.
func (s *Syslog) Log(r *Record) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unixgram", s.path)
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	pri := priOK
	if r.Outcome != "ok" {
		pri = priFail
	}
	msg := fmt.Sprintf("<%d>%s %s[%d]: %s\n", pri, time.Now().Format(time.Stamp), tag, os.Getpid(), Line(r))
	_, _ = c.Write([]byte(msg))
}
