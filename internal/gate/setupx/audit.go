// Package setupx is what the install commands share (docs/TARGET-SETUP.md
// §12.4): the install audit record and its sinks, the write helper (a temp
// file in the target's own directory, fsync, owner and mode on the
// descriptor, rename, read-back by SHA-256), the journal that rolls a run
// back, the user and group databases read from /etc/passwd and /etc/group,
// the Host interface the planners read the host through, the programs they
// may run (through execx, by absolute path, with an empty environment), the
// report lines and a unified diff. Nothing here decides what to install:
// internal/gate/setup (shell-mcp-gate install) and internal/privd/setup
// (shell-mcp-privd install) do.
package setupx

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"os"
	"time"
	"unicode/utf8"
)

// Audit priorities: facility authpriv (10) as the gate's request audit,
// severity notice (5) for a change and warning (4) for a refusal.
const (
	priChange = 10<<3 | 5
	priRefuse = 10<<3 | 4
	// maxText bounds every free-text field (SECURITY §2, log injection).
	maxText      = 512
	dialTimeout  = 250 * time.Millisecond
	writeTimeout = 250 * time.Millisecond
)

// Actions of a Record. ActionRefuse is the only one logged at warning.
const (
	ActionCreate   = "create"
	ActionReplace  = "replace"
	ActionRemove   = "remove"
	ActionRun      = "run"
	ActionRollback = "rollback"
	ActionRefuse   = "refuse"
	ActionWarn     = "warn"
	ActionAccept   = "accept"
	ActionReview   = "review"
)

// Record is one install audit line (TARGET-SETUP §12.4): paths, names, ids,
// modes, SHA-256s and key fingerprints, never a key, a policy's content or
// a file's content. Line sets Event; the sink sets Component.
type Record struct {
	Event        string   `json:"event"`
	Component    string   `json:"component"`
	Action       string   `json:"action"`
	Object       string   `json:"object"`
	Path         string   `json:"path,omitzero"`
	SHA256       string   `json:"sha256,omitzero"`
	Mode         string   `json:"mode,omitzero"`
	Owner        string   `json:"owner,omitzero"`
	User         string   `json:"user,omitzero"`
	Group        string   `json:"group,omitzero"`
	ID           string   `json:"id,omitzero"`
	Fingerprint  string   `json:"fingerprint,omitzero"`
	Principal    string   `json:"principal,omitzero"`
	Policy       string   `json:"policy,omitzero"`
	PolicySHA256 string   `json:"policy_sha256,omitzero"`
	Unit         string   `json:"unit,omitzero"`
	Command      []string `json:"command,omitzero"`
	Reason       string   `json:"reason,omitzero"`
	Detail       string   `json:"detail,omitzero"`
	OwnerScan    string   `json:"owner_scan,omitzero"`
	Paths        []string `json:"paths,omitzero"`
}

// Event is every Record's event name.
const Event = "install"

func truncate(s string) string {
	if len(s) <= maxText {
		return s
	}
	s = s[:maxText]
	for !utf8.ValidString(s) && s != "" {
		s = s[:len(s)-1]
	}
	return s + "..."
}

func truncateAll(l []string) []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, min(len(l), 64))
	for i, s := range l {
		if i == 64 {
			out = append(out, "...")
			break
		}
		out = append(out, truncate(s))
	}
	return out
}

// Line renders r as one JSON object on one line, every string bounded.
func Line(r *Record) string {
	c := *r
	c.Event = Event
	for _, p := range []*string{&c.Component, &c.Action, &c.Object, &c.Path, &c.SHA256, &c.Mode, &c.Owner, &c.User, &c.Group, &c.ID,
		&c.Fingerprint, &c.Principal, &c.Policy, &c.PolicySHA256, &c.Unit, &c.Reason, &c.Detail, &c.OwnerScan} {
		*p = truncate(*p)
	}
	c.Command = truncateAll(c.Command)
	c.Paths = truncateAll(c.Paths)
	b, err := json.Marshal(c, json.Deterministic(true), jsontext.AllowInvalidUTF8(true))
	if err != nil {
		return `{"event":"install","error":"audit record could not be encoded"}`
	}
	return string(b)
}

// Auditor writes each record to stderr and, unless Syslog is "", to the
// syslog socket at Syslog (production: /dev/log) as one bounded RFC 3164
// datagram tagged Tag. A syslog failure never blocks or fails the run. A
// dry run writes no record (it changes nothing).
type Auditor struct {
	Stderr    io.Writer
	Syslog    string
	Tag       string // shell-mcp-gate or shell-mcp-privd
	Component string // gate or privd
	DryRun    bool
}

// Log writes r.
func (a *Auditor) Log(r *Record) {
	if a == nil || a.DryRun {
		return
	}
	c := *r
	c.Component = a.Component
	l := Line(&c)
	if a.Stderr != nil {
		_, _ = fmt.Fprintln(a.Stderr, l)
	}
	if a.Syslog == "" {
		return
	}
	pri := priChange
	if c.Action == ActionRefuse {
		pri = priRefuse
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unixgram", a.Syslog)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = fmt.Fprintf(conn, "<%d>%s %s[%d]: %s\n", pri, time.Now().Format(time.Stamp), a.Tag, os.Getpid(), l)
}
