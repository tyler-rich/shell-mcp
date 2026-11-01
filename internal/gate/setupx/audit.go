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
	"io"

	"time"
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

func truncate(s string) string { var stub0 string; return stub0 }

func truncateAll(l []string) []string { var stub0 []string; return stub0 }

// Line renders r as one JSON object on one line, every string bounded.
func Line(r *Record) string { var stub0 string; return stub0 }

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
func (a *Auditor) Log(r *Record) {}
