//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/selfcheck"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The helper's audit (PRIVILEGED §8): one line per connection on stderr,
// which the unit sends to the journal (SyslogIdentifier=shell-mcp-privd),
// prefixed with a syslog priority the journal honours: <6> info for a
// success, <5> notice for a refused operation, <4> warning for a refused
// connection (a failed self-check or peer check). The line carries the
// request id — the gate's audit line for the same id carries the gate
// principal — the request's tier ceiling, the peer's uid and pid, the op, sanitized arguments (paths,
// owners, modes, command id, argument count, backup id; never content,
// command arguments or output), the backups written, for chmod and chown
// the entry changed with its old mode, owner and group, the outcome and the
// duration.

const maxAuditText = 512

func auditText(s string) string {
	if len(s) <= maxAuditText {
		return s
	}
	s = s[:maxAuditText]
	for !utf8.ValidString(s) && s != "" {
		s = s[:len(s)-1]
	}
	return s + "..."
}

// auditedArgs are the argument names whose scalar values may be logged.
var auditedArgs = map[string]bool{
	"path": true, "source": true, "destination": true, "owner": true, "group": true, "mode": true,
	"recursive": true, "overwrite": true, "parents": true, "create": true, "expect_absent": true, "command_id": true,
	"cwd": true, "id": true, "limit": true, "max_bytes": true, "offset": true, "tail_lines": true,
	"include_hidden": true, "max_output_bytes": true, "action": true, "unit": true,
}

// maxAuditList bounds a logged list (package names).
const maxAuditList = 20

func sanitizeArgs(raw []byte) map[string]any {
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
		case k == "packages" && v.Kind() == '[':
			// Package names are identifiers the policy allow-lists, not content.
			var list []string
			if json.Unmarshal(v, &list) == nil {
				names := make([]string, 0, min(len(list), maxAuditList))
				for _, n := range list[:min(len(list), maxAuditList)] {
					names = append(names, auditText(n))
				}
				out["packages"] = names
			}
		case !auditedArgs[k]:
		case v.Kind() == '"':
			var s string
			if json.Unmarshal(v, &s) == nil {
				if k == "id" {
					k = "backup_id"
				}
				out[k] = auditText(s)
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

// auditChange is an entry chmod or chown changed, with its mode, owner and
// group before the change (metadata is not backed up; the audit line is the
// record).
type auditChange struct {
	Path    string `json:"path"`
	OldMode string `json:"old_mode"`
	OldUID  uint32 `json:"old_uid"`
	OldGID  uint32 `json:"old_gid"`
}

// Bounds on the changed list of one audit line (handoff Q8, D4): at most
// this many entries and this many bytes of them; the line then carries the
// total and changed_truncated.
const (
	maxAuditChanged      = 100
	maxAuditChangedBytes = 32 << 10
)

// recordChanges notes the entries chmod or chown changed, within the
// bounds; every one counts in changed_total.
func (s *server) recordChanges(cs []fsx.MetaChanged) {
	for _, c := range cs {
		s.changedTotal++
		if s.changedTruncated {
			continue
		}
		e := auditChange{Path: auditText(c.Path), OldMode: fmt.Sprintf("%04o", c.Before.Mode), OldUID: c.Before.UID, OldGID: c.Before.GID}
		b, _ := json.Marshal(e) // a plain struct of strings and numbers
		if len(s.changed) == maxAuditChanged || s.changedBytes+len(b)+1 > maxAuditChangedBytes {
			s.changedTruncated = true
			continue
		}
		s.changed = append(s.changed, e)
		s.changedBytes += len(b) + 1 // and its comma
	}
}

// recordRemoved notes the entries a delete removed, within the changed
// list's bounds (at most 100 entries or 32 KiB of them); every one counts
// in removed_total.
func (s *server) recordRemoved(paths []string) {
	for _, p := range paths {
		s.removedTotal++
		if s.removedTruncated {
			continue
		}
		e := auditText(p)
		b, _ := json.Marshal(e) // a string
		if len(s.removed) == maxAuditChanged || s.removedBytes+len(b)+1 > maxAuditChangedBytes {
			s.removedTruncated = true
			continue
		}
		s.removed = append(s.removed, e)
		s.removedBytes += len(b) + 1 // and its comma
	}
}

type auditLine struct {
	ID        string         `json:"id"`
	Ceiling   string         `json:"ceiling"`
	PeerUID   *uint32        `json:"peer_uid"`
	PeerPID   *int32         `json:"peer_pid"`
	Op        string         `json:"op"`
	Args      map[string]any `json:"args"`
	BackupIDs []string       `json:"backup_ids"`
	// BackupIDsDiscarded are backups written and removed again: the operation
	// failed provably unchanged.
	BackupIDsDiscarded []string      `json:"backup_ids_discarded,omitempty"`
	Changed            []auditChange `json:"changed,omitempty"`
	// ChangedTotal is how many entries were changed, ChangedTruncated set
	// when changed lists fewer of them (at most 100 entries or 32 KiB).
	ChangedTotal     int  `json:"changed_total,omitempty"`
	ChangedTruncated bool `json:"changed_truncated,omitempty"`
	// Removed are the entries a delete removed, RemovedTotal how many,
	// RemovedTruncated set when removed lists fewer (the same bounds).
	Removed          []string `json:"removed,omitempty"`
	RemovedTotal     int      `json:"removed_total,omitempty"`
	RemovedTruncated bool     `json:"removed_truncated,omitempty"`
	// SetAside is an entry a delete left set aside and did not remove, or
	// one a move left staged or could not put back under its name.
	SetAside string `json:"set_aside,omitempty"`
	// HungUp is set when the gate hung up while priv_exec ran its command
	// (stopped before the line was written) or before it started it.
	HungUp bool `json:"hung_up,omitempty"`
	// ReapError is why the helper could not confirm that every process a
	// command started has ended (the request answered outcome_unknown).
	// Applied is what dpkg's status shows a package operation changed
	// (bounded as Changed), AppliedTotal how many changes,
	// AppliedTruncated set when Applied lists fewer; Unfinished the
	// packages dpkg left part-way (at most 100); Stopped how the helper
	// stopped apt-get ("sigint", "killed"); AnsweredEarly that the request
	// was answered outcome_unknown before the operation ended, whose own
	// result Outcome then is.
	Applied          *auditApplied `json:"applied,omitempty"`
	AppliedTotal     int           `json:"applied_total,omitzero"`
	AppliedTruncated bool          `json:"applied_truncated,omitzero"`
	Unfinished       []string      `json:"unfinished,omitzero"`
	Stopped          string        `json:"stopped,omitzero"`
	AnsweredEarly    bool          `json:"answered_early,omitzero"`
	// Power is what became of priv_power's action (not_delivered, cancelled,
	// refused, unconfirmed, requested) and ScheduledAt its time; Detail then
	// says why it was refused (PRIVILEGED §8).
	Power       string `json:"power,omitzero"`
	ScheduledAt string `json:"scheduled_at,omitzero"`
	ReapError   string `json:"reap_error,omitempty"`
	Outcome     string `json:"outcome"`
	Check       string `json:"check,omitempty"`
	Detail      string `json:"detail,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

func (s *server) writeAudit(pri int, l *auditLine) {
	if s.o.Audit == nil {
		return
	}
	l.DurationMS = time.Since(s.start).Milliseconds()
	if l.Args == nil {
		l.Args = map[string]any{}
	}
	if l.BackupIDs == nil {
		l.BackupIDs = []string{}
	}
	b, err := json.Marshal(l, json.Deterministic(true), jsontext.AllowInvalidUTF8(true))
	if err != nil {
		b = []byte(`{"error":"audit record could not be encoded"}`)
	}
	_, _ = fmt.Fprintf(s.o.Audit, "<%d>%s\n", pri, b)
}

// auditRefusal logs a refused connection at warning: outcome "refused"
// when it was closed without a byte (the peer check), or the code it was
// answered with (a later self-check). The request was never read, so it
// has no id or op; the peer is logged when known.
func (s *server) auditRefusal(err error, code string) {
	l := &auditLine{Outcome: "refused", Check: "internal", Detail: auditText(err.Error())}
	if code != "" {
		l.Outcome = code
	}
	var se *selfcheck.Error
	if errors.As(err, &se) {
		l.Check = se.Check
	}
	if s.cred.PID != 0 {
		uid, pid := s.cred.UID, s.cred.PID
		l.PeerUID, l.PeerPID = &uid, &pid
	}
	s.writeAudit(4, l)
}

// auditRequest logs one served connection: info on success, notice on
// a refused operation.
func (s *server) auditRequest(resp *protocol.Response) {
	uid, pid := s.cred.UID, s.cred.PID
	l := &auditLine{PeerUID: &uid, PeerPID: &pid, Outcome: "ok", BackupIDs: s.ids(), BackupIDsDiscarded: s.discarded, Changed: s.changed,
		ChangedTotal: s.changedTotal, ChangedTruncated: s.changedTruncated, Removed: s.removed, RemovedTotal: s.removedTotal,
		RemovedTruncated: s.removedTruncated, SetAside: s.setAside, HungUp: s.hungUp, ReapError: auditText(s.reapErr),
		Unfinished: s.unfinished, Stopped: s.stopped, AnsweredEarly: s.answered, Power: s.powerState, ScheduledAt: s.powerAt}
	if s.powerDetail != "" {
		l.Detail = auditText(s.powerDetail)
	}
	if a := s.applied; a != nil {
		l.Applied, l.AppliedTotal, l.AppliedTruncated = a, a.total, a.truncated
	}
	if s.req != nil {
		l.ID, l.Ceiling, l.Op, l.Args = s.req.ID, s.req.Ceiling, auditText(s.req.Op), sanitizeArgs(s.req.Args)
	}
	pri := 6
	if resp.Error != nil {
		l.Outcome, pri = resp.Error.Code, 5
	}
	if s.unit == policy.UnitBroad {
		// Everything the broad unit serves is root-equivalent (PRIVILEGED §8).
		pri = 4
	}
	s.writeAudit(pri, l)
}

// auditApplied is what a package operation changed, for the audit line:
// package names and versions (identifiers, never output), bounded as the
// changed list (at most 100 entries or 32 KiB in all).
type auditApplied struct {
	Install   []auditPkg `json:"install"`
	Upgrade   []auditPkg `json:"upgrade"`
	Remove    []auditPkg `json:"remove"`
	total     int
	truncated bool
	bytes     int
}

type auditPkg struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

func (a *auditApplied) add(list *[]auditPkg, e auditPkg) {
	a.total++
	if a.truncated {
		return
	}
	b, _ := json.Marshal(e) // a plain struct of strings
	if len(a.Install)+len(a.Upgrade)+len(a.Remove) == maxAuditChanged || a.bytes+len(b)+1 > maxAuditChangedBytes {
		a.truncated = true
		return
	}
	*list = append(*list, e)
	a.bytes += len(b) + 1
}

// recordApplied notes what dpkg's status shows a package operation
// changed.
func (s *server) recordApplied(t pkg.Transaction) {
	a := &auditApplied{Install: []auditPkg{}, Upgrade: []auditPkg{}, Remove: []auditPkg{}}
	for _, v := range t.Install {
		a.add(&a.Install, auditPkg{Name: auditText(v.Name), Version: auditText(v.Version)})
	}
	for _, u := range t.Upgrade {
		a.add(&a.Upgrade, auditPkg{Name: auditText(u.Name), From: auditText(u.From), To: auditText(u.To)})
	}
	for _, r := range t.Remove {
		a.add(&a.Remove, auditPkg{Name: auditText(r.Name), Version: auditText(r.Version)})
	}
	s.applied = a
}
