//go:build linux

package ops

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/systemd"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Built-in systemd operations (ARCHITECTURE §4.3). They run fixed argv
// through execx, never a policy command: systemctl and journalctl may not
// be declared as commands (POLICY §5). Real systemd, journald and polkit
// behaviour is proven on a systemd host (S1c); the command-line contract
// here was verified against the systemd 257 and 259 sources.

// Production paths of the built-in binaries (merged /usr on Debian 13 and
// Ubuntu 26.04 LTS).
const (
	SystemctlPath  = "/usr/bin/systemctl"
	JournalctlPath = "/usr/bin/journalctl"
	GitPath        = "/usr/bin/git"
)

const (
	maxStderrBytes     = 4 << 10
	defaultJournal     = 200
	defaultServiceList = 200
	maxServiceList     = 5000
)

// builtin checks a built-in binary like a policy command's: an absolute
// path whose chain is owned by a trusted uid and not group/other-writable,
// resolving to a regular executable file. It returns the resolved path.
func (s *server) builtin(p, name string) (string, error) {
	unavailable := errf(protocol.CodeExecFailed, "%s is not installed, or is not root-owned and protected", name)
	if p == "" {
		return "", unavailable
	}
	rp, err := policy.CheckChain(s.o.Trust, p)
	if err != nil {
		return "", unavailable
	}
	fi, err := os.Stat(rp)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 || fi.Mode().Perm()&0o022 != 0 {
		return "", unavailable
	}
	return rp, nil
}

// runBuiltin runs a built-in binary with the gate's fixed environment
// (plus extra variables) and the policy's output cap.
func (s *server) runBuiltin(bin, name string, args, extraEnv []string, dir string) (execx.Result, error) {
	rp, err := s.builtin(bin, name)
	if err != nil {
		return execx.Result{}, err
	}
	res, err := execx.Run(context.Background(), &execx.Spec{
		Path: rp, Args: args, Env: append(execx.Environment(s.p.ServiceHome), extraEnv...), Dir: dir,
		Timeout: s.timeout(), MaxOutput: s.p.Limits.MaxOutputBytes,
	})
	if err != nil {
		return execx.Result{}, err
	}
	if res.TimedOut {
		return res, errf(protocol.CodeTimeout, "%s did not finish within the request timeout", name)
	}
	return res, nil
}

func exitStatus(res *execx.Result) string {
	switch {
	case res.ExitCode != nil:
		return "exit status " + strconv.Itoa(*res.ExitCode)
	case res.Signal != "":
		return "killed by " + res.Signal
	}
	return "unknown exit"
}

func exited(res *execx.Result, code int) bool { return res.ExitCode != nil && *res.ExitCode == code }

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// checkUnit validates a requested unit name and matches it against
// patterns; field names the policy section in the refusal.
func checkUnit(unit string, patterns []string, field string) error {
	if !systemd.ValidUnit(unit) {
		return errf(protocol.CodeBadRequest, "unit must be an exact unit name with a type suffix (no globs, no leading '-')")
	}
	if !matchAny(patterns, unit) {
		return errf(protocol.CodePolicyDenied, "unit is not allowed by %s", field)
	}
	return nil
}

type unitArgs struct {
	Unit string `json:"unit"`
}

type serviceStatus struct {
	Unit          string  `json:"unit"`
	Description   string  `json:"description"`
	LoadState     string  `json:"load_state"`
	ActiveState   string  `json:"active_state"`
	SubState      string  `json:"sub_state"`
	UnitFileState string  `json:"unit_file_state"`
	MainPID       *int64  `json:"main_pid"`
	ActiveSince   string  `json:"active_since"`
	StateChanged  string  `json:"state_changed"`
	MemoryBytes   *uint64 `json:"memory_bytes"`
	NRestarts     *int64  `json:"n_restarts"`
	Result        string  `json:"result"`
}

// numberOrNil parses systemd's numbers; "[not set]", empty and UINT64_MAX
// ("infinity") are nil.
func numberOrNil[T int64 | uint64](v string) *T {
	u, err := strconv.ParseUint(v, 10, 64)
	if err != nil || u == ^uint64(0) || u > 1<<62 {
		return nil
	}
	n := T(u)
	return &n
}

// status runs `systemctl show` for unit and shapes the result.
func (s *server) status(unit string) (serviceStatus, error) {
	res, err := s.runBuiltin(s.o.Systemctl, "systemctl",
		[]string{"show", "--no-pager", "-p", strings.Join(systemd.ShowProperties, ","), "--", unit}, nil, "/")
	if err != nil {
		return serviceStatus{}, err
	}
	if !exited(&res, 0) || res.StdoutTruncated {
		return serviceStatus{}, errf(protocol.CodeExecFailed, "systemctl show failed (%s)", exitStatus(&res))
	}
	p, err := systemd.ParseShow(res.Stdout, systemd.ShowProperties)
	if err != nil {
		return serviceStatus{}, errf(protocol.CodeExecFailed, "systemctl show output could not be parsed")
	}
	return serviceStatus{
		Unit: unit, Description: s.red.String(p["Description"]), LoadState: p["LoadState"], ActiveState: p["ActiveState"],
		SubState: p["SubState"], UnitFileState: p["UnitFileState"], MainPID: numberOrNil[int64](p["MainPID"]),
		ActiveSince: p["ActiveEnterTimestamp"], StateChanged: p["StateChangeTimestamp"],
		MemoryBytes: numberOrNil[uint64](p["MemoryCurrent"]), NRestarts: numberOrNil[int64](p["NRestarts"]), Result: p["Result"],
	}, nil
}

func (s *server) serviceStatus(raw jsontext.Value) (data any, warns []string, failure error) {
	var a unitArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if len(s.p.Services.Status) == 0 {
		return nil, nil, errf(protocol.CodePolicyDenied, "services.status is empty in this gate policy")
	}
	if err := checkUnit(a.Unit, s.p.Services.Status, "services.status"); err != nil {
		return nil, nil, err
	}
	st, err := s.status(a.Unit)
	if err != nil {
		return nil, nil, err
	}
	return st, nil, nil
}

type serviceListArgs struct {
	FailedOnly   bool   `json:"failed_only"`
	NameContains string `json:"name_contains"`
	Limit        int    `json:"limit"`
}

type serviceListData struct {
	Units     []systemd.Unit `json:"units"`
	Matched   int            `json:"matched"`
	Truncated bool           `json:"truncated"`
}

// serviceList lists service units, only those matching services.status.
func (s *server) serviceList(raw jsontext.Value) (data any, warns []string, failure error) {
	var a serviceListArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	switch {
	case a.Limit == 0:
		a.Limit = defaultServiceList
	case a.Limit < 1 || a.Limit > maxServiceList:
		return nil, nil, errf(protocol.CodeBadRequest, "limit must be 1..%d", maxServiceList)
	}
	if len(a.NameContains) > maxFilterLen {
		return nil, nil, errf(protocol.CodeBadRequest, "name_contains is at most %d bytes", maxFilterLen)
	}
	if len(s.p.Services.Status) == 0 {
		return nil, nil, errf(protocol.CodePolicyDenied, "services.status is empty in this gate policy")
	}
	args := []string{"list-units", "--no-pager", "--plain", "--output=json", "--type=service"}
	if a.FailedOnly {
		args = append(args, "--state=failed")
	}
	res, err := s.runBuiltin(s.o.Systemctl, "systemctl", args, nil, "/")
	if err != nil {
		return nil, nil, err
	}
	if !exited(&res, 0) || res.StdoutTruncated {
		return nil, nil, errf(protocol.CodeExecFailed, "systemctl list-units failed or its output exceeded max_output_bytes (%s)", exitStatus(&res))
	}
	units, err := systemd.ParseListUnits(res.Stdout)
	if err != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "systemctl list-units output could not be parsed")
	}
	d := serviceListData{Units: []systemd.Unit{}}
	for _, u := range units {
		if !systemd.ValidUnit(u.Unit) || !matchAny(s.p.Services.Status, u.Unit) || !strings.Contains(u.Unit, a.NameContains) {
			continue
		}
		d.Matched++
		if len(d.Units) == a.Limit {
			d.Truncated = true
			continue
		}
		u.Description = s.red.String(u.Description)
		d.Units = append(d.Units, u)
	}
	return d, nil, nil
}

type journalArgs struct {
	Unit     string `json:"unit"`
	Lines    int    `json:"lines"`
	Since    string `json:"since"`
	Until    string `json:"until"`
	Priority string `json:"priority"`
}

type journalData struct {
	Unit      string `json:"unit"`
	Lines     int    `json:"lines"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated"`
	Stderr    string `json:"stderr"`
}

// journal returns the unit's last lines: journalctl --no-pager -o short-iso
// -n N [--since @T] [--until @T] [-p PRIO] -u UNIT. since/until are
// converted to epoch seconds here; the unit is an exact name (journalctl
// -u would expand a glob).
func (s *server) journal(raw jsontext.Value) (data any, warns []string, failure error) {
	var a journalArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if len(s.p.Journal.Units) == 0 {
		return nil, nil, errf(protocol.CodePolicyDenied, "journal is not configured in this gate policy")
	}
	if err := checkUnit(a.Unit, s.p.Journal.Units, "journal.units"); err != nil {
		return nil, nil, err
	}
	switch {
	case a.Lines == 0:
		a.Lines = min(defaultJournal, s.p.Journal.MaxLines)
	case a.Lines < 1 || a.Lines > s.p.Journal.MaxLines:
		return nil, nil, errf(protocol.CodeBadRequest, "lines must be 1..%d (journal.max_lines)", s.p.Journal.MaxLines)
	}
	args := []string{"--no-pager", "-o", "short-iso", "-n", strconv.Itoa(a.Lines)}
	now := time.Now()
	var since, until string
	for _, t := range []struct {
		in, flag string
		out      *string
	}{{a.Since, "--since", &since}, {a.Until, "--until", &until}} {
		if t.in == "" {
			continue
		}
		v, err := systemd.JournalTime(t.in, now)
		if err != nil {
			return nil, nil, errf(protocol.CodeBadRequest, "%s: %v", strings.TrimPrefix(t.flag, "--"), err)
		}
		*t.out = v
		args = append(args, t.flag, v)
	}
	if since != "" && until != "" {
		si, _ := strconv.ParseInt(since[1:], 10, 64)
		ui, _ := strconv.ParseInt(until[1:], 10, 64)
		if si > ui {
			return nil, nil, errf(protocol.CodeBadRequest, "since is after until")
		}
	}
	if a.Priority != "" {
		if !systemd.ValidPriority(a.Priority) {
			return nil, nil, errf(protocol.CodeBadRequest, "priority must be emerg, alert, crit, err, warning, notice, info or debug")
		}
		args = append(args, "-p", a.Priority)
	}
	args = append(args, "-u", a.Unit)
	res, err := s.runBuiltin(s.o.Journalctl, "journalctl", args, nil, "/")
	if err != nil {
		return nil, nil, err
	}
	stderr, _ := s.red.Truncate(res.Stderr, maxStderrBytes)
	if !exited(&res, 0) {
		msg := "journalctl failed (" + exitStatus(&res) + ")"
		if bytes.Contains(res.Stderr, []byte("insufficient permissions")) {
			msg += "; the service account cannot read the journal (add it to systemd-journal)"
		}
		return nil, nil, errf(protocol.CodeExecFailed, "%s", msg)
	}
	out, cut := s.red.Truncate(res.Stdout, s.p.Limits.MaxOutputBytes)
	var warnings []string
	if bytes.Contains(res.Stderr, []byte("not seeing messages")) {
		warnings = append(warnings, "journalctl reports limited access: add the service account to the systemd-journal group to see all messages")
	}
	return journalData{Unit: a.Unit, Lines: a.Lines, Output: string(out), Truncated: cut || res.StdoutTruncated, Stderr: string(stderr)}, warnings, nil
}

type controlArgs struct {
	Unit   string `json:"unit"`
	Action string `json:"action"`
}

type controlData struct {
	Unit   string        `json:"unit"`
	Action string        `json:"action"`
	Status serviceStatus `json:"status"`
}

// polkitDenied reports whether a failed systemctl verb was refused by
// polkit (verified at the source, systemd 257 and 259): polkit "no" is
// org.freedesktop.DBus.Error.AccessDenied, exit 4 (EXIT_NOPERMISSION); a
// challenge that --no-ask-password cannot answer is
// InteractiveAuthorizationRequired, exit 1 with "Interactive authentication
// required." (257) or "...requires interactive authentication..." (259).
// systemd does not translate these messages.
func polkitDenied(res *execx.Result) bool {
	if exited(res, 4) {
		return true
	}
	return exited(res, 1) && (bytes.Contains(res.Stderr, []byte("Interactive authentication required")) ||
		bytes.Contains(res.Stderr, []byte("requires interactive authentication")))
}

// serviceControl runs systemctl --no-ask-password <verb> -- <unit> as the
// service user (authorized by the generated polkit rule, never sudo) and
// re-reads the unit's status.
func (s *server) serviceControl(raw jsontext.Value) (data any, warns []string, failure error) {
	var a controlArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if !systemd.ValidUnit(a.Unit) {
		return nil, nil, errf(protocol.CodeBadRequest, "unit must be an exact unit name with a type suffix")
	}
	if !slices.Contains([]string{"start", "stop", "restart", "reload"}, a.Action) {
		return nil, nil, errf(protocol.CodeBadRequest, "action must be start, stop, restart or reload")
	}
	if !slices.Contains(s.p.Services.ControlUnits, a.Unit) {
		return nil, nil, errf(protocol.CodePolicyDenied, "unit is not in services.control.units")
	}
	if !slices.Contains(s.p.Services.ControlVerbs, a.Action) {
		return nil, nil, errf(protocol.CodePolicyDenied, "action is not in services.control.verbs")
	}
	res, err := s.runBuiltin(s.o.Systemctl, "systemctl", []string{"--no-ask-password", a.Action, "--", a.Unit}, nil, "/")
	if err != nil {
		return nil, nil, err
	}
	switch {
	case polkitDenied(&res):
		return nil, nil, errf(protocol.CodeNotAuthorized, "polkit refused systemctl %s for this unit (%s); install the rule from shell-mcp-gate polkit",
			a.Action, exitStatus(&res))
	case !exited(&res, 0):
		return nil, nil, errf(protocol.CodeExecFailed, "systemctl %s failed (%s)", a.Action, exitStatus(&res))
	}
	d := controlData{Unit: a.Unit, Action: a.Action}
	st, err := s.status(a.Unit)
	var warnings []string
	var oe *opError
	switch {
	case err == nil:
		d.Status = st
	case errors.As(err, &oe):
		warnings = append(warnings, fmt.Sprintf("the action succeeded but the status could not be re-read: %s", oe.msg))
	default:
		warnings = append(warnings, "the action succeeded but the status could not be re-read")
	}
	return d, warnings, nil
}
