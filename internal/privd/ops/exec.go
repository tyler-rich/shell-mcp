//go:build linux

package ops

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// execArgs has no stdin: the privileged policy declares no stdin limit, so
// root commands always read /dev/null.
type execArgs struct {
	CommandID      string   `json:"command_id"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	// Unit is the routing label the server supplies from the command's
	// preview so that the gate can pick the socket (the gate cannot read the
	// privileged policy): "", "core" or "broad". The helper decides by the
	// command's declared unit; a label that disagrees with this instance is
	// refused.
	Unit string `json:"unit"`
	// ExpectedPreviewSHA256 is the preview_sha256 priv_exec_preview returned
	// for the same command, arguments and cwd: required for an operator or
	// destructive command, which approval always covers, and optional for a
	// read command (handoff P-3, Q14).
	ExpectedPreviewSHA256 *string `json:"expected_preview_sha256"`
}

type execData struct {
	CommandID       string   `json:"command_id"`
	Argv            []string `json:"argv"`
	ExitCode        *int     `json:"exit_code"`
	Signal          *string  `json:"signal"`
	TimedOut        bool     `json:"timed_out"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
	DurationMS      int64    `json:"duration_ms"`
}

// resolver resolves {path:read} and {path:write} against the privileged
// roots; the privileged policy declares no units.
type resolver struct{ s *server }

func (r resolver) ResolvePath(v string, write bool) (string, error) {
	if write {
		return r.s.fs.ResolveWrite(v)
	}
	return r.s.fs.ResolveRead(v)
}

func (resolver) MatchUnit(string) bool { return false }

// responseBudget leaves room for the envelope inside MaxResponseBytes.
const responseBudget = protocol.MaxResponseBytes - 256<<10

// execHome is HOME for root commands: ProtectHome=read-only leaves /root
// read-only, and the helper has no home of its own.
const execHome = "/root"

// resolvedExec is a privileged command resolved for one request: the
// command, the template its arguments matched, the arguments as they are
// passed (path placeholders resolved) and the working directory.
type resolvedExec struct {
	c        *policy.Command
	template int
	args     []string
	dir      string
}

// resolveExec is the one resolution priv_exec and priv_exec_preview share
// (handoff D6), so what a preview shows is what priv_exec runs: the command
// declared; unitOK on it (priv_exec: the command runs in this instance's
// unit; the preview: nothing, since the core instance previews commands of
// either unit); the command's tier against max_tier and the request's
// ceiling, before anything else about the request; the template its
// arguments match, with {path:read} and {path:write} resolved under the
// privileged roots; and the working directory.
func (s *server) resolveExec(id string, args []string, cwd string, unitOK func(*policy.Command) error) (*resolvedExec, error) {
	c, ok := s.p.Command(id)
	if !ok {
		return nil, errf(protocol.CodePolicyDenied, "command_id is not declared in the privileged policy")
	}
	if err := unitOK(c); err != nil {
		return nil, err
	}
	if err := s.within("command", c.Tier); err != nil {
		return nil, err
	}
	if len(args) > template.MaxTokens {
		return nil, errf(protocol.CodeBadRequest, "at most %d arguments", template.MaxTokens)
	}
	i, out, err := template.MatchIndex(c.Templates, args, resolver{s})
	if err != nil {
		return nil, err
	}
	dir := "/"
	if cwd != "" {
		if dir, err = s.fs.ResolveDir(cwd); err != nil {
			return nil, err
		}
	}
	return &resolvedExec{c: c, template: i, args: out, dir: dir}, nil
}

type execPreviewArgs struct {
	CommandID string   `json:"command_id"`
	Args      []string `json:"args"`
	Cwd       string   `json:"cwd"`
}

// execPreviewData is priv_exec_preview's result (handoff P-2d).
type execPreviewData struct {
	CommandID      string   `json:"command_id"`
	Tier           string   `json:"tier"`
	Unit           string   `json:"unit"`
	Description    string   `json:"description"`
	RootEquivalent bool     `json:"root_equivalent"`
	Capabilities   []string `json:"capabilities"`
	Template       []string `json:"template"`
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

const execPreviewDomain = "shell-mcp priv exec preview v1\x00"

// preview describes the resolved command; preview_sha256 covers every
// field, this policy's SHA-256 and the unit included, each length-prefixed
// and every list counted.
func (rx *resolvedExec) preview(policySHA string) execPreviewData {
	caps := slices.Clone(rx.c.Capabilities)
	if caps == nil {
		caps = []string{}
	}
	d := execPreviewData{
		CommandID: rx.c.ID, Tier: rx.c.Tier.String(), Unit: string(rx.c.Unit), Description: rx.c.Description, RootEquivalent: rx.c.RootEquivalent,
		Capabilities: caps, Template: rx.c.Templates[rx.template].String(), Argv: append([]string{rx.c.Resolved}, rx.args...), Cwd: rx.dir,
		PolicySHA256: policySHA,
	}
	b := []byte(execPreviewDomain)
	for _, f := range []string{d.PolicySHA256, d.CommandID, d.Tier, d.Unit, d.Description, d.Cwd} {
		b = appendField(b, f)
	}
	if d.RootEquivalent {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	for _, list := range [][]string{d.Capabilities, d.Template, d.Argv} {
		b = binary.AppendUvarint(b, uint64(len(list)))
		for _, f := range list {
			b = appendField(b, f)
		}
	}
	h := sha256.Sum256(b)
	d.PreviewSHA256 = hex.EncodeToString(h[:])
	return d
}

// appendField appends s with its length.
func appendField(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// execPreview resolves a command exactly as priv_exec would, in the core
// instance for commands of either unit, and runs nothing (handoff P-2d).
func (s *server) execPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a execPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	rx, err := s.resolveExec(a.CommandID, a.Args, a.Cwd, func(*policy.Command) error { return nil })
	if err != nil {
		return nil, nil, err
	}
	return rx.preview(s.p.SHA256), nil, nil
}

func (s *server) exec(raw jsontext.Value) (data any, warns []string, failure error) {
	var a execArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	label := policy.Unit(a.Unit)
	switch label {
	case "", policy.UnitCore, policy.UnitBroad:
	default:
		return nil, nil, errf(protocol.CodeBadRequest, "unit must be core or broad")
	}
	// The unit before anything else about the command: a command declared for
	// the other unit, or a request labelled for it, never runs here.
	rx, err := s.resolveExec(a.CommandID, a.Args, a.Cwd, func(c *policy.Command) error {
		if c.Unit != s.unit {
			return s.wrongUnit(c.Unit)
		}
		if label != "" && label != s.unit {
			return s.wrongUnit(label)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// The approved preview, recomputed here, in this instance's unit (Q14).
	want := a.ExpectedPreviewSHA256
	switch {
	case want == nil && rx.c.Tier > policy.TierRead:
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 is required for an operator or destructive command: "+
			"the preview_sha256 that priv_exec_preview returned for the same command, arguments and cwd")
	case want != nil && !fsx.ValidPreviewSHA256(*want):
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that priv_exec_preview returned")
	case want != nil && rx.preview(s.p.SHA256).PreviewSHA256 != *want:
		return nil, nil, errf(protocol.CodeExists, "the command resolves differently than its preview in the %s unit (its preview_sha256 differs: "+
			"the privileged policy, the command, a path placeholder or the cwd changed); nothing was run", s.unit)
	}
	maxOut := s.p.Limits.MaxOutputBytes
	if a.MaxOutputBytes != 0 {
		if a.MaxOutputBytes < 1 || a.MaxOutputBytes > maxOut {
			return nil, nil, errf(protocol.CodeBadRequest, "max_output_bytes must be 1..%d", maxOut)
		}
		maxOut = a.MaxOutputBytes
	}
	res, err := s.runCommand(&execx.Spec{
		Trampoline: s.o.Executable,
		Path:       rx.c.Resolved,
		Args:       rx.args,
		Env:        execx.Environment(execHome),
		Dir:        rx.dir,
		Timeout:    s.timeout(),
		MaxOutput:  maxOut,
	})
	if err != nil {
		return nil, nil, err
	}
	stdout, cutOut := s.red.Truncate(res.Stdout, maxOut)
	stderr, cutErr := s.red.Truncate(res.Stderr, maxOut)
	d := execData{
		CommandID:       rx.c.ID,
		Argv:            append([]string{rx.c.Resolved}, rx.args...),
		ExitCode:        res.ExitCode,
		TimedOut:        res.TimedOut,
		Stdout:          string(stdout),
		Stderr:          string(stderr),
		StdoutTruncated: res.StdoutTruncated || cutOut,
		StderrTruncated: res.StderrTruncated || cutErr,
		DurationMS:      res.Duration.Milliseconds(),
	}
	if res.Signal != "" {
		sig := res.Signal
		d.Signal = &sig
	}
	var warnings []string
	if res.OutputCeilingHit {
		warnings = append(warnings, "output exceeded the hard ceiling; the process group was killed")
	}
	for i := 0; i < 24; i++ {
		b, err := protocol.Marshal(d)
		if err != nil || len(b) <= responseBudget {
			break
		}
		if i == 0 {
			warnings = append(warnings, "output was cut further to fit the 4 MiB response limit")
		}
		if len(d.Stdout) >= len(d.Stderr) {
			out, _ := s.red.Truncate([]byte(d.Stdout), len(d.Stdout)/2)
			d.Stdout, d.StdoutTruncated = string(out), true
		} else {
			out, _ := s.red.Truncate([]byte(d.Stderr), len(d.Stderr)/2)
			d.Stderr, d.StderrTruncated = string(out), true
		}
	}
	return d, warnings, nil
}

// reapBound bounds how long the helper kills and reaps what a command left.
const reapBound = 5 * time.Second

// runCommand runs a resolved command and stops it when the gate goes away
// (handoff must-fix (a), PRIVILEGED §6 "Timeouts, and a gate that goes
// away"). The gate sends one request and then only reads, so anything on
// the connection — end of file when the gate exits, is killed or shuts
// down its sending side because it stopped waiting, a reset, or a further
// byte — is a hang-up: a command not yet started is not started, and a
// running one is stopped as at its timeout (SIGTERM, then SIGKILL after the
// grace, on its process group) before the answer. With ReapOrphans, the
// helper is a child subreaper while the command runs, so what the command
// started outside its process group becomes the helper's child when its
// parent ends, and is killed and reaped after the command, however it
// ended, before the answer.
func (s *server) runCommand(spec *execx.Spec) (execx.Result, error) {
	if s.conn != nil && connHungUp(s.conn) {
		s.hungUp = true
		return execx.Result{}, errf(protocol.CodeTimeout, "the gate stopped waiting before the command started; nothing was run")
	}
	if s.o.ReapOrphans {
		_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
		defer func() { _ = reapOrphans(reapBound, func() ([]int, error) { return children(), nil }, func(pid int) { _ = unix.Kill(pid, unix.SIGKILL) }, waitAnyChild) }()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hung atomic.Bool
	if s.conn != nil {
		hangup := watchHangup(s.conn)
		done := make(chan struct{})
		defer func() { cancel(); <-done }()
		go func() {
			defer close(done)
			select {
			case <-hangup:
				hung.Store(true)
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	res, err := execx.Run(ctx, spec)
	if err != nil {
		return res, err
	}
	// execx reports TimedOut only when it stopped the command (its deadline,
	// or this cancel); a hang-up after the command ended changes nothing.
	if hung.Load() && res.TimedOut {
		s.hungUp = true
		return res, errf(protocol.CodeTimeout, "the gate stopped waiting (its connection closed) while the command ran; "+
			"the command and every process it started were stopped before this answer, and what it changed before then stays")
	}
	return res, nil
}

// connHungUp reports, without blocking, whether anything is readable on the
// connection: end of file, a reset, or bytes the gate should never send.
func connHungUp(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	gone := false
	_ = rc.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLRDHUP}} //nolint:gosec // G115: a descriptor fits in int32
		n, err := unix.Poll(fds, 0)
		gone = err == nil && n > 0 && fds[0].Revents != 0
	})
	return gone
}

// watchHangup returns a channel closed when a read on the connection
// returns: end of file, an error, or a byte (each a hang-up). The read
// ends when the connection is closed at the end of Serve.
func watchHangup(c net.Conn) <-chan struct{} {
	ch := make(chan struct{})
	_ = c.SetReadDeadline(time.Time{})
	go func() {
		defer close(ch)
		_, _ = c.Read(make([]byte, 1))
	}()
	return ch
}

// reapOrphans kills (SIGKILL) and reaps every child this process still
// has, for at most bound: as a child subreaper, a process a command started
// that left its process group became this process's child when its parent
// ended. Children are listed in /proc/self/task/*/children (the helper's
// own /proc/<pid>, which its Landlock ruleset and ProcSubset=pid leave
// readable); it returns once wait4 says no child is left.
func reapOrphans(bound time.Duration, list func() ([]int, error), kill func(int), wait func() (int, error)) error {
	// Stub (failing-first commit): the old, fail-open behaviour.
	deadline := time.Now().Add(bound)
	for {
		pids, _ := list()
		for _, pid := range pids {
			kill(pid)
		}
		for {
			pid, err := wait()
			if errors.Is(err, unix.ECHILD) {
				return nil
			}
			if err != nil || pid <= 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitAnyChild() (int, error) {
	var ws unix.WaitStatus
	return unix.Wait4(-1, &ws, unix.WNOHANG, nil)
}

// ReapHooks is a stub (failing-first commit): accepted and ignored.
type ReapHooks struct {
	Children func() ([]int, error)
	Wait     func() (int, error)
}

// maxChildren bounds the children read from /proc.
const maxChildren = 4096

// children lists this process's children from /proc/self/task/*/children.
func children() []int {
	tasks, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		b, err := os.ReadFile(t) //nolint:gosec // G304: a /proc/self path from a fixed pattern
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if pid, err := strconv.Atoi(f); err == nil && pid > 1 && len(out) < maxChildren {
				out = append(out, pid)
			}
		}
	}
	return out
}
