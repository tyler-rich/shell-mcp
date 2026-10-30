//go:build linux

package ops

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/procfs"
	"github.com/tyler-rich/shell-mcp/internal/gate/procself"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/redact"
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
// roots, under the chain rule (fsx.Config.GuardExecPaths, handoff N-10):
// the command looks the resolved path up again itself, as root, so only a
// path whose directories from / to its parent no account but root can
// change is given to it. The privileged policy declares no units.
type resolver struct{ s *server }

func (r resolver) ResolvePath(v string, write bool) (string, error) {
	if write {
		return r.s.fs.ResolveWrite(v)
	}
	return r.s.fs.ResolveRead(v)
}

// ResolveReadFD refuses: the privileged policy refuses {path:read:fd} at
// load (root commands get closed paths only), and this keeps a template
// that reached the helper anyway from running.
func (resolver) ResolveReadFD(string) (*os.File, string, error) {
	return nil, "", &fsx.Error{Code: protocol.CodePolicyDenied, Msg: "{path:read:fd} is not available in the privileged policy; nothing was run"}
}

func (resolver) MatchUnit(string) bool { return false }

// responseBudget leaves room for the envelope inside MaxResponseBytes.
const responseBudget = protocol.MaxResponseBytes - 256<<10

// execHome is HOME for root commands: the helper has no home of its own.
// The core unit hides /root (ProtectHome=yes) or leaves it read-only, and
// the helper's Landlock domain grants nothing under it either way.
const execHome = "/root"

// resolvedExec is a privileged command resolved for one request: the
// command, the template its arguments matched, the arguments as they are
// passed (path placeholders resolved) and the working directory.
type resolvedExec struct {
	c        *policy.Command
	template int
	args     []string
	dir      string
	// strict: the output gets redact.MaskKeyBodies, for a command that
	// declares reads_private_keys or reads a file too large to search
	// (handoff N-35).
	strict bool
}

// resolveExec is the one resolution priv_exec and priv_exec_preview share
// (handoff D6), so what a preview shows is what priv_exec runs: the command
// declared; unitOK on it (priv_exec: the command runs in this instance's
// unit; the preview: nothing, since the core instance previews commands of
// either unit); the command's tier against max_tier and the request's
// ceiling, before anything else about the request; the template its
// arguments match, with {path:read} and {path:write} resolved under the
// privileged roots; and the working directory. Placeholders and the working
// directory are refused (path_denied) unless every directory from / to
// their parent is closed (N-10), so the preview requests no approval for a
// path priv_exec would refuse.
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
	// A file that holds a private key could be printed in part, without its
	// BEGIN line (handoff N-35): refused unless the command opts in.
	over, err := s.fs.CommandKeyInputs(c.ID, &c.Templates[i], out, nil, c.ReadsPrivateKeys)
	if err != nil {
		return nil, err
	}
	return &resolvedExec{c: c, template: i, args: out, dir: dir, strict: over || c.ReadsPrivateKeys}, nil
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
		Trampoline:  s.o.Executable,
		Path:        rx.c.Resolved,
		Args:        rx.args,
		Env:         execx.Environment(execHome),
		Dir:         rx.dir,
		Timeout:     s.timeout(),
		MaxOutput:   maxOut,
		MaxMemoryMB: s.p.Limits.MaxMemoryMB,
	}, rx.c.Tier > policy.TierRead)
	if err != nil {
		return nil, nil, err
	}
	if rx.strict {
		res.Stdout = redact.MaskKeyBodies(s.red.Bytes(res.Stdout), redact.PlainLines)
		res.Stderr = redact.MaskKeyBodies(s.red.Bytes(res.Stderr), redact.PlainLines)
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
// grace, on its process group) before the answer, which is outcome_unknown
// for a command that can change the host (mayChange) and timeout for a
// read command. With ReapOrphans, the helper is a child subreaper while the
// command runs, so what the command started outside its process group
// becomes the helper's child when its parent ends; after the command,
// however it ended, the helper kills and reaps every child left, and
// answers outcome_unknown (never a success) when it cannot confirm that
// none is left.
func (s *server) runCommand(spec *execx.Spec, mayChange bool) (execx.Result, error) {
	if s.conn != nil && (connHungUp(s.conn) || closed(s.hangup())) {
		s.hungUp = true
		return execx.Result{}, errf(protocol.CodeTimeout, "the gate stopped waiting before the command started; nothing was run")
	}
	if s.o.ReapOrphans && s.o.ReapHooks == nil {
		// Without it, what the command leaves behind would escape the reaping.
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			s.reapErr = "PR_SET_CHILD_SUBREAPER: " + err.Error()
			return execx.Result{}, errf(protocol.CodeExecFailed, "the helper could not make itself a child subreaper, so it could not account for what the command would start; nothing was run")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hung atomic.Bool
	if s.conn != nil {
		hangup := s.hangup()
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
	if s.o.ReapOrphans {
		if rerr := s.reap(); rerr != nil {
			s.reapErr = rerr.Error()
			return res, errf(protocol.CodeOutcomeUnknown, "the helper could not confirm that every process the command started has ended "+
				"(see its journal on the host); the command may still be running or have changed the host")
		}
	}
	if err != nil {
		return res, err
	}
	// execx reports TimedOut only when it stopped the command (its deadline,
	// or this cancel); a hang-up after the command ended changes nothing.
	if hung.Load() && res.TimedOut {
		s.hungUp = true
		code := protocol.CodeTimeout
		if mayChange {
			code = protocol.CodeOutcomeUnknown
		}
		return res, errf(code, "the gate stopped waiting (its connection closed) while the command ran; "+
			"the command and every process it started were stopped before this answer, and what it changed before then stays")
	}
	return res, nil
}

// pollFn is poll(2); tests inject its errors.
var pollFn = unix.Poll

// maxPollEINTR bounds connHungUp's retries of an interrupted poll.
const maxPollEINTR = 100

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
		// poll(2) is never restarted after a signal handler (signal(7)), and
		// the runtime's own signals can interrupt it: poll again. Still
		// interrupted after maxPollEINTR tries, the gate counts as gone, so
		// nothing is started (fail closed).
		for range maxPollEINTR {
			n, err := pollFn(fds, 0)
			if errors.Is(err, unix.EINTR) {
				gone = true
				continue
			}
			gone = err == nil && n > 0 && fds[0].Revents != 0
			return
		}
	})
	return gone
}

// hangup is the connection's one hang-up watcher (watchHangup), started on
// first use and shared by everything that waits for the gate to go away in
// this request; without a connection, a channel never closed.
func (s *server) hangup() <-chan struct{} {
	s.hangOnce.Do(func() {
		if s.conn == nil {
			s.hangCh = make(chan struct{})
			return
		}
		s.hangCh = watchHangup(s.conn)
	})
	return s.hangCh
}

// closed reports whether ch is closed, without waiting.
func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
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

// ReapHooks replace how ReapOrphans lists this process's children and
// waits for them (and skip PR_SET_CHILD_SUBREAPER); tests only.
type ReapHooks struct {
	// Children lists the children (production: task/*/children of the
	// helper's own /proc/<pid>, through the descriptor opened before the
	// sandbox).
	Children func() ([]int, error)
	// Fallback lists them another way (production: /proc/[0-9]*/stat);
	// nil means none.
	Fallback func() ([]int, error)
	// Wait is wait4(-1, WNOHANG): the pid of a child that ended, 0 when
	// children are left and none ended, or ECHILD when none is left.
	Wait func() (int, error)
}

// reap kills and reaps every child left after a command (reapOrphans), with
// the test hooks when set.
func (s *server) reap() error {
	lists, wait := []func() ([]int, error){func() ([]int, error) { return childrenIn(s.proc) }, childrenByStat}, waitAnyChild
	if h := s.o.ReapHooks; h != nil {
		lists, wait = []func() ([]int, error){h.Children}, h.Wait
		if h.Fallback != nil {
			lists = append(lists, h.Fallback)
		}
	}
	return reapOrphans(reapBound, lists, func(pid int) { _ = unix.Kill(pid, unix.SIGKILL) }, wait)
}

func waitAnyChild() (int, error) {
	var ws unix.WaitStatus
	return unix.Wait4(-1, &ws, unix.WNOHANG, nil)
}

// reapOrphans kills (SIGKILL) and reaps every child this process still
// has: as a child subreaper, a process a command started that left its
// process group became this process's child when its parent ended. Each
// round lists the children (so one born of a process killed in the
// previous round, reparented here, is killed in the next), kills them, and
// reaps whatever has ended; the rounds go on until wait4 says no child is
// left. Each round uses the first of lists that works (the per-thread
// children files, then the /proc scan), and a round whose listings all
// fail kills what they found and lists again in the next (handoff N-30:
// after an OOM kill in the instance, the listing failed once and the reap
// gave up). It fails closed: it returns nil only when wait4 reports ECHILD
// (the kernel's own word that no child is left, whatever the listings
// said), and after bound an error carrying the last round's listing error,
// or saying that children were still there.
func reapOrphans(bound time.Duration, lists []func() ([]int, error), kill func(int), wait func() (int, error)) error {
	deadline := time.Now().Add(bound)
	for {
		pids, lerr := listChildren(lists)
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
			if lerr != nil {
				return fmt.Errorf("the children could not be listed, so some may be left: %w", lerr)
			}
			return fmt.Errorf("children of the command were still there %v after it ended", bound)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// maxChildren bounds the children read from /proc.
const maxChildren = 4096

// maxTasks bounds the helper's own threads the listing reads, and
// maxChildrenBytes one thread's children file.
const (
	maxTasks         = 4096
	maxChildrenBytes = 64 << 10
)

// childrenByStat is the fallback listing: the processes in /proc whose
// parent is this process. In the core unit Landlock grants no read of
// other processes' /proc entries, so there it fails with the real error
// (EACCES); it serves where no Landlock ruleset applies (the broad unit).
func childrenByStat() ([]int, error) { return childrenByStatIn("/proc", os.Getpid()) }

// ended reports an error that means the process or thread went away
// between the listing and the read.
func ended(err error) bool { return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) }

// childrenIn lists the children from task/<tid>/children under proc (the
// helper's own /proc/<pid>, opened before the sandbox: procself; its
// Landlock ruleset and ProcSubset=pid leave it readable), with the real
// error: the task directory or a children file that cannot be read (its
// errno included), or no children file read at all (a kernel without
// CONFIG_PROC_CHILDREN). A thread that ended meanwhile is skipped. Reading
// through proc's descriptor, not the /proc/self path, keeps the core
// unit's Landlock rule covering the reads after memory pressure in the
// instance (an OOM kill), which can make the path reach a new procfs inode.
func childrenIn(proc *procself.Dir) ([]int, error) {
	if proc == nil {
		return nil, errors.New("no /proc/self descriptor")
	}
	tids, err := proc.ReadDirNames("task", maxTasks)
	if err != nil {
		return nil, err
	}
	var out []int
	read := 0
	for _, tid := range tids {
		if n, err := strconv.Atoi(tid); err != nil || n <= 0 {
			return out, fmt.Errorf("%s/task/%s: not a thread id", proc.Path(), tid)
		}
		p := proc.Path() + "/task/" + tid + "/children"
		b, err := proc.ReadFile("task/"+tid+"/children", maxChildrenBytes)
		if ended(err) {
			continue
		}
		if err != nil {
			return out, err
		}
		read++
		for _, f := range strings.Fields(string(b)) {
			pid, err := strconv.Atoi(f)
			if err != nil || pid <= 1 {
				return out, fmt.Errorf("%s: not a child pid list", p)
			}
			if len(out) == maxChildren {
				return out, fmt.Errorf("more than %d children", maxChildren)
			}
			out = append(out, pid)
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("no %s/task/*/children file could be read", proc.Path())
	}
	return out, nil
}

// maxStatScan bounds the /proc entries childrenByStatIn reads.
const maxStatScan = 1 << 16

// childrenByStatIn lists the processes under procDir (/proc) whose parent
// pid, from <pid>/stat, is ppid, with the real error: procDir that cannot
// be listed, more entries than maxStatScan, or a stat file that cannot be
// read or parsed. A process that ended meanwhile is skipped.
func childrenByStatIn(procDir string, ppid int) ([]int, error) {
	d, err := os.Open(procDir) //nolint:gosec // G304: /proc, or the tests' own directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	names, err := d.Readdirnames(maxStatScan + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maxStatScan {
		return nil, fmt.Errorf("%s has more than %d entries", procDir, maxStatScan)
	}
	var out []int
	for _, n := range names {
		pid, err := strconv.Atoi(n)
		if err != nil || pid <= 0 {
			continue // not a process
		}
		p := procDir + "/" + n + "/stat"
		b, err := os.ReadFile(p) //nolint:gosec // G304: a numeric entry of the fixed /proc directory
		if ended(err) {
			continue
		}
		if err != nil {
			return out, err
		}
		st, err := procfs.ParsePIDStat(b)
		if err != nil || st.PID != pid {
			return out, fmt.Errorf("%s: not a stat line", p)
		}
		if st.PPID == ppid {
			if len(out) == maxChildren {
				return out, fmt.Errorf("more than %d children", maxChildren)
			}
			out = append(out, pid)
		}
	}
	return out, nil
}

// listChildren kills nothing; it returns the children from the first
// listing that works, or, when every listing fails, what they found and all
// their errors (each with its errno).
func listChildren(lists []func() ([]int, error)) ([]int, error) {
	var found []int
	var errs error
	for _, l := range lists {
		pids, err := l()
		if err == nil {
			return pids, nil
		}
		found = append(found, pids...)
		if errs == nil {
			errs = err
		} else {
			errs = fmt.Errorf("%w; fallback: %w", errs, err)
		}
	}
	return found, errs
}
