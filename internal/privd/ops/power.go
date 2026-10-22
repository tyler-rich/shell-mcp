//go:build linux

package ops

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The power operations (PRIVILEGED §6, "Power"; handoff S4c-8, design B2,
// decided by the maintainer on 2026-10-22). A reboot or power-off ends the
// connection that carries its own answer, so priv_power answers first,
// confirms that the gate read the answer, waits a fixed delay holding the
// package operation record (no package operation of this helper can start,
// nor a second power action), checks again, and only then asks logind:
// org.freedesktop.login1.Manager.RebootWithFlags or PowerOffWithFlags with
// SD_LOGIND_ROOT_CHECK_INHIBITORS, never SD_LOGIND_SKIP_INHIBITORS. logind
// refuses while a block inhibitor holds (for root with that flag, a
// block-weak one of another uid too), waits for delay inhibitors, and
// starts the target with replace-irreversibly itself: an orderly shutdown
// (systemd 257 and 259, logind-dbus.c, method_do_shutdown_or_sleep and
// verify_shutdown_creds). Not PID 1's StartUnit, which consults no
// inhibitor, and not logind's ScheduleShutdown, which checks block
// inhibitors only when scheduling and creates /run/nologin five minutes
// before its time (immediately for a shorter delay), refusing the gate's
// own login. priv_power_preview reports what priv_power would do and
// refuses whatever would block it; priv_power_cancel stops a waiting
// action through the decision file. The core unit can never do any of
// this: its /run, and so the bus socket, is an empty tmpfs.

const (
	// powerDelay is the time between the answer and the request to
	// logind.
	powerDelay = 60 * time.Second
	// powerConfirmWait bounds how long the gate has to read the answer.
	powerConfirmWait = 10 * time.Second
	// powerTimeout bounds each exchange with the bus.
	powerTimeout = 10 * time.Second
	// powerPoll is how often a waiting action looks for a cancel.
	powerPoll = 200 * time.Millisecond
	// powerCancelWait bounds how long a cancel waits for the waiting
	// instance to release the record.
	powerCancelWait = 5 * time.Second
	// minPowerTimeoutS is the least limits.max_timeout_s that lets the
	// instance outlive the delay inside RuntimeMaxSec= (max_timeout_s + 30 s):
	// the delay, the confirmation and the logind call take at most 80 s.
	minPowerTimeoutS = 60
	// logindRootCheckInhibitors is SD_LOGIND_ROOT_CHECK_INHIBITORS
	// (src/basic/login-util.h, systemd 257 and 259): root's request is
	// refused by block-weak inhibitors of other users too. No other flag is
	// ever passed (SD_LOGIND_SKIP_INHIBITORS would ignore them).
	logindRootCheckInhibitors = uint64(1)
	// DefaultPowerDecision is the decision file a cancel and a waiting
	// action arbitrate through.
	DefaultPowerDecision = "/run/shell-mcp-privd-power"

	logindDest  = "org.freedesktop.login1"
	logindPath  = "/org/freedesktop/login1"
	logindIface = "org.freedesktop.login1.Manager"

	powerPreviewDomain = "shell-mcp priv power preview v1\x00"
)

type powerPreviewArgs struct {
	Action string `json:"action"`
}

type powerArgs struct {
	Action                string  `json:"action"`
	ExpectedPreviewSHA256 *string `json:"expected_preview_sha256"`
}

type powerPreviewData struct {
	Action        string `json:"action"`
	Target        string `json:"target"`
	DelayS        int64  `json:"delay_s"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type powerData struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	ScheduledAt string `json:"scheduled_at"`
	DelayS      int64  `json:"delay_s"`
	Cancel      string `json:"cancel"`
}

type powerCancelData struct {
	Cancelled   bool   `json:"cancelled"`
	RequestID   string `json:"request_id"`
	Action      string `json:"action"`
	ScheduledAt string `json:"scheduled_at"`
}

// powerDecision is the decision file's contents: "cancel", written by
// priv_power_cancel, or "commit", written by the waiting action just before
// it asks logind; whichever creates the file first decides.
type powerDecision struct {
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
}

func (s *server) delay() time.Duration {
	if s.o.PowerDelay > 0 {
		return s.o.PowerDelay
	}
	return powerDelay
}

func (s *server) delayS() int64 { return int64(s.delay() / time.Second) }

// powerPreviewHash covers the domain, this policy's SHA-256, the action, the
// target and the delay: never a time (the re-call's fresh preview would
// differ), and never a blocker (a blocker refuses instead).
func powerPreviewHash(policySHA, action, target string, delayS int64) string {
	b := []byte(powerPreviewDomain)
	for _, f := range []string{policySHA, action, target, fmt.Sprint(delayS)} {
		b = binary.AppendUvarint(b, uint64(len(f)))
		b = append(b, f...)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// powerAllowed checks the request against the policy: a known action,
// listed in power.allowed itself (reboot never allows poweroff), the
// destructive tier within max_tier, and a limit the instance can wait in.
func (s *server) powerAllowed(action string) error {
	if !slices.Contains(policy.PowerActions, action) {
		return errf(protocol.CodeBadRequest, "action must be reboot or poweroff")
	}
	if !slices.Contains(s.p.Power.Allowed, action) {
		return errf(protocol.CodePolicyDenied, "the privileged policy's power section does not allow %s (each action must be listed in power.allowed itself)", action)
	}
	if s.p.MaxTier < policy.TierDestructive {
		return errf(protocol.CodeTierDenied, "priv_power is destructive and exceeds the privileged policy's max_tier %s", s.p.MaxTier)
	}
	if s.p.Limits.MaxTimeoutS < minPowerTimeoutS {
		return errf(protocol.CodePolicyDenied, "the privileged policy's limits.max_timeout_s is %d; priv_power needs at least %d, because its instance waits %d s before asking logind",
			s.p.Limits.MaxTimeoutS, minPowerTimeoutS, s.delayS())
	}
	return nil
}

// powerResolve is the preview, shared by priv_power_preview and priv_power:
// the policy's checks, everything that would block the action (held says
// the caller holds the record itself), and the hash.
func (s *server) powerResolve(action string, held bool) (*powerPreviewData, error) {
	if err := s.powerAllowed(action); err != nil {
		return nil, err
	}
	if err := s.powerBlockers(held); err != nil {
		return nil, err
	}
	target := action + ".target"
	return &powerPreviewData{Action: action, Target: target, DelayS: s.delayS(), PolicySHA256: s.p.SHA256,
		PreviewSHA256: powerPreviewHash(s.p.SHA256, action, target, s.delayS())}, nil
}

// powerBlockers refuses, naming it, whatever would block the action: a
// package operation of this helper or another power action (the record;
// unless held), the dpkg frontend lock held by another process, packages
// dpkg left unfinished, a logind inhibitor lock on shutdown in mode block
// or block-weak, a shutdown logind has scheduled, or one it is preparing.
func (s *server) powerBlockers(held bool) error {
	if !held {
		if err := s.notInProgress(); err != nil {
			return err
		}
	}
	if err := s.powerPackageChecks(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), powerTimeout)
	defer cancel()
	c, err := s.dialBus(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := inhibited(c); err != nil {
		return err
	}
	var sched []any
	if err := logindProperty(c, "ScheduledShutdown", "(st)", &sched); err != nil {
		return err
	}
	if what, ok := sched[0].(string); !ok || what != "" {
		return errf(protocol.CodeExecFailed, "logind already has a shutdown scheduled (%s); nothing was scheduled; an administrator cancels it on the host with shutdown -c", cleanText(fmt.Sprint(sched[0]), 40))
	}
	var preparing bool
	if err := logindProperty(c, "PreparingForShutdown", "b", &preparing); err != nil {
		return err
	}
	if preparing {
		return errf(protocol.CodeExecFailed, "the host is already shutting down; nothing was scheduled")
	}
	return nil
}

// powerPackageChecks: the dpkg frontend lock free, and nothing dpkg left
// unfinished. A power action must never interrupt a package operation.
func (s *server) powerPackageChecks() error {
	h, held, err := pkgLockHolder(s.dpkgLock())
	switch {
	case err != nil:
		return errf(protocol.CodeExecFailed, "the dpkg frontend lock could not be checked (%s); nothing was scheduled", err.Error())
	case held:
		return errf(protocol.CodeExecFailed, "a package operation is running: the dpkg frontend lock is held by %s; nothing was scheduled; preview again after it ends", h)
	}
	st, err := pkg.ReadStatus(s.o.DpkgDir)
	if err != nil {
		return errf(protocol.CodeExecFailed, "dpkg's status could not be read (%s); nothing was scheduled", err.Error())
	}
	return unfinishedErr(st, s.o.DpkgDir, "nothing was scheduled")
}

func (s *server) dialBus(ctx context.Context) (*dbus.Conn, error) {
	bus := s.o.SystemBus
	if bus == "" {
		bus = dbus.SystemBus
	}
	c, err := dbus.Dial(ctx, bus, os.Getuid())
	if err != nil {
		return nil, errf(protocol.CodeExecFailed, "the system bus cannot be reached, so logind could not be asked; nothing was scheduled")
	}
	return c, nil
}

// inhibited refuses while a logind inhibitor lock on shutdown in mode block
// or block-weak is held (ListInhibitors: what, who, why, mode, uid, pid). A
// delay inhibitor does not block: logind waits for it when the action is
// requested.
func inhibited(c *dbus.Conn) error {
	r, err := c.Call(logindDest, logindPath, logindIface, "ListInhibitors")
	if err != nil {
		return busErr("ListInhibitors", err)
	}
	v, err := r.Values()
	if err != nil || r.Signature != "a(ssssuu)" || len(v) != 1 {
		return errf(protocol.CodeExecFailed, "logind's list of inhibitor locks could not be read; nothing was scheduled")
	}
	list, _ := v[0].([]any)
	for _, e := range list {
		f, _ := e.([]any)
		if len(f) != 6 {
			return errf(protocol.CodeExecFailed, "logind's list of inhibitor locks could not be read; nothing was scheduled")
		}
		what, _ := f[0].(string)
		who, _ := f[1].(string)
		why, _ := f[2].(string)
		mode, _ := f[3].(string)
		uid, _ := f[4].(uint32)
		pid, _ := f[5].(uint32)
		if !slices.Contains(strings.Split(what, ":"), "shutdown") || (mode != "block" && mode != "block-weak") {
			continue
		}
		return errf(protocol.CodeExecFailed, "a shutdown inhibitor lock (%s) is held by %q (%q), uid %d, pid %d; nothing was scheduled; preview again after it is released",
			mode, cleanText(who, 100), cleanText(why, 200), uid, pid)
	}
	return nil
}

// logindProperty reads a property of logind's manager whose variant has the
// signature sig into out (*[]any for a struct, *bool for b).
func logindProperty(c *dbus.Conn, name, sig string, out any) error {
	r, err := c.Call(logindDest, logindPath, "org.freedesktop.DBus.Properties", "Get", logindIface, name)
	if err != nil {
		return busErr(name, err)
	}
	v, err := r.Values()
	var vr dbus.Variant
	if err == nil && len(v) == 1 {
		vr, _ = v[0].(dbus.Variant)
	}
	ok := false
	if vr.Signature == sig {
		switch o := out.(type) {
		case *[]any:
			*o, ok = vr.Value.([]any)
			ok = ok && len(*o) > 0
		case *bool:
			*o, ok = vr.Value.(bool)
		}
	}
	if !ok {
		return errf(protocol.CodeExecFailed, "logind's %s could not be read; nothing was scheduled", name)
	}
	return nil
}

// errorNameRE is a D-Bus error name safe to put in a message.
var errorNameRE = regexp.MustCompile(`^[A-Za-z0-9_.]{1,255}$`)

func errorName(err error) (name, msg string, ok bool) {
	var de *dbus.Error
	if !errors.As(err, &de) {
		return "", "", false
	}
	name = de.Name
	if !errorNameRE.MatchString(name) {
		name = "an unreadable error"
	}
	return name, cleanText(de.Message, 200), true
}

func busErr(what string, err error) error {
	if name, msg, ok := errorName(err); ok {
		return errf(protocol.CodeExecFailed, "logind refused %s (%s: %s); nothing was scheduled", what, name, msg)
	}
	return errf(protocol.CodeExecFailed, "logind's answer to %s could not be read; nothing was scheduled", what)
}

// cleanText bounds a string another process chose (an inhibitor's who and
// why, a D-Bus error message) for a message: printable, one line, at most n
// bytes.
func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for s != "" && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "..."
}

func (s *server) powerPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a powerPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	p, err := s.powerResolve(a.Action, false)
	if err != nil {
		return nil, nil, err
	}
	return p, nil, nil
}

// power is priv_power: the record, the preview again, the answer, the
// confirmation, the wait, the checks again, the decision, logind.
func (s *server) power(raw jsontext.Value) (data any, warns []string, failure error) {
	var a powerArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	switch w := a.ExpectedPreviewSHA256; {
	case w == nil:
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 is required: the preview_sha256 that priv_power_preview returned for the same action")
	case !fsx.ValidPreviewSHA256(*w):
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that priv_power_preview returned")
	}
	if err := s.powerAllowed(a.Action); err != nil {
		return nil, nil, err
	}
	// (1) The record: no package operation of this helper, and no second
	// power action, runs while this one waits.
	now := time.Now()
	rec, err := s.holdRecordAs(&pkgRecordData{RequestID: s.req.ID, Started: now.UTC().Format(time.RFC3339),
		Until: now.Add(s.delay() + powerConfirmWait + 2*powerTimeout).UTC().Format(time.RFC3339)})
	if err != nil {
		return nil, nil, err
	}
	defer rec.release()
	// A decision file left by an earlier action is stale: this instance
	// holds the record, so no other action is waiting.
	if rerr := os.Remove(s.decisionPath()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return nil, nil, errf(protocol.CodeExecFailed, "the power decision file could not be removed (%s); nothing was scheduled", rerr.Error())
	}
	// (2) The preview again, with every check.
	p, err := s.powerResolve(a.Action, true)
	if err != nil {
		return nil, nil, err
	}
	if p.PreviewSHA256 != *a.ExpectedPreviewSHA256 {
		return nil, nil, errf(protocol.CodeExists, "the power action differs from its preview (the action, the delay or the privileged policy changed); nothing was scheduled; preview again")
	}
	// (3) The answer, before anything is scheduled to happen.
	at := time.Now().Add(s.delay()).Truncate(time.Millisecond).Add(time.Millisecond)
	s.powerAt = at.UTC().Format(time.RFC3339Nano)
	if werr := rec.write(&pkgRecordData{RequestID: s.req.ID, Started: now.UTC().Format(time.RFC3339),
		Until: at.Add(2 * powerTimeout).UTC().Format(time.RFC3339), Op: protocol.OpPrivPower, Action: a.Action, ScheduledAt: s.powerAt}); werr != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "the package operation record could not be written (%s); nothing was scheduled", werr.Error())
	}
	cancel := fmt.Sprintf("send priv_power_cancel (the shell_priv_cancel_power tool) to this host before %s", s.powerAt)
	if u := ownUnit(); u != "" {
		cancel += "; on the host, systemctl stop " + u + " cancels it too"
	}
	resp := s.result(powerData{Action: a.Action, Target: p.Target, ScheduledAt: s.powerAt, DelayS: p.DelayS, Cancel: cancel}, nil, nil)
	resp.ID = s.req.ID
	s.mu.Lock()
	s.answered = true
	s.earlyCode = s.respond(s.conn, resp)
	s.mu.Unlock()
	// (4) The gate must have read it; otherwise nothing is scheduled.
	if s.earlyCode != 0 || !answerRead(s.conn, s.confirmWait()) {
		s.powerState = "not_delivered"
		return nil, nil, errf(protocol.CodeExecFailed, "the gate did not read the answer; nothing was scheduled")
	}
	// (5) The wait. A hang-up of the gate does not cancel it (PRIVILEGED
	// §6, must-fix (a)'s second exception); a cancel does.
	for {
		if d, ok := s.readDecision(); ok {
			if d.RequestID == s.req.ID && d.Decision == "cancel" {
				_ = os.Remove(s.decisionPath())
				s.powerState = "cancelled"
				return powerData{Action: a.Action, Target: p.Target, ScheduledAt: s.powerAt, DelayS: p.DelayS, Cancel: cancel}, nil, nil
			}
			_ = os.Remove(s.decisionPath()) // not this action's: stale
		}
		left := time.Until(at)
		if left <= 0 {
			break
		}
		time.Sleep(min(powerPoll, left))
	}
	// (6) The checks again, immediately before the request.
	refuse := func(err error) (any, []string, error) {
		s.powerState = "refused"
		s.powerDetail = errMessage(err)
		return nil, nil, err
	}
	if !rec.intact(s.o.PkgRecord) {
		return refuse(errf(protocol.CodeExecFailed, "the package operation record is no longer the file this instance locked; nothing was requested"))
	}
	if cerr := s.powerPackageChecks(); cerr != nil {
		return refuse(cerr)
	}
	// (7) The decision: a cancel that created the file first wins.
	if d, derr := s.decide(powerDecision{RequestID: s.req.ID, Decision: "commit"}); derr != nil {
		if d.RequestID == s.req.ID && d.Decision == "cancel" {
			_ = os.Remove(s.decisionPath())
			s.powerState = "cancelled"
			return powerData{Action: a.Action, Target: p.Target, ScheduledAt: s.powerAt, DelayS: p.DelayS, Cancel: cancel}, nil, nil
		}
		return refuse(errf(protocol.CodeExecFailed, "the power decision could not be recorded (%s); nothing was requested", derr.Error()))
	}
	// (8) logind. The shutdown it starts stops this instance; the journal
	// line must still be written, so SIGTERM is ignored from here on (systemd
	// sends SIGKILL after TimeoutStopSec=).
	if s.o.HoldTermWhileRequesting {
		signal.Ignore(syscall.SIGTERM)
	}
	member := map[string]string{"reboot": "RebootWithFlags", "poweroff": "PowerOffWithFlags"}[a.Action]
	ctx, cancelCtx := context.WithTimeout(context.Background(), powerTimeout)
	defer cancelCtx()
	c, err := s.dialBus(ctx)
	if err != nil {
		return refuse(errf(protocol.CodeExecFailed, "the system bus cannot be reached, so logind was not asked; nothing was requested"))
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Call(logindDest, logindPath, logindIface, member, logindRootCheckInhibitors); err != nil {
		if name, msg, ok := errorName(err); ok {
			return refuse(errf(protocol.CodeExecFailed, "logind refused %s (%s: %s)", member, name, msg))
		}
		s.powerState = "unconfirmed"
		s.powerDetail = "logind's answer to " + member + " could not be read; the action may have been requested"
		return nil, nil, errf(protocol.CodeOutcomeUnknown, "%s", s.powerDetail)
	}
	s.powerState = "requested"
	return powerData{Action: a.Action, Target: p.Target, ScheduledAt: s.powerAt, DelayS: p.DelayS, Cancel: cancel}, nil, nil
}

func (s *server) confirmWait() time.Duration {
	if s.o.PowerConfirmWait > 0 {
		return s.o.PowerConfirmWait
	}
	return powerConfirmWait
}

func (s *server) decisionPath() string {
	if s.o.PowerDecision != "" {
		return s.o.PowerDecision
	}
	return DefaultPowerDecision
}

// errMessage is an op error's message, for the journal's detail.
func errMessage(err error) string {
	var oe *opError
	if errors.As(err, &oe) {
		return oe.msg
	}
	return err.Error()
}

// answerRead waits, at most wait, until the gate has read the whole answer:
// the bytes it has not read (SIOCOUTQ: the socket's send queue, which on a
// Unix stream socket holds what the peer has not consumed) reach 0, and the
// connection was not reset. A peer that closes with the answer unread
// makes the kernel set ECONNRESET on this side before it drops the data
// (unix_release_sock), so an empty queue alone does not prove it was read.
func answerRead(c net.Conn, wait time.Duration) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	deadline := time.Now().Add(wait)
	for {
		outq, soerr := -1, -1
		var ierr, serr error
		if cerr := rc.Control(func(fd uintptr) {
			outq, ierr = unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
			if ierr == nil && outq == 0 {
				soerr, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			}
		}); cerr != nil || ierr != nil {
			return false
		}
		if outq == 0 {
			return serr == nil && soerr == 0
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// openDecision opens the decision file for reading, refusing anything but a
// private regular file of a trusted owner.
func (s *server) openDecision() (*os.File, error) {
	f, err := os.OpenFile(s.decisionPath(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0o077 != 0 || !s.o.Trust.Owns(st.Uid) {
		_ = f.Close()
		return nil, errors.New("the power decision file is not a private regular file of root")
	}
	return f, nil
}

// readDecision reads the decision file, if there is one.
func (s *server) readDecision() (powerDecision, bool) {
	f, err := s.openDecision()
	if err != nil {
		return powerDecision{}, false
	}
	defer func() { _ = f.Close() }()
	var d powerDecision
	b, _ := io.ReadAll(io.LimitReader(bufio.NewReader(f), maxRecordBytes))
	if json.Unmarshal(b, &d) != nil {
		return powerDecision{}, true
	}
	return d, true
}

// decide creates the decision file with d, exclusively; if it exists, it
// returns what it holds and an error.
func (s *server) decide(d powerDecision) (powerDecision, error) {
	f, err := os.OpenFile(s.decisionPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if errors.Is(err, os.ErrExist) {
		got, _ := s.readDecision()
		return got, errors.New("another decision was recorded first")
	}
	if err != nil {
		return powerDecision{}, err
	}
	b, _ := json.Marshal(d)
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return powerDecision{}, werr
	}
	return d, nil
}

// powerCancel is priv_power_cancel: it stops the power action this helper
// scheduled and is still waiting, identified by the record, never by
// anything the client sends.
func (s *server) powerCancel(raw jsontext.Value) (data any, warns []string, failure error) {
	if err := decode(raw, &noArgs{}); err != nil {
		return nil, nil, err
	}
	none := errf(protocol.CodeNotFound, "no power action is scheduled on this host")
	f, err := s.openRecord(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, none
	}
	if err != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "the package operation record could not be used (%s); nothing was cancelled", err.Error())
	}
	defer func() { _ = f.Close() }()
	free := func() (bool, error) {
		err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		if err == nil {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			return true, nil
		}
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	if ok, err := free(); err != nil || ok {
		if err != nil {
			return nil, nil, errf(protocol.CodeExecFailed, "the package operation record could not be locked (%s); nothing was cancelled", err.Error())
		}
		return nil, nil, none
	}
	r, ok := readRecord(f)
	if !ok || r.Op != protocol.OpPrivPower {
		return nil, nil, errf(protocol.CodeNotFound, "no power action is scheduled on this host (a package operation is in progress)")
	}
	result := powerCancelData{Cancelled: true, RequestID: r.RequestID, Action: r.Action, ScheduledAt: r.ScheduledAt}
	if d, err := s.decide(powerDecision{RequestID: r.RequestID, Decision: "cancel"}); err != nil {
		switch {
		case d.RequestID == r.RequestID && d.Decision == "commit":
			return nil, nil, errf(protocol.CodeExecFailed, "too late: the %s was requested from logind at its time (%s); the helper's journal under request id %s says what logind answered",
				r.Action, r.ScheduledAt, r.RequestID)
		case d.RequestID == r.RequestID && d.Decision == "cancel":
			// Another cancel is already in flight; wait for it as well.
		default:
			return nil, nil, errf(protocol.CodeExecFailed, "the power decision file does not belong to the scheduled action; nothing was cancelled")
		}
	}
	for deadline := time.Now().Add(powerCancelWait); ; time.Sleep(50 * time.Millisecond) {
		ok, err := free()
		if err == nil && ok {
			return result, nil, nil
		}
		if time.Now().After(deadline) {
			return nil, nil, errf(protocol.CodeExecFailed, "the cancel was recorded, but the waiting instance did not confirm it within %s; the helper's journal under request id %s says whether the %s was requested",
				powerCancelWait, r.RequestID, r.Action)
		}
	}
}

// ownUnitRE is the name systemd gives a broad helper instance.
var ownUnitRE = regexp.MustCompile(`^shell-mcp-privd-broad@[A-Za-z0-9:._-]{1,200}\.service$`)

// ownUnit is this instance's unit, from /proc/self/cgroup, for the host's
// cancel instruction; empty when it is not a broad helper instance (tests).
func ownUnit() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || len(b) > 64<<10 {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		_, path, ok := strings.Cut(l, "::")
		if !ok {
			continue
		}
		u := path[strings.LastIndexByte(path, '/')+1:]
		if ownUnitRE.MatchString(u) {
			return u
		}
	}
	return ""
}
