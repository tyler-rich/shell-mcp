//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/privd/ops"
)

// The stop points of install, upgrade and remove (S4c-7, the maintainer's
// decision on item 5; PRIVILEGED §6 "Timeouts, and a gate that goes away",
// the exception for package operations): at a hang-up or the request's
// deadline the helper sends no signal and answers outcome_unknown at once,
// naming the request id and the UTC time the operation may run until; at
// max_timeout_s less the stop allowance it sends SIGINT to apt-get alone;
// at max_timeout_s it kills the process group and reaps; the journal line
// is written whenever the operation ends. Here max_timeout_s is 4 s, so
// the allowance is min(60 s, 4 s / 4) = 1 s: SIGINT at 3 s, the kill at
// 4 s. Not parallel: each bounds wall-clock times.

// stagePolicy shortens the fixture's limits: default 2 s, max 4 s.
func stagePolicy() opt {
	return replace("  default_timeout_s: 5\n  max_timeout_s: 10\n", "  default_timeout_s: 2\n  max_timeout_s: 4\n")
}

// asyncServe is one Serve running on a socket pair, with the gate's end.
type asyncServe struct {
	t     *testing.T
	gate  int
	start time.Time
	done  chan time.Time
}

func (f *fixture) serveAsync(line string) *asyncServe {
	f.t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.helperFD = fds[0]
	if _, err := unix.Write(fds[1], []byte(line)); err != nil {
		f.t.Fatal(err)
	}
	conn := os.NewFile(uintptr(fds[0]), "conn")
	o := f.opts
	o.Conn = conn
	a := &asyncServe{t: f.t.(*testing.T), gate: fds[1], start: time.Now(), done: make(chan time.Time, 1)}
	go func() {
		ops.Serve(&o)
		_ = conn.Close()
		a.done <- time.Now()
	}()
	f.t.Cleanup(func() { _ = unix.Close(fds[1]) })
	return a
}

// answer reads the helper's answer from the gate's end within d, and when
// it arrived.
func (a *asyncServe) answer(d time.Duration) (response, time.Time) {
	a.t.Helper()
	_ = unix.SetsockoptTimeval(a.gate, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: int64(d / time.Second), Usec: int64(d % time.Second / time.Microsecond)})
	var b []byte
	buf := make([]byte, 64<<10)
	for !strings.Contains(string(b), "\n") {
		n, err := unix.Read(a.gate, buf)
		if n <= 0 || err != nil {
			a.t.Fatalf("no answer within %v (read %q, %v)", d, b, err)
		}
		b = append(b, buf[:n]...)
	}
	at := time.Now()
	var r response
	if err := json.Unmarshal(b, &r); err != nil {
		a.t.Fatalf("answer %q: %v", b, err)
	}
	return r, at
}

// ended waits for Serve to return, at most d after the request was sent.
func (a *asyncServe) ended(d time.Duration) time.Duration {
	a.t.Helper()
	select {
	case at := <-a.done:
		return at.Sub(a.start)
	case <-time.After(d - time.Since(a.start)):
		a.t.Fatalf("Serve did not return within %v", d)
	}
	return 0
}

func pkgLine(op string, args m, timeoutMS int) string {
	b, _ := json.Marshal(args)
	return fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"destructive","op":%q,"args":%s,"timeout_ms":%d}`+"\n", reqID, op, b, timeoutMS)
}

var untilRE = regexp.MustCompile(`may run until \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`)

// wantEarly checks an early answer: outcome_unknown naming the request id
// and the time it may run until.
func wantEarly(t *testing.T, r *response) {
	t.Helper()
	if r.OK || r.Error == nil || r.Error.Code != "outcome_unknown" || !strings.Contains(r.Error.Message, reqID) || !untilRE.MatchString(r.Error.Message) {
		t.Fatalf("early answer %+v", r.Error)
	}
}

// signalsGot is what the recording child in apt-get's process group (dpkg
// and maintainer scripts) received.
func signalsGot(t *testing.T, p string) string {
	b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// TestPkgEarlyAnswer: at the request's deadline (1 s) the helper answers
// outcome_unknown at once and lets apt-get finish (2.5 s), without a
// signal; meanwhile a preview says the operation is in progress; the
// journal line, written when it ends, has the operation's own result.
func TestPkgEarlyAnswer(t *testing.T) {
	f := modelFixture(t, &pkgModel{}, nil, stagePolicy())
	marker := filepath.Join(f.d, "child-signals")
	p := f.pkgPreview("priv_pkg_install", hello)
	f.setModel(&pkgModel{Run: mrun{SlowMS: 2500, Child: marker}})
	a := f.serveAsync(pkgLine("priv_pkg_install", bound(hello, p), 1000))
	r, at := a.answer(3 * time.Second)
	wantEarly(t, &r)
	if d := at.Sub(a.start); d < 900*time.Millisecond || d > 2*time.Second {
		t.Fatalf("answered after %v, want at the 1 s deadline", d)
	}
	// In progress: the record is held by the running operation.
	pr := f.serve("priv_pkg_install_preview", hello)
	if pr.OK || !strings.Contains(pr.Error.Message, "package operation in progress") || !strings.Contains(pr.Error.Message, reqID) {
		t.Fatalf("preview during the operation: %+v", pr.Error)
	}
	if took := a.ended(6 * time.Second); took < 2500*time.Millisecond {
		t.Fatalf("Serve returned after %v, before apt-get finished", took)
	}
	if got := f.dpkgState(); strings.Join(got, ",") != "example-hello 1.1 installed,example-lib 2.1-1 installed" {
		t.Fatalf("dpkg %v", got)
	}
	if s := signalsGot(t, marker); s != "" {
		t.Fatalf("apt-get's process group got %q", s)
	}
	l := f.lastAudit()
	if !strings.Contains(l, `"op":"priv_pkg_install"`) || !strings.Contains(l, `"outcome":"ok"`) || !strings.Contains(l, `"answered_early":true`) ||
		!strings.Contains(l, `"applied":`) || strings.Contains(l, `"stopped"`) {
		t.Fatalf("audit %q", l)
	}
}

// TestPkgHangupLetsFinish: a hang-up while apt-get runs sends no signal: a
// gate that still reads gets the early answer; apt-get finishes; the
// journal line records the hang-up and the result.
func TestPkgHangupLetsFinish(t *testing.T) {
	for _, mode := range []string{"close", "half"} {
		t.Run(mode, func(t *testing.T) {
			f := modelFixture(t, &pkgModel{}, nil, stagePolicy())
			marker := filepath.Join(f.d, "child-signals")
			p := f.pkgPreview("priv_pkg_install", hello)
			f.setModel(&pkgModel{Run: mrun{SlowMS: 2000, Child: marker}})
			a := f.serveAsync(pkgLine("priv_pkg_install", bound(hello, p), 4000))
			time.Sleep(500 * time.Millisecond)
			if mode == "close" {
				_ = unix.Close(a.gate)
			} else {
				_ = unix.Shutdown(a.gate, unix.SHUT_WR)
				r, at := a.answer(2 * time.Second)
				wantEarly(t, &r)
				if at.Sub(a.start) > 1500*time.Millisecond {
					t.Fatalf("answered %v after the request", at.Sub(a.start))
				}
			}
			if took := a.ended(6 * time.Second); took < 2*time.Second {
				t.Fatalf("Serve returned after %v, before apt-get finished", took)
			}
			if got := f.dpkgState(); len(got) != 2 || !strings.HasSuffix(got[0], "installed") {
				t.Fatalf("dpkg %v", got)
			}
			if s := signalsGot(t, marker); s != "" {
				t.Fatalf("apt-get's process group got %q", s)
			}
			l := f.lastAudit()
			if !strings.Contains(l, `"hung_up":true`) || !strings.Contains(l, `"answered_early":true`) || !strings.Contains(l, `"outcome":"ok"`) {
				t.Fatalf("audit %q", l)
			}
		})
	}
}

// TestPkgSigintAtStopPoint: at max_timeout_s less the allowance (3 s) the
// helper sends SIGINT to apt-get alone, never its process group; apt stops
// at a safe point and exits 0; the part it applied is verify_failed, from
// dpkg's status, not its exit code.
func TestPkgSigintAtStopPoint(t *testing.T) {
	f := modelFixture(t, &pkgModel{}, nil, stagePolicy())
	marker := filepath.Join(f.d, "child-signals")
	p := f.pkgPreview("priv_pkg_install", hello)
	f.setModel(&pkgModel{Run: mrun{SlowMS: 30000, OnInt: "partial", Child: marker}})
	a := f.serveAsync(pkgLine("priv_pkg_install", bound(hello, p), 1000))
	r, _ := a.answer(3 * time.Second)
	wantEarly(t, &r)
	took := a.ended(10 * time.Second)
	if took < 2900*time.Millisecond || took > 4*time.Second {
		t.Fatalf("Serve returned after %v, want just after the 3 s stop point and before the 4 s kill", took)
	}
	if s := signalsGot(t, marker); s != "" {
		t.Fatalf("the SIGINT reached apt-get's process group: %q", s)
	}
	if got := f.dpkgState(); len(got) != 1 {
		t.Fatalf("dpkg %v, want the first change only", got)
	}
	l := f.lastAudit()
	if !strings.Contains(l, `"stopped":"sigint"`) || !strings.Contains(l, `"outcome":"verify_failed"`) || !strings.Contains(l, `"answered_early":true`) ||
		!strings.Contains(l, `"applied":`) || strings.Contains(l, `"unfinished"`) {
		t.Fatalf("audit %q", l)
	}
}

// TestPkgFinalKill: an apt-get that does not stop at SIGINT (dpkg in a
// maintainer script that never ends; its first package, example-lib, is
// half-configured) is killed at max_timeout_s with its
// process group and reaped; dpkg's database is left unfinished, which the
// journal line reports; everything ends well inside RuntimeMaxSec
// (max_timeout_s + 30 s).
func TestPkgFinalKill(t *testing.T) {
	f := modelFixture(t, &pkgModel{}, nil, stagePolicy())
	marker := filepath.Join(f.d, "child-signals")
	p := f.pkgPreview("priv_pkg_install", hello)
	f.setModel(&pkgModel{Run: mrun{SlowMS: 60000, OnInt: "ignore", IgnoreTerm: true, UnfinishedFirst: true, Child: marker}})
	a := f.serveAsync(pkgLine("priv_pkg_install", bound(hello, p), 1000))
	r, _ := a.answer(3 * time.Second)
	wantEarly(t, &r)
	took := a.ended(4*time.Second + 30*time.Second)
	// SIGTERM at 4 s, SIGKILL 2 s later, the reaping and the journal line.
	if took < 4*time.Second || took > 9*time.Second {
		t.Fatalf("Serve returned after %v, want after the 4 s kill and its 2 s grace", took)
	}
	if s := signalsGot(t, marker); s != "SIGTERM" && s != "terminated" {
		t.Fatalf("the process group got %q, want only the final SIGTERM", s)
	}
	l := f.lastAudit()
	if !strings.Contains(l, `"stopped":"killed"`) || !strings.Contains(l, `"outcome":"verify_failed"`) || !strings.Contains(l, `"unfinished":["example-lib"]`) {
		t.Fatalf("audit %q", l)
	}
	// The next preview reports the unfinished database with its recovery.
	pr := f.serve("priv_pkg_install_preview", hello)
	if pr.OK || pr.Error.Code != "exec_failed" || !strings.Contains(pr.Error.Message, "dpkg --configure -a") {
		t.Fatalf("preview after the kill: %+v", pr.Error)
	}
}

// TestPkgHangupBeforeStart: a hang-up before apt-get started (the lock
// held, so the operation waits) runs nothing: timeout, nothing changed.
func TestPkgHangupBeforeStart(t *testing.T) {
	f := modelFixture(t, &pkgModel{}, nil, stagePolicy())
	f.opts.PkgLockRetry = 50 * time.Millisecond
	p := f.pkgPreview("priv_pkg_install", hello)
	_, release := f.holdDpkgLock()
	defer release()
	a := f.serveAsync(pkgLine("priv_pkg_install", bound(hello, p), 4000))
	time.Sleep(300 * time.Millisecond)
	_ = unix.Shutdown(a.gate, unix.SHUT_WR)
	r, _ := a.answer(3 * time.Second)
	if r.OK || r.Error.Code != "timeout" || !strings.Contains(r.Error.Message, "nothing was changed") {
		t.Fatalf("answer %+v", r.Error)
	}
	a.ended(4 * time.Second)
	if len(f.realRuns()) != 0 || len(f.dpkgState()) != 0 {
		t.Fatal("apt-get ran after the hang-up")
	}
	if l := f.lastAudit(); !strings.Contains(l, `"hung_up":true`) || !strings.Contains(l, `"outcome":"timeout"`) {
		t.Fatalf("audit %q", l)
	}
}

// TestPkgUpdateIndexKilledOnHangup: the index update is not part of the
// exception (apt-get update never touches dpkg's database): a hang-up
// stops it as a command, before the answer, which is outcome_unknown.
func TestPkgUpdateIndexKilledOnHangup(t *testing.T) {
	f := pkgFixture(t, "slow", stagePolicy())
	var u preview
	f.ok("priv_pkg_update_index_preview", m{}, &u)
	a := f.serveAsync(pkgLine("priv_pkg_update_index", m{"expected_preview_sha256": u.PreviewSHA256}, 4000))
	time.Sleep(500 * time.Millisecond)
	_ = unix.Shutdown(a.gate, unix.SHUT_WR)
	r, at := a.answer(4 * time.Second)
	if r.OK || r.Error.Code != "outcome_unknown" {
		t.Fatalf("answer %+v", r.Error)
	}
	if d := at.Sub(a.start); d > 3500*time.Millisecond {
		t.Fatalf("answered after %v", d)
	}
	a.ended(5 * time.Second)
	if l := f.lastAudit(); !strings.Contains(l, `"hung_up":true`) || strings.Contains(l, `"answered_early"`) {
		t.Fatalf("audit %q", l)
	}
}

// TestPkgDropKeepsTheOperation (the maintainer's follow-up on the e2e
// drop): a gate that goes away while apt-get runs, by a reset (it leaves
// the early answer unread and closes, so the helper's next read or write
// on the connection fails with ECONNRESET or EPIPE) or by closing before
// the early answer (whose write then fails), must not stop the operation
// or skip its journal line: apt-get and its process group get no signal,
// the whole transaction is applied, nothing is left unfinished, Serve
// returns only after apt-get ended, and the line has the result.
func TestPkgDropKeepsTheOperation(t *testing.T) {
	for _, mode := range []string{"reset after the early answer", "closed before the early answer"} {
		t.Run(mode, func(t *testing.T) {
			f := modelFixture(t, &pkgModel{}, nil, stagePolicy())
			marker := filepath.Join(f.d, "child-signals")
			p := f.pkgPreview("priv_pkg_install", hello)
			f.setModel(&pkgModel{Run: mrun{SlowMS: 2500, Child: marker}})
			timeoutMS := 4000
			if mode == "reset after the early answer" {
				timeoutMS = 700
			}
			a := f.serveAsync(pkgLine("priv_pkg_install", bound(hello, p), timeoutMS))
			if mode == "reset after the early answer" {
				// The early answer is queued on the gate's end, unread.
				deadline := time.Now().Add(2 * time.Second)
				for unreadBytes(t, a.gate) == 0 && time.Now().Before(deadline) {
					time.Sleep(20 * time.Millisecond)
				}
				if unreadBytes(t, a.gate) == 0 {
					t.Fatal("no early answer by 2 s")
				}
			} else {
				time.Sleep(400 * time.Millisecond)
			}
			_ = unix.Close(a.gate)
			if took := a.ended(8 * time.Second); took < 2500*time.Millisecond {
				t.Fatalf("Serve returned after %v, before apt-get finished", took)
			}
			if s := signalsGot(t, marker); s != "" {
				t.Fatalf("apt-get's process group got %q", s)
			}
			if got := f.dpkgState(); strings.Join(got, ",") != "example-hello 1.1 installed,example-lib 2.1-1 installed" {
				t.Fatalf("dpkg %v", got)
			}
			l := f.lastAudit()
			if !strings.Contains(l, `"answered_early":true`) || !strings.Contains(l, `"outcome":"ok"`) || strings.Contains(l, `"unfinished"`) {
				t.Fatalf("audit %q", l)
			}
		})
	}
}
