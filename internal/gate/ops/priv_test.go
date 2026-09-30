//go:build linux

package ops_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeHelper is an in-process stand-in for the privileged helper: it
// accepts connections on a Unix socket in the test's temp directory and
// answers as told. The gate reaches it through Options.DialHelper, as it
// would reach /run/shell-mcp/privd.sock.
type fakeHelper struct {
	path   string
	mu     sync.Mutex
	got    []string // request lines received
	dialed int
}

// sockDir is a short-named private directory for a test's Unix sockets:
// t.TempDir embeds the test name, and a long subtest name under a long
// TMPDIR would pass the 108-byte sun_path limit (unix(7)).
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func startHelper(t *testing.T, f *fixture, answer func(req string, c net.Conn)) *fakeHelper {
	t.Helper()
	h := &fakeHelper{path: filepath.Join(sockDir(t), "privd.sock")}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", h.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			h.mu.Lock()
			h.got = append(h.got, line)
			h.mu.Unlock()
			answer(line, c)
			_ = c.Close()
		}
	}()
	f.opts.DialHelper = func(ctx context.Context, socket string) (net.Conn, error) {
		h.mu.Lock()
		h.dialed++
		h.mu.Unlock()
		if socket != "/run/shell-mcp/privd.sock" {
			return nil, errors.New("gate dialed an unexpected socket " + socket)
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", h.path)
	}
	f.opts.HelperGrace = 200 * time.Millisecond
	f.writePolicy("destructive", "privileged:\n  enabled: true\n  socket: /run/shell-mcp/privd.sock\n  max_tier: destructive\n")
	return h
}

func (h *fakeHelper) dials() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dialed
}

// reply answers with a fixed line.
func reply(s string) func(string, net.Conn) {
	return func(_ string, c net.Conn) { _, _ = c.Write([]byte(s)) }
}

// echoID answers ok, or with an error code, for the request's own id.
func echoID(code string) func(string, net.Conn) {
	return func(req string, c net.Conn) {
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(req), &r)
		if code == "" {
			_, _ = c.Write([]byte(`{"v":1,"id":"` + r.ID + `","ok":true,"data":{"from":"helper"},"warnings":["helper warning"],"gate":{"version":"h","principal":"shell-mcp-privd","duration_ms":1}}` + "\n"))
			return
		}
		_, _ = c.Write([]byte(`{"v":1,"id":"` + r.ID + `","ok":false,"error":{"code":"` + code + `","message":"refused by the helper"},"warnings":[]}` + "\n"))
	}
}

func TestForwardRequestUnchanged(t *testing.T) {
	f := newFixture(t, "destructive")
	h := startHelper(t, f, echoID(""))
	args := `{"path":"/etc/example-app/app.conf","content_b64":"eA==","mode":"0640","owner":"root"}`
	in := `{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"priv_write_file","args":` + args + `,"timeout_ms":5000}` + "\n"
	r, _ := f.serveRaw(in)
	if !r.OK || string(r.Data) != `{"from":"helper"}` || len(r.Warnings) != 1 || r.Warnings[0] != "helper warning" {
		t.Fatalf("forwarded response %+v %s", r.Error, r.Data)
	}
	// The envelope's gate block is the gate's own, never the helper's.
	if r.Gate == nil || r.Gate.Principal != "readonly-key" || r.Gate.Version != "test" {
		t.Fatalf("gate info %+v", r.Gate)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.got) != 1 {
		t.Fatalf("helper got %d requests", len(h.got))
	}
	var got struct {
		V         int             `json:"v"`
		ID        string          `json:"id"`
		Op        string          `json:"op"`
		Args      json.RawMessage `json:"args"`
		TimeoutMS int64           `json:"timeout_ms"`
	}
	if err := json.Unmarshal([]byte(h.got[0]), &got); err != nil || !strings.HasSuffix(h.got[0], "\n") {
		t.Fatalf("forwarded %q: %v", h.got[0], err)
	}
	if got.V != 1 || got.ID != "0b5c0000-0000-4000-8000-000000000001" || got.Op != "priv_write_file" || got.TimeoutMS != 5000 || string(got.Args) != args {
		t.Fatalf("forwarded request changed: %q", h.got[0])
	}
}

func TestForwardErrors(t *testing.T) {
	for name, c := range map[string]struct {
		answer func(string, net.Conn)
		code   string
	}{
		// A helper error is passed through with its code.
		"helper path_denied":   {echoID("path_denied"), "path_denied"},
		"helper backup_failed": {echoID("backup_failed"), "backup_failed"},
		// Closed without a byte: a refused peer or a failed self-check.
		"closed without response": {func(string, net.Conn) {}, "helper_refused"},
		// Never answers: the gate's deadline (timeout_ms plus the grace).
		"no answer": {func(string, net.Conn) { time.Sleep(3 * time.Second) }, "timeout"},
		// A sandbox refusal comes before the helper reads the request.
		"sandbox refusal without id": {reply(`{"v":1,"id":"","ok":false,"error":{"code":"sandbox_unavailable","message":"no landlock"},"warnings":[]}` + "\n"), "sandbox_unavailable"},
		// Anything malformed is helper_unavailable.
		"not json":      {reply("nope\n"), "helper_unavailable"},
		"unknown field": {reply(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ok":true,"warnings":[],"root":true}` + "\n"), "helper_unavailable"},
		"other id":      {reply(`{"v":1,"id":"0b5c0000-0000-4000-8000-00000000000f","ok":true,"warnings":[]}` + "\n"), "helper_unavailable"},
		"ok without id": {reply(`{"v":1,"id":"","ok":true,"warnings":[]}` + "\n"), "helper_unavailable"},
		"unknown code":  {reply(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ok":false,"error":{"code":"granted","message":"m"},"warnings":[]}` + "\n"), "helper_unavailable"},
		"oversized":     {reply(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","ok":true,"warnings":["` + strings.Repeat("a", 4<<20) + `"]}` + "\n"), "helper_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "destructive")
			startHelper(t, f, c.answer)
			start := time.Now()
			// A 300 ms request timeout: the gate gives up at 300 ms plus the
			// 200 ms grace, long before the silent helper closes.
			r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"priv_stat","args":{"path":"/etc/example-app"},"timeout_ms":300}` + "\n")
			if r.OK || r.Error == nil || r.Error.Code != c.code {
				t.Fatalf("got %+v, want %s", r.Error, c.code)
			}
			if name == "no answer" && time.Since(start) > 2500*time.Millisecond {
				t.Fatalf("timeout took %v", time.Since(start))
			}
		})
	}
}

// A refusing helper closes without reading the request. Closing a Unix
// stream socket with unread data resets it, so the gate sees ECONNRESET on
// its read (or EPIPE on its write) rather than EOF — still a refusal with
// no byte received, never helper_unavailable.
func TestForwardRefusedWithRequestUnread(t *testing.T) {
	f := newFixture(t, "destructive")
	startHelper(t, f, echoID(""))
	p := filepath.Join(sockDir(t), "refusing.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Wait until the request is queued, then close without reading it.
			buf := make([]byte, 1)
			uc := c.(*net.UnixConn)
			raw, _ := uc.SyscallConn()
			for range 200 {
				n := 0
				_ = raw.Read(func(fd uintptr) bool {
					n, _, _ = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
					return true
				})
				if n > 0 {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			_ = c.Close()
		}
	}()
	f.opts.DialHelper = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p)
	}
	for range 5 {
		f.fail("priv_stat", m{"path": "/etc/example-app"}, "helper_refused")
	}
}

// selfCheckCodes are the helper's own self-check codes (PRIVILEGED §7),
// answered to the authenticated gate before the request is read.
var selfCheckCodes = []string{"helper_install_insecure", "helper_policy_invalid", "helper_policy_mismatch",
	"helper_client_uid_mismatch", "helper_capabilities_broad"}

// answerUnread is a helper that answers line without reading the request
// and closes. With early set, it answers and closes before the gate has
// written anything (the gate's write then fails with EPIPE); otherwise it
// waits until the request is queued, so its close resets the connection.
func answerUnread(t *testing.T, f *fixture, line string, early bool) {
	t.Helper()
	p := filepath.Join(sockDir(t), "answering.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	closed := make(chan struct{}, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if !early {
				buf := make([]byte, 1)
				raw, _ := c.(*net.UnixConn).SyscallConn()
				for range 200 {
					n := 0
					_ = raw.Read(func(fd uintptr) bool {
						n, _, _ = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
						return true
					})
					if n > 0 {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			_, _ = c.Write([]byte(line))
			_ = c.Close()
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}()
	f.opts.DialHelper = func(ctx context.Context, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", p)
		if err == nil && early {
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Error("the helper did not close")
			}
		}
		return c, err
	}
}

// A self-check failure answered by the authenticated helper passes through
// the gate with its code and message, whether the helper's close arrives
// before the gate's write (EPIPE) or after it (a reset): never
// helper_refused, which is kept for a close without a byte.
func TestForwardHelperSelfCheckCodes(t *testing.T) {
	for _, code := range selfCheckCodes {
		for _, early := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/early=%v", code, early), func(t *testing.T) {
				f := newFixture(t, "destructive")
				startHelper(t, f, echoID(""))
				msg := "the privileged helper refused to serve: " + code
				answerUnread(t, f, `{"v":1,"id":"","ok":false,"error":{"code":"`+code+`","message":"`+msg+`"},"warnings":[]}`+"\n", early)
				for range 3 {
					r, _ := f.serveRaw(`{"v":1,"id":"0b5c0000-0000-4000-8000-000000000001","op":"priv_stat","args":{"path":"/etc/example-app"},"timeout_ms":2000}` + "\n")
					if r.OK || r.Error == nil || r.Error.Code != code || r.Error.Message != msg {
						t.Fatalf("got %+v, want %s", r.Error, code)
					}
				}
			})
		}
	}
	// The control: closed early without a byte is still helper_refused.
	f := newFixture(t, "destructive")
	startHelper(t, f, echoID(""))
	answerUnread(t, f, "", true)
	f.fail("priv_stat", m{"path": "/etc/example-app"}, "helper_refused")
}

func TestForwardUnavailable(t *testing.T) {
	f := newFixture(t, "destructive")
	startHelper(t, f, echoID(""))
	f.opts.DialHelper = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(t.TempDir(), "missing.sock"))
	}
	f.fail("priv_stat", m{"path": "/etc/example-app"}, "helper_unavailable")
}

// The gate refuses before dialing when forwarding is disabled or the op is
// above privileged.max_tier.
func TestForwardRefusedAtGateNeverDials(t *testing.T) {
	f := newFixture(t, "destructive")
	h := startHelper(t, f, echoID(""))
	f.writePolicy("destructive", "privileged:\n  enabled: true\n  socket: /run/shell-mcp/privd.sock\n  max_tier: operator\n")
	f.fail("priv_delete", m{"path": "/etc/example-app/x"}, "tier_denied")
	f.writePolicy("destructive", "privileged:\n  enabled: false\n  socket: /run/shell-mcp/privd.sock\n")
	f.fail("priv_stat", m{"path": "/etc/example-app"}, "privileged_disabled")
	f.fail("priv_not_an_op", m{}, "unknown_op")
	if n := h.dials(); n != 0 {
		t.Fatalf("dialed %d times", n)
	}
}

// The gate's audit line for a forwarded request carries the request id and
// the helper's outcome.
func TestForwardAudit(t *testing.T) {
	f := newFixture(t, "destructive")
	startHelper(t, f, echoID("path_denied"))
	next := f.auditTo(t)
	f.fail("priv_read_file", m{"path": "/etc/example-app/app.conf"}, "path_denied")
	l := next()
	for _, want := range []string{`"id":"0b5c0000-0000-4000-8000-000000000001"`, `"op":"priv_read_file"`, `"outcome":"path_denied"`, `"principal":"readonly-key"`} {
		if !strings.Contains(l, want) {
			t.Errorf("audit lacks %s: %q", want, l)
		}
	}
}
