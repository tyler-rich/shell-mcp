package gateclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// All keys, ids, names and addresses below are invented test fixtures.

// target starts a test SSH server whose forced command is exec and returns
// a client for it.
func target(t *testing.T, exec sshtest.Exec, maxSessions int) (*sshx.Client, *sshtest.Server) {
	t.Helper()
	hk, ck := sshtest.Ed25519(t), sshtest.Ed25519(t)
	srv := sshtest.Start(t, sshtest.Config{HostKeys: []ssh.Signer{hk}, ClientKeys: []ssh.PublicKey{ck.PublicKey()}, Exec: exec})
	host, portStr, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(portStr)
	p, _ := config.ParseHostKeyPin(sshtest.Pin(hk))
	c, err := sshx.New(config.Target{Name: "app-host", Host: host, Port: port, User: "svc-shell",
		HostKeys: []config.HostKey{p}, Key: config.PrivateKeyFromSigner(ck)}, sshx.Options{MaxSessions: maxSessions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, srv
}

// gate answers the request it reads with respond(req).
func gate(respond func(req *protocol.Request) string) sshtest.Exec {
	return func(_ context.Context, s *sshtest.Session) uint32 {
		if s.OriginalCommand != protocol.Hello {
			_, _ = io.WriteString(s.Stdout, `{"v":1,"id":"","ok":false,"error":{"code":"bad_request","message":"wrong hello"}}`+"\n")
			return 1
		}
		req, err := protocol.DecodeRequest(s.Stdin)
		if err != nil {
			_, _ = io.WriteString(s.Stdout, `{"v":1,"id":"","ok":false,"error":{"code":"bad_request","message":"undecodable"}}`+"\n")
			return 1
		}
		_, _ = io.WriteString(s.Stdout, respond(req))
		return 0
	}
}

func okFor(req *protocol.Request) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"ok":true,"data":{"op":%q,"timeout_ms":%d},"warnings":[],"gate":{"version":"0.1.0","principal":"readonly-key","policy_sha256":"ab","max_tier":"read","duration_ms":1}}`+"\n",
		req.ID, req.Op, req.TimeoutMS)
}

func newClient() *Client { return New(Options{Logger: slog.New(slog.DiscardHandler)}) }

func wantCode(t *testing.T, err error, code string) *envelope.Error {
	t.Helper()
	var e *envelope.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
	return e
}

func TestRoundTrip(t *testing.T) {
	c, _ := target(t, gate(okFor), 4)
	resp, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Op        string `json:"op"`
		TimeoutMS int64  `json:"timeout_ms"`
	}
	if !resp.OK || json.Unmarshal(resp.Data, &d) != nil || d.Op != "hello" || d.TimeoutMS != 7000 || resp.Gate.Principal != "readonly-key" {
		t.Fatalf("response %+v data %s", resp, resp.Data)
	}
}

func TestRequestIDsAreFreshUUIDv4(t *testing.T) {
	var ids []string
	c, _ := target(t, gate(func(req *protocol.Request) string {
		ids = append(ids, req.ID) // DecodeRequest already enforced lowercase UUID v4
		return okFor(req)
	}), 1)
	for range 20 {
		if _, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(ids)
	if len(slices.Compact(ids)) != 20 {
		t.Fatalf("ids repeat: %v", ids)
	}
}

func TestRefusalWithoutRequestID(t *testing.T) {
	// The gate (install checks, sandbox) and the helper (self-checks,
	// passed through by the gate) answer before reading the request: no id.
	for _, code := range []string{protocol.CodeInstallInsecure, protocol.CodeSandboxUnavailable, protocol.CodeHelperPolicyMismatch, protocol.CodeHelperInstallInsecure} {
		t.Run(code, func(t *testing.T) {
			c, _ := target(t, func(_ context.Context, s *sshtest.Session) uint32 {
				_, _ = fmt.Fprintf(s.Stdout, `{"v":1,"id":"","ok":false,"error":{"code":%q,"message":"refused before the request"}}`+"\n", code)
				return 0
			}, 1)
			resp, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second)
			if err != nil {
				t.Fatalf("an early refusal became a transport error: %v", err)
			}
			if resp.OK || resp.Error.Code != code || resp.ID != "" {
				t.Fatalf("response %+v", resp)
			}
		})
	}
}

func TestAnswerBeforeRequestFullyWritten(t *testing.T) {
	// The gate answers and exits without reading stdin while the client is
	// still writing a request far larger than the SSH channel window: the
	// write fails (closed channel), and must not hide the answer.
	c, _ := target(t, func(_ context.Context, s *sshtest.Session) uint32 {
		_, _ = io.WriteString(s.Stdout, `{"v":1,"id":"","ok":false,"error":{"code":"install_insecure","message":"early"}}`+"\n")
		s.Close()
		return 1
	}, 1)
	args := map[string]string{"content_b64": strings.Repeat("A", protocol.MaxRequestBytes-1024)}
	resp, err := newClient().Call(t.Context(), c, protocol.OpWriteFile, args, time.Second)
	if err != nil {
		t.Fatalf("the early answer was lost: %v", err)
	}
	if resp.OK || resp.Error.Code != protocol.CodeInstallInsecure {
		t.Fatalf("response %+v", resp)
	}
}

func TestResponseIDMismatch(t *testing.T) {
	other := "0b5c0000-0000-4000-8000-0000000000ff"
	for name, body := range map[string]string{
		"ok with another id":      `{"v":1,"id":"` + other + `","ok":true,"data":{},"warnings":[]}`,
		"failure with another id": `{"v":1,"id":"` + other + `","ok":false,"error":{"code":"path_denied","message":"m"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := target(t, gate(func(*protocol.Request) string { return body + "\n" }), 1)
			_, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second)
			wantCode(t, err, envelope.CodeProtocolMismatch)
		})
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	// A gate speaking another version.
	c, _ := target(t, gate(func(req *protocol.Request) string {
		return `{"v":2,"id":"` + req.ID + `","ok":true,"data":{},"warnings":[]}` + "\n"
	}), 1)
	_, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second)
	e := wantCode(t, err, envelope.CodeProtocolMismatch)
	if !strings.Contains(e.Message, "version") {
		t.Fatalf("message = %q", e.Message)
	}
	// The gate refusing our version answers protocol_mismatch itself.
	c, _ = target(t, func(_ context.Context, s *sshtest.Session) uint32 {
		_, _ = io.WriteString(s.Stdout, `{"v":1,"id":"","ok":false,"error":{"code":"protocol_mismatch","message":"unsupported protocol version"}}`+"\n")
		return 0
	}, 1)
	resp, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second)
	if err != nil || resp.Error.Code != protocol.CodeProtocolMismatch {
		t.Fatalf("resp %+v err %v", resp, err)
	}
}

func TestMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":            "hello\n",
		"unknown field":       `{"v":1,"id":"","ok":false,"error":{"code":"internal","message":"m"},"extra":1}` + "\n",
		"code outside closed": `{"v":1,"id":"","ok":false,"error":{"code":"made_up","message":"m"}}` + "\n",
		"two values":          `{"v":1,"id":"","ok":false,"error":{"code":"internal","message":"m"}} {}` + "\n",
		"ok without id":       `{"v":1,"id":"","ok":true,"data":{},"warnings":[]}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := target(t, func(_ context.Context, s *sshtest.Session) uint32 {
				_, _ = io.WriteString(s.Stdout, body)
				return 0
			}, 1)
			_, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second)
			wantCode(t, err, envelope.CodeProtocolMismatch)
		})
	}
}

func TestNoResponse(t *testing.T) {
	// sshd ran the forced command and it exited without a byte (for example
	// a missing gate binary): the gate is unavailable.
	c, _ := target(t, func(context.Context, *sshtest.Session) uint32 { return 127 }, 1)
	_, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, time.Second)
	wantCode(t, err, envelope.CodeGateUnavailable)
}

func TestOversizedResponseIsBounded(t *testing.T) {
	var wrote atomic.Int64
	c, _ := target(t, func(ctx context.Context, s *sshtest.Session) uint32 {
		chunk := []byte(strings.Repeat("x", 64<<10))
		w := bufio.NewWriter(s.Stdout)
		for range 16 * 6 { // 6 MiB, no newline
			if ctx.Err() != nil {
				break
			}
			n, err := w.Write(chunk)
			wrote.Add(int64(n))
			if err != nil {
				break
			}
		}
		_ = w.Flush()
		return 0
	}, 1)
	_, err := newClient().Call(t.Context(), c, protocol.OpHello, nil, 2*time.Second)
	wantCode(t, err, protocol.CodeTooLarge)
}

func TestTimeBudget(t *testing.T) {
	c, _ := target(t, func(ctx context.Context, s *sshtest.Session) uint32 {
		_, _ = io.Copy(io.Discard, s.Stdin) // read the request, never answer
		<-ctx.Done()
		return 0
	}, 1)
	cl := New(Options{Logger: slog.New(slog.DiscardHandler), Grace: 100 * time.Millisecond})
	start := time.Now()
	_, err := cl.Call(t.Context(), c, protocol.OpHello, nil, 100*time.Millisecond)
	wantCode(t, err, envelope.CodeTimeout)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the call took %v with a 200 ms budget", d)
	}
	// The session's slot was released (the target allows one at a time).
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	s, err := c.Session(ctx)
	if err != nil {
		t.Fatalf("slot not released after the timeout: %v", err)
	}
	_ = s.Close()
}

func TestRequestTooLargeIsNotSent(t *testing.T) {
	c, srv := target(t, gate(okFor), 1)
	args := map[string]string{"content_b64": strings.Repeat("A", protocol.MaxRequestBytes)}
	_, err := newClient().Call(t.Context(), c, protocol.OpWriteFile, args, time.Second)
	wantCode(t, err, envelope.CodeValidationError)
	if slices.Contains(srv.Events(), "channel:session") {
		t.Fatal("an oversized request opened a session")
	}
}

func TestTransportErrorsPassThrough(t *testing.T) {
	// A client for a port nothing listens on.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	hk := sshtest.Ed25519(t)
	p, _ := config.ParseHostKeyPin(sshtest.Pin(hk))
	dead, err := sshx.New(config.Target{Name: "app-host", Host: "127.0.0.1", Port: addr.Port, User: "svc-shell",
		HostKeys: []config.HostKey{p}, Key: config.PrivateKeyFromSigner(sshtest.Ed25519(t))}, sshx.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newClient().Call(t.Context(), dead, protocol.OpHello, nil, time.Second)
	wantCode(t, err, envelope.CodeTargetUnreachable)
}
