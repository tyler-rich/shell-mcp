package sshx

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// All keys, names and addresses below are invented test fixtures.

func pin(t *testing.T, s ssh.Signer) config.HostKey {
	t.Helper()
	p, ok := config.ParseHostKeyPin(sshtest.Pin(s))
	if !ok {
		t.Fatalf("bad pin %q", sshtest.Pin(s))
	}
	return p
}

type fixture struct {
	t      *testing.T
	srv    *sshtest.Server
	client ssh.Signer
	target config.Target
	logs   *bytes.Buffer
	opts   Options
}

// echoExec answers each exec with "ok:<original command>".
func echoExec(_ context.Context, s *sshtest.Session) uint32 {
	_, _ = io.WriteString(s.Stdout, "ok:"+s.OriginalCommand)
	return 0
}

func newFixture(t *testing.T, cfg sshtest.Config, pins ...config.HostKey) *fixture {
	t.Helper()
	client := sshtest.Ed25519(t)
	cfg.ClientKeys = append(cfg.ClientKeys, client.PublicKey())
	if cfg.Exec == nil {
		cfg.Exec = echoExec
	}
	srv := sshtest.Start(t, cfg)
	host, portStr, _ := net.SplitHostPort(srv.Addr)
	port, _ := strconv.Atoi(portStr)
	if len(pins) == 0 {
		for _, k := range cfg.HostKeys {
			pins = append(pins, pin(t, k))
		}
	}
	f := &fixture{t: t, srv: srv, client: client, logs: &bytes.Buffer{},
		target: config.Target{Name: "app-host", Host: host, Port: port, User: "svc-shell", HostKeys: pins,
			Key: config.PrivateKeyFromSigner(client)}}
	f.opts = Options{ConnectTimeout: 2 * time.Second, MaxSessions: 4, Logger: slog.New(slog.NewJSONHandler(&syncWriter{w: f.logs}, nil))}
	return f
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (f *fixture) newClient() *Client {
	f.t.Helper()
	c, err := New(f.target, f.opts)
	if err != nil {
		f.t.Fatalf("New: %v", err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	return c
}

// run opens a session, execs the gate hello, and returns its output.
func run(ctx context.Context, c *Client) (string, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }()
	out, err := s.Output("shell-mcp-gate/1")
	return string(out), err
}

func wantCode(t *testing.T, err error, code string) *envelope.Error {
	t.Helper()
	var e *envelope.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
	return e
}

func TestHostKeyAlgorithmsFromPins(t *testing.T) {
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	hk := func(typ string) config.HostKey { return config.HostKey{Type: typ, Fingerprint: fp} }
	cases := []struct {
		pins []config.HostKey
		want []string
	}{
		{[]config.HostKey{hk("ssh-ed25519")}, []string{"ssh-ed25519"}},
		{[]config.HostKey{hk("ecdsa-sha2-nistp256")}, []string{"ecdsa-sha2-nistp256"}},
		{[]config.HostKey{hk("ecdsa-sha2-nistp384")}, []string{"ecdsa-sha2-nistp384"}},
		{[]config.HostKey{hk("ecdsa-sha2-nistp521")}, []string{"ecdsa-sha2-nistp521"}},
		{[]config.HostKey{hk("ssh-rsa")}, []string{"rsa-sha2-512", "rsa-sha2-256"}},
		{[]config.HostKey{hk("ssh-rsa"), hk("ssh-ed25519"), hk("ssh-rsa"), hk("ssh-ed25519")}, []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"}},
		{[]config.HostKey{hk("ssh-dss"), hk("ssh-ed25519-cert-v01@openssh.com")}, []string{}},
	}
	for _, c := range cases {
		got := HostKeyAlgorithms(c.pins)
		if !slices.Equal(got, c.want) {
			t.Fatalf("pins %v: algorithms %v, want %v", c.pins, got, c.want)
		}
		if slices.Contains(got, ssh.KeyAlgoRSA) || slices.Contains(got, ssh.InsecureKeyAlgoDSA) { //nolint:staticcheck // asserting their absence
			t.Fatalf("insecure algorithm offered: %v", got)
		}
	}
}

func TestEd25519PinConnectsWhenServerAlsoHasECDSA(t *testing.T) {
	ec, ed := sshtest.ECDSA(t), sshtest.Ed25519(t)
	// x/crypto/ssh's default preference puts ECDSA before Ed25519, so an
	// unrestricted client would be shown the ECDSA key and fail the pin.
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{ec, ed}}, pin(t, ed))
	c := f.newClient()
	if c.VerifiedHostKey() != "" {
		t.Fatal("verified before connecting")
	}
	out, err := run(t.Context(), c)
	if err != nil || out != "ok:shell-mcp-gate/1" {
		t.Fatalf("out %q err %v", out, err)
	}
	if c.VerifiedHostKey() != sshtest.Pin(ed) {
		t.Fatalf("verified %q, want %q", c.VerifiedHostKey(), sshtest.Pin(ed))
	}
}

func TestUnpinnedHostKeyRefused(t *testing.T) {
	presented, pinned := sshtest.Ed25519(t), sshtest.Ed25519(t)
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{presented}}, pin(t, pinned))
	_, err := run(t.Context(), f.newClient())
	wantCode(t, err, envelope.CodeHostKeyMismatch)
	logs := f.logs.String()
	for _, fp := range []string{ssh.FingerprintSHA256(presented.PublicKey()), ssh.FingerprintSHA256(pinned.PublicKey())} {
		if !strings.Contains(logs, fp) {
			t.Fatalf("log lacks fingerprint %s: %s", fp, logs)
		}
	}
	blob := base64.StdEncoding.EncodeToString(presented.PublicKey().Marshal())
	if strings.Contains(logs, blob) || strings.Contains(err.Error(), blob) {
		t.Fatal("key material in the log or error")
	}
	if slices.Contains(f.srv.Events(), "channel:session") {
		t.Fatal("a session was opened on an unverified connection")
	}
}

func TestWrongAlgorithmRefused(t *testing.T) {
	// The pin names ECDSA; the target offers only an Ed25519 host key.
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}}, pin(t, sshtest.ECDSA(t)))
	_, err := run(t.Context(), f.newClient())
	e := wantCode(t, err, envelope.CodeHostKeyMismatch)
	if !strings.Contains(e.Message, "no host key of a pinned type") {
		t.Fatalf("message = %q", e.Message)
	}
}

func TestRSAPinNeverNegotiatesSHA1(t *testing.T) {
	sha1Only := sshtest.RSA(t, ssh.KeyAlgoRSA) //nolint:staticcheck // the insecure algorithm under test
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sha1Only}})
	_, err := run(t.Context(), f.newClient())
	wantCode(t, err, envelope.CodeHostKeyMismatch)

	sha2 := sshtest.RSA(t, ssh.KeyAlgoRSASHA256)
	f = newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sha2}})
	if out, err := run(t.Context(), f.newClient()); err != nil || out != "ok:shell-mcp-gate/1" {
		t.Fatalf("rsa-sha2-256: out %q err %v", out, err)
	}
}

func TestClientRequestsOnlyPublicKeySessionAndExec(t *testing.T) {
	hk := sshtest.Ed25519(t)
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{hk}})
	f.opts.KeepaliveInterval = 20 * time.Millisecond
	c := f.newClient()
	for range 2 {
		if _, err := run(t.Context(), c); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(80 * time.Millisecond)
	for _, ev := range f.srv.Events() {
		switch ev {
		case "auth:publickey", "channel:session", "request:exec", "global:keepalive@openssh.com":
		default:
			t.Fatalf("client sent %q (events %v)", ev, f.srv.Events())
		}
	}
	if !slices.Contains(f.srv.Events(), "global:keepalive@openssh.com") {
		t.Fatalf("no keepalive sent: %v", f.srv.Events())
	}
	if f.srv.Accepted() != 1 {
		t.Fatalf("%d connections for two sessions, want 1 (reuse)", f.srv.Accepted())
	}
}

func TestSessionRefusesPTYAgentEnvAndForwarding(t *testing.T) {
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}})
	s, err := f.newClient().Session(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := s.Setenv("LANG", "C"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Setenv: %v", err)
	}
	if err := s.Shell(); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Shell: %v", err)
	}
	if err := s.RequestSubsystem("sftp"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("RequestSubsystem: %v", err)
	}
	if err := s.Start("anything else"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Start with another command: %v", err)
	}
	for _, ev := range f.srv.Events() {
		if strings.HasPrefix(ev, "request:") {
			t.Fatalf("a refused request reached the server: %q", ev)
		}
	}
}

func TestClientKeyNotAuthorized(t *testing.T) {
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}})
	f.target.Key = config.PrivateKeyFromSigner(sshtest.Ed25519(t)) // not the authorized key
	_, err := run(t.Context(), f.newClient())
	wantCode(t, err, envelope.CodeAuthFailedSSH)
	for _, ev := range f.srv.Events() {
		if ev == "auth:password" || ev == "auth:keyboard-interactive" {
			t.Fatalf("client tried %s", ev)
		}
	}
}

func TestOnlyEd25519ClientKeys(t *testing.T) {
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}})
	f.target.Key = config.PrivateKeyFromSigner(sshtest.ECDSA(t))
	if _, err := New(f.target, f.opts); err == nil {
		t.Fatal("New accepted a non-Ed25519 client key")
	}
}

func TestMaxSessionsPerTarget(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int64
	block := func(ctx context.Context, s *sshtest.Session) uint32 {
		started.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		_, _ = io.WriteString(s.Stdout, "done")
		return 0
	}
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}, Exec: block})
	f.opts.MaxSessions = 2
	c := f.newClient()
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Go(func() {
			_, err := run(t.Context(), c)
			errs <- err
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for started.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := started.Load(); n != 2 {
		t.Fatalf("%d sessions running, want 2 (the limit)", n)
	}
	// A caller whose deadline passes while waiting for a slot times out.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	_, err := run(ctx, c)
	cancel()
	wantCode(t, err, envelope.CodeTimeout)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if p := f.srv.PeakSessions(); p != 2 {
		t.Fatalf("peak concurrent sessions %d, want 2", p)
	}
}

func TestReconnectReverifiesHostKey(t *testing.T) {
	good, rogue := sshtest.Ed25519(t), sshtest.Ed25519(t)
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{good}})
	f.opts.BackoffMin, f.opts.BackoffMax = time.Millisecond, time.Millisecond
	c := f.newClient()
	if _, err := run(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	// The connection drops and whoever answers next presents another key.
	f.srv.SetHostKeys(rogue)
	f.srv.DropConnections()
	waitDisconnected(t, c)
	_, err := run(t.Context(), c)
	wantCode(t, err, envelope.CodeHostKeyMismatch)
	f.srv.SetHostKeys(good)
	time.Sleep(5 * time.Millisecond)
	if _, err := run(t.Context(), c); err != nil {
		t.Fatalf("after the pinned key is back: %v", err)
	}
	if f.srv.Accepted() != 3 {
		t.Fatalf("accepted %d connections, want 3", f.srv.Accepted())
	}
}

func waitDisconnected(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for c.connected() {
		if time.Now().After(deadline) {
			t.Fatal("client did not notice the dropped connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBackoffBetweenFailedConnects(t *testing.T) {
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}})
	var dials atomic.Int64
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	f.opts.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	f.opts.BackoffMin, f.opts.BackoffMax = time.Second, 4*time.Second
	f.opts.Dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("connection refused")
	}
	c := f.newClient()
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	steps := []struct {
		advance time.Duration
		dials   int64
	}{
		{0, 1},                       // first attempt
		{0, 1},                       // within the 1 s backoff: no dial
		{1100 * time.Millisecond, 2}, // then 2 s
		{1500 * time.Millisecond, 2},
		{600 * time.Millisecond, 3}, // then 4 s (the ceiling)
		{4100 * time.Millisecond, 4},
		{4100 * time.Millisecond, 5}, // still 4 s
	}
	for i, s := range steps {
		advance(s.advance)
		_, err := run(t.Context(), c)
		wantCode(t, err, envelope.CodeTargetUnreachable)
		if dials.Load() != s.dials {
			t.Fatalf("step %d: %d dials, want %d", i, dials.Load(), s.dials)
		}
	}
}

func TestConnectTimeout(t *testing.T) {
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}, Stall: true})
	f.opts.ConnectTimeout = 200 * time.Millisecond
	start := time.Now()
	_, err := run(t.Context(), f.newClient())
	wantCode(t, err, envelope.CodeTargetUnreachable)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("connect took %v with a 200 ms timeout", d)
	}
}

func TestKeepaliveDropsUnresponsiveConnection(t *testing.T) {
	f := newFixture(t, sshtest.Config{HostKeys: []ssh.Signer{sshtest.Ed25519(t)}, NoGlobalReplies: true})
	f.opts.KeepaliveInterval = 30 * time.Millisecond
	c := f.newClient()
	if _, err := run(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	waitDisconnected(t, c)
	f.srv.SetNoGlobalReplies(false)
	if _, err := run(t.Context(), c); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if f.srv.Accepted() != 2 {
		t.Fatalf("accepted %d, want 2", f.srv.Accepted())
	}
}

// TestSSHTestOnlyInTests: the test server is never part of a binary.
func TestSSHTestOnlyInTests(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(p), "internal/sshx/sshtest/") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: walking this repository's sources
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(`"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"`)) {
			t.Errorf("%s imports sshtest outside a test file", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
