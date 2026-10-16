package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// ErrForbidden is returned by the Session methods this client never uses:
// PTY, environment, shell, subsystem, and any exec other than the gate hello.
var ErrForbidden = errors.New("sshx: request not allowed (D-012: no PTY, environment, shell, subsystem or other command)")

// Defaults.
const (
	DefaultMaxSessions       = 4
	DefaultKeepaliveInterval = 15 * time.Second
	DefaultBackoffFirst      = 500 * time.Millisecond
	DefaultBackoffCeiling    = 30 * time.Second
	defaultConnectTimeout    = 10 * time.Second
)

// Options configure a Client. Zero values take the defaults above.
type Options struct {
	ConnectTimeout time.Duration
	MaxSessions    int
	// KeepaliveInterval is how often a keepalive@openssh.com request is
	// sent; a reply not received within the same interval closes the
	// connection.
	KeepaliveInterval      time.Duration
	BackoffMin, BackoffMax time.Duration
	Logger                 *slog.Logger
	// Dial opens the TCP connection (default net.Dialer).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Now is the clock for the reconnect backoff (default time.Now).
	Now func() time.Time
}

// Client is the SSH client for one target. It keeps one connection, opens
// at most MaxSessions sessions on it at a time, and reconnects with a
// bounded exponential backoff, verifying the host key on every new
// connection. It never requests agent forwarding, port forwarding, a PTY,
// environment variables, a shell or a subsystem, and authenticates only
// with the target's Ed25519 key.
type Client struct {
	target config.Target
	o      Options
	cfg    *ssh.ClientConfig
	addr   string
	sem    chan struct{}

	mu          sync.Mutex
	conn        *ssh.Client
	closed      bool
	backoff     time.Duration
	nextAttempt time.Time
	lastErr     *envelope.Error

	// verified is the pin the last verified connection matched.
	verified atomic.Value
}

// HostKeyAlgorithms returns the host-key algorithms to offer for pins, in
// pin order without duplicates: each type's own algorithm, and for ssh-rsa
// rsa-sha2-512 and rsa-sha2-256 only (never SHA-1 ssh-rsa). DSA,
// certificates and unknown types contribute nothing.
func HostKeyAlgorithms(pins []config.HostKey) []string {
	out := []string{}
	add := func(algos ...string) {
		for _, a := range algos {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	for _, p := range pins {
		switch p.Type {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			add(p.Type)
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		}
	}
	return out
}

// New returns the client for target. It does not connect.
func New(target *config.Target, o Options) (*Client, error) {
	t := *target
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = defaultConnectTimeout
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = DefaultMaxSessions
	}
	if o.KeepaliveInterval <= 0 {
		o.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if o.BackoffMin <= 0 {
		o.BackoffMin = DefaultBackoffFirst
	}
	if o.BackoffMax < o.BackoffMin {
		o.BackoffMax = max(o.BackoffMin, DefaultBackoffCeiling)
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Dial == nil {
		d := &net.Dialer{Timeout: o.ConnectTimeout}
		o.Dial = d.DialContext
	}
	if t.Key == nil || t.Key.Signer() == nil || t.Key.Signer().PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("sshx: target %q: the client key must be Ed25519", t.Name)
	}
	algos := HostKeyAlgorithms(t.HostKeys)
	if len(algos) == 0 {
		return nil, fmt.Errorf("sshx: target %q: no pinned host key of a supported type", t.Name)
	}
	as, ok := t.Key.Signer().(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("sshx: target %q: the client key cannot sign", t.Name)
	}
	signer, err := ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoED25519})
	if err != nil {
		return nil, fmt.Errorf("sshx: target %q: %w", t.Name, err)
	}
	c := &Client{
		target: t,
		o:      o,
		addr:   net.JoinHostPort(t.Host, strconv.Itoa(t.Port)),
		sem:    make(chan struct{}, o.MaxSessions),
	}
	c.cfg = &ssh.ClientConfig{
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   c.verifyHostKey,
		HostKeyAlgorithms: algos,
		BannerCallback:    func(string) error { return nil },
		Timeout:           o.ConnectTimeout,
	}
	return c, nil
}

// errHostKeyNotPinned is returned by the host-key callback.
var errHostKeyNotPinned = errors.New("sshx: host key not pinned")

// verifyHostKey accepts only a key whose type and SHA-256 fingerprint
// equal one of the target's pins. A mismatch is logged with both
// fingerprints; key material is never logged.
func (c *Client) verifyHostKey(_ string, _ net.Addr, key ssh.PublicKey) error {
	got := config.HostKey{Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
	if slices.Contains(c.target.HostKeys, got) {
		c.verified.Store(got.String()) // c.mu is held by connection() during the handshake
		return nil
	}
	pinned := make([]string, 0, len(c.target.HostKeys))
	for _, p := range c.target.HostKeys {
		pinned = append(pinned, p.String())
	}
	c.o.Logger.Warn("SSH host key mismatch", "target", c.target.Name, "host", c.target.Host, "port", c.target.Port,
		"presented", got.String(), "pinned", pinned)
	return errHostKeyNotPinned
}

// Session opens a session, waiting for a free slot (MaxSessions) and
// connecting if needed. Its Close releases the slot. Errors are
// *envelope.Error with a server code.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, envelope.Errorf(envelope.CodeTimeout, "all %d sessions to the target are busy", c.o.MaxSessions)
	}
	release := sync.OnceFunc(func() { <-c.sem })
	s, err := c.newSession(ctx)
	if err != nil {
		release()
		return nil, err
	}
	return &Session{s: s, release: release}, nil
}

func (c *Client) newSession(ctx context.Context) (*ssh.Session, error) {
	for attempt := 0; ; attempt++ {
		conn, err := c.connection(ctx)
		if err != nil {
			return nil, err
		}
		s, serr := conn.NewSession()
		if serr == nil {
			return s, nil
		}
		var oce *ssh.OpenChannelError
		if errors.As(serr, &oce) {
			// The server is there and refused the channel (MaxSessions).
			return nil, envelope.Errorf(envelope.CodeGateUnavailable, "the target refused a new SSH session (%s)", oce.Reason)
		}
		// The connection broke under us: drop it and connect once more.
		c.drop(conn)
		if attempt > 0 {
			return nil, envelope.Errorf(envelope.CodeTargetUnreachable, "the SSH connection to the target closed")
		}
	}
}

// connection returns the open connection, or connects. While a backoff is
// in effect after a failed attempt, it returns that attempt's error
// without dialling.
func (c *Client) connection(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, envelope.Errorf(envelope.CodeTargetUnreachable, "the SSH client is closed")
	}
	if c.conn != nil {
		return c.conn, nil
	}
	now := c.o.Now()
	if c.lastErr != nil && now.Before(c.nextAttempt) {
		return nil, c.lastErr
	}
	conn, err := c.dial(ctx)
	if err != nil {
		if c.backoff == 0 {
			c.backoff = c.o.BackoffMin
		} else {
			c.backoff = min(2*c.backoff, c.o.BackoffMax)
		}
		c.nextAttempt = now.Add(c.backoff)
		c.lastErr = c.classify(err)
		return nil, c.lastErr
	}
	c.backoff, c.lastErr = 0, nil
	c.conn = conn
	go c.watch(conn)
	return conn, nil
}

// dial connects and completes the SSH handshake within ConnectTimeout (or
// the caller's deadline, if sooner).
func (c *Client) dial(ctx context.Context) (*ssh.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, c.o.ConnectTimeout)
	defer cancel()
	nc, err := c.o.Dial(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, c.addr, c.cfg)
	if !stop() || err != nil {
		_ = nc.Close()
		if err == nil {
			err = context.DeadlineExceeded
		}
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

func (c *Client) classify(err error) *envelope.Error {
	var ane *ssh.AlgorithmNegotiationError
	switch {
	case errors.Is(err, errHostKeyNotPinned):
		return envelope.Errorf(envelope.CodeHostKeyMismatch, "the target presented a host key that is not pinned for it")
	case errors.As(err, &ane) && strings.Contains(ane.What, "host key"):
		c.o.Logger.Warn("SSH host key mismatch", "target", c.target.Name, "host", c.target.Host, "port", c.target.Port,
			"presented_algorithms", ane.RequestedAlgorithms, "pinned_algorithms", ane.SupportedAlgorithms)
		return envelope.Errorf(envelope.CodeHostKeyMismatch, "the target offers no host key of a pinned type")
	case strings.Contains(err.Error(), "ssh: unable to authenticate"):
		c.o.Logger.Warn("SSH authentication failed", "target", c.target.Name, "host", c.target.Host, "port", c.target.Port,
			"client_key", c.target.Key.Fingerprint())
		return envelope.Errorf(envelope.CodeAuthFailedSSH, "the target refused the client key")
	}
	c.o.Logger.Warn("SSH connection failed", "target", c.target.Name, "host", c.target.Host, "port", c.target.Port, "error", err.Error())
	return envelope.Errorf(envelope.CodeTargetUnreachable, "cannot reach the target's SSH server")
}

// watch sends keepalives until the connection ends, closes it when a reply
// does not arrive within the interval, and forgets it when it ends.
func (c *Client) watch(conn *ssh.Client) {
	done := make(chan struct{})
	go func() {
		_ = conn.Wait()
		close(done)
	}()
	t := time.NewTicker(c.o.KeepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			c.drop(conn)
			return
		case <-t.C:
			replied := make(chan error, 1)
			go func() {
				_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
				replied <- err
			}()
			timer := time.NewTimer(c.o.KeepaliveInterval)
			select {
			case err := <-replied:
				if err != nil {
					_ = conn.Close()
				}
			case <-timer.C:
				c.o.Logger.Warn("SSH keepalive unanswered; closing the connection", "target", c.target.Name)
				_ = conn.Close()
			case <-done:
			}
			timer.Stop()
		}
	}
}

// drop forgets conn (if it is still the current one) and closes it.
func (c *Client) drop(conn *ssh.Client) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
	_ = conn.Close()
}

// VerifiedHostKey is the pin ("<type> SHA256:…") the most recent connection
// was verified against, or "" before any connection succeeded.
func (c *Client) VerifiedHostKey() string {
	s, _ := c.verified.Load().(string)
	return s
}

func (c *Client) connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Close closes the connection; later sessions fail.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn, c.closed = nil, true
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// Session is one SSH session. Only the gate hello may be exec'd; the
// requests this project never makes are refused here, before anything is
// sent.
type Session struct {
	s       *ssh.Session
	release func()
}

// StdinPipe returns the session's stdin.
func (s *Session) StdinPipe() (io.WriteCloser, error) { return s.s.StdinPipe() }

// StdoutPipe returns the session's stdout.
func (s *Session) StdoutPipe() (io.Reader, error) { return s.s.StdoutPipe() }

// Start execs cmd, which must be the gate hello (protocol.Hello). sshd
// ignores it and runs the key's forced command, which reads it from
// SSH_ORIGINAL_COMMAND.
func (s *Session) Start(cmd string) error {
	if cmd != protocol.Hello {
		return ErrForbidden
	}
	return s.s.Start(cmd)
}

// Output execs cmd (the gate hello) and returns its stdout.
func (s *Session) Output(cmd string) ([]byte, error) {
	if cmd != protocol.Hello {
		return nil, ErrForbidden
	}
	return s.s.Output(cmd)
}

// Wait waits for the remote command to exit.
func (s *Session) Wait() error { return s.s.Wait() }

// Close closes the session and releases its slot.
func (s *Session) Close() error {
	defer s.release()
	err := s.s.Close()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// RequestPty is never allowed.
func (*Session) RequestPty(string, int, int, ssh.TerminalModes) error { return ErrForbidden }

// Setenv is never allowed.
func (*Session) Setenv(string, string) error { return ErrForbidden }

// Shell is never allowed.
func (*Session) Shell() error { return ErrForbidden }

// RequestSubsystem is never allowed.
func (*Session) RequestSubsystem(string) error { return ErrForbidden }
