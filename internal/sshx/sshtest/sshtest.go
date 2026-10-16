// Package sshtest is an in-process SSH server for tests of the SSH client
// and the gate client. It behaves like sshd with a forced command: it
// accepts one authorized public key, never a password or keyboard-
// interactive answer, ignores the command a client asks to exec (it is
// passed to the handler as the original command, as sshd sets
// SSH_ORIGINAL_COMMAND), refuses every other request, and records
// everything a client sent so tests can prove what was never requested.
//
// It is test support: imported only by _test.go files, never by a binary
// (TestSSHTestOnlyInTests in internal/sshx).
package sshtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Exec handles one exec request: the session's stdin and stdout, and the
// command the client asked for. It returns the exit status. Stdin reads
// end with io.EOF when the client closes its side.
type Exec func(ctx context.Context, s *Session) uint32

// Session is one exec'd session.
type Session struct {
	OriginalCommand string
	Stdin           io.Reader
	Stdout          io.Writer
	// Close closes the channel at once, as a process that exits without
	// reading stdin would.
	Close func()
}

// Config configures a Server.
type Config struct {
	HostKeys []ssh.Signer
	// ClientKeys are the authorized client public keys.
	ClientKeys []ssh.PublicKey
	Exec       Exec
	// NoGlobalReplies makes the server never answer global requests (a
	// connection that stopped responding).
	NoGlobalReplies bool
	// Stall makes the server accept TCP connections and never speak SSH.
	Stall bool
}

// Server is a running test server.
type Server struct {
	Addr string

	t        testing.TB
	ln       net.Listener
	mu       sync.Mutex
	cfg      Config
	events   []string
	conns    []net.Conn
	accepted atomic.Int64
	active   atomic.Int64
	peak     atomic.Int64
	wg       sync.WaitGroup
}

// Start starts a server on 127.0.0.1 and stops it when the test ends.
func Start(t testing.TB, cfg Config) *Server {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: ln.Addr().String(), t: t, ln: ln, cfg: cfg}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.DropConnections()
		s.wg.Wait()
	})
	return s
}

// SetHostKeys replaces the host keys offered to new connections.
func (s *Server) SetHostKeys(keys ...ssh.Signer) {
	s.mu.Lock()
	s.cfg.HostKeys = keys
	s.mu.Unlock()
}

// SetNoGlobalReplies changes NoGlobalReplies for new connections.
func (s *Server) SetNoGlobalReplies(v bool) {
	s.mu.Lock()
	s.cfg.NoGlobalReplies = v
	s.mu.Unlock()
}

// DropConnections closes every open connection.
func (s *Server) DropConnections() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// Events returns what clients sent, in order: "auth:<method>",
// "channel:<type>", "request:<type>" (channel requests), "global:<type>".
func (s *Server) Events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

// Accepted is the number of TCP connections accepted.
func (s *Server) Accepted() int { return int(s.accepted.Load()) }

// PeakSessions is the largest number of exec handlers that ran at once.
func (s *Server) PeakSessions() int { return int(s.peak.Load()) }

func (s *Server) record(e string) {
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		s.mu.Lock()
		s.conns = append(s.conns, c)
		cfg := s.cfg
		s.mu.Unlock()
		if cfg.Stall {
			continue // never speaks; closed by DropConnections
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c, cfg)
		}()
	}
}

func (s *Server) handle(c net.Conn, cfg Config) {
	sc := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.record("auth:publickey")
			for _, k := range cfg.ClientKeys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.New("key not authorized")
		},
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			s.record("auth:password")
			return nil, errors.New("no passwords")
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			s.record("auth:keyboard-interactive")
			return nil, errors.New("no keyboard-interactive")
		},
	}
	for _, k := range cfg.HostKeys {
		sc.AddHostKey(k)
	}
	conn, chans, reqs, err := ssh.NewServerConn(c, sc)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() { _ = conn.Close() }()
	go func() {
		for r := range reqs {
			s.record("global:" + r.Type)
			if r.WantReply && !cfg.NoGlobalReplies {
				_ = r.Reply(false, nil)
			}
		}
	}()
	var wg sync.WaitGroup
	for nc := range chans {
		s.record("channel:" + nc.ChannelType())
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "only session channels")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.session(ch, creqs, cfg)
		}()
	}
	wg.Wait()
}

type execPayload struct{ Command string }

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request, cfg Config) {
	defer func() { _ = ch.Close() }()
	for r := range reqs {
		s.record("request:" + r.Type)
		if r.Type != "exec" || cfg.Exec == nil {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		var p execPayload
		if err := ssh.Unmarshal(r.Payload, &p); err != nil {
			_ = r.Reply(false, nil)
			continue
		}
		_ = r.Reply(true, nil)
		// The handler's context ends when the client closes the channel (the
		// requests channel closes with it) or the handler returns.
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer cancel()
			for r := range reqs {
				s.record("request:" + r.Type)
				if r.WantReply {
					_ = r.Reply(false, nil)
				}
			}
		}()
		n := s.active.Add(1)
		for {
			p := s.peak.Load()
			if n <= p || s.peak.CompareAndSwap(p, n) {
				break
			}
		}
		status := cfg.Exec(ctx, &Session{OriginalCommand: p.Command, Stdin: ch, Stdout: ch, Close: func() { _ = ch.Close() }})
		cancel()
		s.active.Add(-1)
		_ = ch.CloseWrite()
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

// Ed25519 returns a new Ed25519 signer.
func Ed25519(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer(t, priv)
}

// ECDSA returns a new ECDSA P-256 signer.
func ECDSA(t testing.TB) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer(t, priv)
}

// RSA returns a new 2048-bit RSA signer; algorithms, if given, restrict
// the signature algorithms it offers (for example only "ssh-rsa").
func RSA(t testing.TB, algorithms ...string) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := signer(t, priv)
	if len(algorithms) == 0 {
		return s
	}
	ms, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), algorithms)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func signer(t testing.TB, priv any) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Pin returns the typed pin "<type> SHA256:<base64>" of s's public key.
func Pin(s ssh.Signer) string {
	return s.PublicKey().Type() + " " + ssh.FingerprintSHA256(s.PublicKey())
}
