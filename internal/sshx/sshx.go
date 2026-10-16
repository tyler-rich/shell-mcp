package sshx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// ErrForbidden (stub).
var ErrForbidden = errors.New("forbidden")

// Options (stub).
type Options struct {
	ConnectTimeout         time.Duration
	MaxSessions            int
	KeepaliveInterval      time.Duration
	BackoffMin, BackoffMax time.Duration
	Logger                 *slog.Logger
	Dial                   func(ctx context.Context, network, addr string) (net.Conn, error)
	Now                    func() time.Time
}

// Client (stub).
type Client struct{}

// New (stub).
func New(config.Target, Options) (*Client, error) { return &Client{}, nil }

// Session (stub).
func (c *Client) Session(context.Context) (*Session, error) { return nil, errors.New("stub") }

// Close (stub).
func (c *Client) Close() error { return nil }

func (c *Client) connected() bool { return false }

// Session (stub).
type Session struct{}

// Output (stub).
func (s *Session) Output(string) ([]byte, error) { return nil, nil }

// Close (stub).
func (s *Session) Close() error { return nil }

// RequestPty (stub).
func (s *Session) RequestPty(string, int, int, map[uint8]uint32) error { return nil }

// Setenv (stub).
func (s *Session) Setenv(string, string) error { return nil }

// Shell (stub).
func (s *Session) Shell() error { return nil }

// RequestSubsystem (stub).
func (s *Session) RequestSubsystem(string) error { return nil }

// Start (stub).
func (s *Session) Start(string) error { return nil }

// StdinPipe (stub).
func (s *Session) StdinPipe() (io.WriteCloser, error) { return nil, nil }

// HostKeyAlgorithms (stub).
func HostKeyAlgorithms([]config.HostKey) []string { return nil }
