package gateclient

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// Opener (stub).
type Opener interface {
	Session(context.Context) (*sshx.Session, error)
}

// Options (stub).
type Options struct {
	Grace  time.Duration
	Logger *slog.Logger
}

// Client (stub).
type Client struct{}

// New (stub).
func New(Options) *Client { return &Client{} }

// Call (stub).
func (c *Client) Call(context.Context, Opener, string, any, time.Duration) (*protocol.Response, error) {
	return nil, errors.New("stub")
}
