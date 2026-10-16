package sshx

import (
	"errors"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// Pool holds one Client per configured target.
type Pool struct {
	clients map[string]*Client
}

// NewPool returns a client for every target in cfg. o's ConnectTimeout and
// MaxSessions default to cfg's SHELL_MCP_SSH_CONNECT_TIMEOUT and
// SHELL_MCP_SSH_MAX_SESSIONS.
func NewPool(cfg *config.Config, o Options) (*Pool, error) {
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = cfg.SSHConnectTimeout
	}
	if o.MaxSessions == 0 {
		o.MaxSessions = cfg.SSHMaxSessions
	}
	p := &Pool{clients: map[string]*Client{}}
	for _, t := range cfg.Targets {
		c, err := New(t, o)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.clients[t.Name] = c
	}
	return p, nil
}

// Get returns the client for the target named name.
func (p *Pool) Get(name string) (*Client, bool) {
	c, ok := p.clients[name]
	return c, ok
}

// Close closes every client.
func (p *Pool) Close() {
	var errs []error
	for _, c := range p.clients {
		errs = append(errs, c.Close())
	}
	_ = errors.Join(errs...)
}
