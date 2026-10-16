package tools

import (
	"log/slog"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
)

// Deps (stub).
type Deps struct {
	Targets        []config.Target
	DefaultTarget  string
	Opener         func(target string) (gateclient.Opener, bool)
	Gate           *gateclient.Client
	Principal      auth.Principal
	Logger         *slog.Logger
	DefaultTimeout time.Duration
}

// Catalogue (stub).
func Catalogue(*Deps) (*Registry, error) { return NewRegistry(), nil }
