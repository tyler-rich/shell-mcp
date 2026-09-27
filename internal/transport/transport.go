package transport

import (
	"errors"
	"net/http"

	"github.com/tyler-rich/shell-mcp/internal/config"
)

// ErrBearerNotImplemented is returned for bearer mode until Session 2.
var ErrBearerNotImplemented = errors.New("bearer auth arrives in Session 2")

// New builds the HTTP server.
func New(_ *config.Config, _ http.Handler) (*http.Server, error) {
	return nil, errors.New("not implemented")
}
