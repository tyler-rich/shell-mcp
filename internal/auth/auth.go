package auth

import (
	"net/http"
)

// Principal is the authenticated MCP caller.
type Principal struct {
	Name    string
	Profile string
}

// Middleware is the bearer-auth middleware. (stub)
type Middleware struct{}

// Handler wraps next. (stub)
func (m *Middleware) Handler(next http.Handler) http.Handler { return next }

// Tracked is the number of clients with recorded failures. (stub)
func (m *Middleware) Tracked() int { return 0 }
