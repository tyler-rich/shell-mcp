//go:build shellmcp_diag

package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DiagBuild reports whether this binary carries the elicitation diagnostic
// tool (build tag shellmcp_diag). Release builds and CI's image never do.
const DiagBuild = true

func registerDiag(r *Registry, d *Deps) error { return nil } // stub

var _ = context.Background
var _ = mcp.NewServer
