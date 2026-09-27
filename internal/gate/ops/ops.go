//go:build linux

package ops

import (
	"io"

	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

// Options configures one gate run. ProductionOptions fills it from the
// running process; nothing in it comes from the request or the forced
// command line except PolicyPath and Principal.
type Options struct {
	Version    string
	PolicyPath string
	Principal  string

	Identity           install.Identity
	Trust              policy.Trust
	Executable         string
	SSHOriginalCommand *string
	ServiceHome        string

	// ApplySandbox applies the sandbox (production: sandbox.Apply).
	ApplySandbox func(*policy.Policy) (sandbox.Report, error)
	// InjectReadBackFault is passed to fsx; tests only.
	InjectReadBackFault func([]byte) []byte
}

// Serve runs the gate for one request: install checks, policy load,
// sandbox, then (only then) read one request, dispatch, and write one
// response. It returns the process exit code: 0 whenever a response was
// written, 1 if it could not be.
func Serve(o Options, stdin io.Reader, stdout io.Writer) int {
	return 1
}
