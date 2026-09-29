//go:build linux

// Package units generates the privileged helper's systemd units from its
// policy (docs/PRIVILEGED.md §2, §5.1): the socket unit and the templated
// service unit of the core sandbox, pinned to the policy's SHA-256. The
// broad unit arrives in S1d.
package units

import (
	"errors"

	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// Fixed paths and names (PRIVILEGED §2).
const (
	SocketPath  = "/run/shell-mcp/privd.sock"
	HelperPath  = "/usr/local/libexec/shell-mcp-privd"
	BackupDir   = "/var/lib/shell-mcp/backups"
	SocketUnit  = "shell-mcp-privd.socket"
	ServiceUnit = "shell-mcp-privd@.service"
	// HashEnv carries the policy hash into the helper.
	HashEnv = "SHELL_MCP_PRIVD_POLICY_SHA256"
)

// Files are the generated unit files' contents.
type Files struct {
	Socket  string
	Service string
}

// Core generates the core unit pair for a validated policy.
func Core(p *policy.Policy) (Files, error) { return Files{}, errors.New("not implemented") }
