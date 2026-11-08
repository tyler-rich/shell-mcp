//go:build linux

package setup

import (
	"fmt"
	"io"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// MoveOptions are move-key's flags (TARGET-SETUP §12.1, "Moving a key
// between accounts").
type MoveOptions struct {
	// Principal selects the line: its forced command's --principal.
	Principal string
	// FromUser and ToUser are the source and destination accounts.
	FromUser, ToUser string
	DryRun           bool
	NoReload         bool
}

// MoveUsage is move-key's usage line.
const MoveUsage = `usage: shell-mcp-gate move-key --principal <label> --from-user <name> --to-user <name> [--dry-run] [--no-reload]
`

// ParseMoveFlags parses move-key's arguments. Not implemented yet.
func ParseMoveFlags(_ []string) (*MoveOptions, error) {
	return nil, fmt.Errorf("%w: move-key is not implemented", ErrUsage)
}

// MoveKey runs shell-mcp-gate move-key. Not implemented yet.
func MoveKey(_ *MoveOptions, _ Host, stdout io.Writer, _ *setupx.Auditor) int {
	_, _ = io.WriteString(stdout, "FAIL move-key is not implemented\n")
	return 1
}
