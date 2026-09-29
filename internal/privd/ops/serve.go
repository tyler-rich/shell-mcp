//go:build linux

// Package ops is the privileged helper's serve pipeline (docs/PRIVILEGED.md
// §3, §6, §7, §8; ARCHITECTURE §3 step 5): self-checks → policy → peer
// credentials → Landlock → read one request → tier → op against the
// privileged policy → backup → execute → verify → respond → audit.
package ops

import (
	"io"
	"os"
	"time"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// Options configures one helper run. ProductionOptions fills it from the
// running process; nothing in it comes from the connection.
type Options struct {
	Version    string
	PolicyPath string
	// Executable is the helper binary's resolved path.
	Executable string
	// ExpectedSHA256 is SHELL_MCP_PRIVD_POLICY_SHA256 from the unit.
	ExpectedSHA256 string
	Trust          gpolicy.Trust
	// Lookups fills the policy loader's user and group lookups
	// (production: policy.ProductionLookups).
	Lookups func(*policy.LoadOptions)
	// SystemBinDirs are the identity check's directories (nil: defaults).
	SystemBinDirs []string
	// ReadStatus returns /proc/self/status.
	ReadStatus func() ([]byte, error)
	// Conn is the accepted connection (stdin under the unit).
	Conn *os.File
	// BackupDir is the backup store (production: units.BackupDir).
	BackupDir string
	// ApplySandbox applies Landlock (production: the helper's ruleset).
	ApplySandbox func(*policy.Policy, string) (sandbox.Report, error)
	// Audit receives one line per connection (production: stderr, which
	// the unit sends to the journal).
	Audit io.Writer
	// InjectReadBackFault is passed to fsx; tests only.
	InjectReadBackFault func([]byte) []byte
	// Now is the clock (backup ids and times).
	Now func() time.Time
}

// Serve handles one connection and returns the process exit code: 0 when a
// response was written, 1 otherwise (including every refusal, which closes
// the connection without a response).
func Serve(o *Options) int { return 1 }
