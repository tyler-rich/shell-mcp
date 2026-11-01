package setup

import ()

// MaxScanPaths bounds --owner-scan-paths.
const MaxScanPaths = 32

// Options are install's flags (TARGET-SETUP §12.1).
type Options struct {
	Policy    string
	Principal string
	From      []string
	// Key is the server's public key file, absolute.
	Key  string
	User string
	UID  uint32
	GID  uint32
	Home string
	// SocketGroup and SocketGID are the helper's socket group; HasSocket
	// says either flag was given.
	SocketGroup string
	SocketGID   uint32
	HasSocket   bool
	// MemoryMax is --memory-max as given ("" for the default, "none").
	MemoryMax string
	// OwnerScanPaths narrows the owner scan; nil means the full scan.
	OwnerScanPaths []string
	DryRun         bool
	NoReload       bool
	ReplaceKey     bool
}

// Usage is install's usage line.
const Usage = `usage: shell-mcp-gate install --policy <file> --principal <label> --from <addr>[,<addr>…] --key <file.pub>
        --uid <n> --gid <n> [--user <name>] [--home <dir>] [--socket-group <name> --socket-gid <n>]
        [--memory-max <size>|none] [--owner-scan-paths <dir>[,<dir>…]] [--dry-run] [--no-reload] [--replace-key]
`

// ParseFlags parses install's arguments; cwd resolves a relative --key. A
// missing or malformed flag is an ErrUsage (exit 2); values are checked
// later, as refusals.
func ParseFlags(args []string, cwd string) (*Options, error) {
	var stub0 *Options
	var stub1 error
	return stub0, stub1
}

// The scan can be narrowed, never skipped: an empty list, "none"
// or anything else that scans nothing is a usage error.
