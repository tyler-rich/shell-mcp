package setup

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
)

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
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := &Options{}
	var from, uid, gid, sgid, scan string
	fs.StringVar(&o.Policy, "policy", "", "")
	fs.StringVar(&o.Principal, "principal", "", "")
	fs.StringVar(&from, "from", "", "")
	fs.StringVar(&o.Key, "key", "", "")
	fs.StringVar(&o.User, "user", defaultUser, "")
	fs.StringVar(&uid, "uid", "", "")
	fs.StringVar(&gid, "gid", "", "")
	fs.StringVar(&o.Home, "home", "", "")
	fs.StringVar(&o.SocketGroup, "socket-group", "", "")
	fs.StringVar(&sgid, "socket-gid", "", "")
	fs.StringVar(&o.MemoryMax, "memory-max", "", "")
	fs.StringVar(&scan, "owner-scan-paths", "", "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	fs.BoolVar(&o.NoReload, "no-reload", false, "")
	fs.BoolVar(&o.ReplaceKey, "replace-key", false, "")
	usage := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrUsage}, a...)...)
	}
	if err := fs.Parse(args); err != nil {
		return nil, usage("%v", err)
	}
	if fs.NArg() != 0 {
		return nil, usage("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, req := range []string{"policy", "principal", "from", "key", "uid", "gid"} {
		if !set[req] {
			return nil, usage("--%s is required", req)
		}
	}
	var err error
	if o.UID, err = ParseID(uid); err != nil {
		return nil, usage("--uid: %v", err)
	}
	if o.GID, err = ParseID(gid); err != nil {
		return nil, usage("--gid: %v", err)
	}
	if set["socket-group"] || set["socket-gid"] {
		if !set["socket-group"] || !set["socket-gid"] {
			return nil, usage("--socket-group and --socket-gid go together")
		}
		o.HasSocket = true
		if o.SocketGID, err = ParseID(sgid); err != nil {
			return nil, usage("--socket-gid: %v", err)
		}
	}
	o.From = strings.Split(from, ",")
	if from == "" {
		o.From = nil
	}
	if set["owner-scan-paths"] {
		// The scan can be narrowed, never skipped: an empty list, "none"
		// or anything else that scans nothing is a usage error.
		if scan == "" || scan == "none" {
			return nil, usage("--owner-scan-paths %q scans nothing; the owner scan cannot be skipped (give directories, or leave the flag out for the full scan)", scan)
		}
		o.OwnerScanPaths = strings.Split(scan, ",")
		if len(o.OwnerScanPaths) > MaxScanPaths {
			return nil, usage("--owner-scan-paths: %d directories, at most %d", len(o.OwnerScanPaths), MaxScanPaths)
		}
		seen := map[string]bool{}
		for _, p := range o.OwnerScanPaths {
			switch {
			case p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p:
				return nil, usage("--owner-scan-paths: %q is not an absolute, clean directory", p)
			case seen[p]:
				return nil, usage("--owner-scan-paths: %q is listed twice", p)
			}
			seen[p] = true
		}
		slices.Sort(o.OwnerScanPaths)
	}
	if o.Home == "" {
		o.Home = "/var/lib/" + o.User
	}
	if o.Key != "" && !filepath.IsAbs(o.Key) {
		o.Key = filepath.Join(cwd, o.Key)
	}
	o.Key = filepath.Clean(o.Key)
	return o, nil
}
