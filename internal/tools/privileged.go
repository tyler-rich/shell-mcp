package tools

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Privileged tools (docs/TOOLS.md, privileged tier; docs/PRIVILEGED.md §6):
// forwarded by the gate to the host's privileged helper, which runs them as
// root under its own policy and sandbox. They are registered in the admin
// profile only, and a target whose gate does not forward privileged
// operations does not serve them (EffectiveTools). Privileged operations of
// tier operator or above are always approval-gated (D-006, Deps.gated); the
// read tools below never are. The file read tools are variants of the
// gate's own (files.go, fileTool); shell_priv_list_backups is here.

// privilegedTools are the privileged tools, each registered at the tier it
// is defined with.
func privilegedTools(d *Deps) []Tool {
	return []Tool{privReadFile(d), privListDirectory(d), privStatPath(d), privListBackups(d),
		privWriteFile(d), privMakeDirectory(d), privCopyPath(d), privMovePath(d), privChangeOwner(d), privSetPermissions(d),
		privPreviewDelete(d), privDeletePath(d), privRestoreBackup(d), privRunCommand(d),
		privPreviewPackages(d), privUpdatePackageIndex(d), privInstallPackages(d), privUpgradePackages(d), privRemovePackages(d)}
}

type listBackupsIn struct {
	targetArg
	Path  string `json:"path,omitzero" jsonschema:"Only backups of this original path: absolute and clean. Default: every path."`
	Limit *int   `json:"limit,omitzero" jsonschema:"Most backups returned, newest first (1-1000, default 100)."`
}

func (in *listBackupsIn) validate() *envelope.Error {
	if e := checkOptPath("path", in.Path); e != nil {
		return e
	}
	return checkCount("limit", in.Limit, maxBackupList)
}

// maxBackupList is the helper's bound on priv_list_backups' limit.
const maxBackupList = 1000

// Backup is one backup's metadata, as the helper keeps it. Its content is
// never returned.
type Backup struct {
	ID      string `json:"id" jsonschema:"The backup id (YYYYMMDDTHHMMSSZ-<16 hex>)."`
	Kind    string `json:"kind" jsonschema:"file, or tree for a directory."`
	Path    string `json:"path" jsonschema:"The original path."`
	UID     uint32 `json:"uid" jsonschema:"The original owner's uid."`
	GID     uint32 `json:"gid" jsonschema:"The original group's gid."`
	Mode    string `json:"mode" jsonschema:"The original permission bits in octal."`
	Size    int64  `json:"size" jsonschema:"Bytes backed up."`
	SHA256  string `json:"sha256" jsonschema:"SHA-256 of the backed-up data."`
	Entries int    `json:"entries" jsonschema:"Entries in a tree backup; 0 for a file."`
	Created string `json:"created" jsonschema:"When it was made, RFC 3339."`
	Op      string `json:"op" jsonschema:"The operation that made it."`
}

// BackupList is shell_priv_list_backups' data.
type BackupList struct {
	Backups   []Backup `json:"backups" jsonschema:"Backups, newest first."`
	Truncated bool     `json:"truncated" jsonschema:"True when more backups existed than were returned (limit or output size)."`
}

type listBackupsWire struct {
	Path  string `json:"path,omitzero"`
	Limit int    `json:"limit,omitzero"`
}

func privListBackups(d *Deps) Tool {
	return define(d, spec[listBackupsIn, BackupList]{
		name:        "shell_priv_list_backups",
		title:       "List backups",
		description: "Lists, as root, the backups the privileged helper kept of what it overwrote or deleted, newest first: id, kind, original path, owner, mode, size, SHA-256, time and operation.",
		tier:        TierRead,
		privileged:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "path", pathPattern, 4096)
			intIn(s, "limit", 1, maxBackupList)
		},
		audit: func(in listBackupsIn) map[string]any { return map[string]any{"target": in.Target, "path": in.Path} },
		summary: func(l *BackupList) string {
			return plural(len(l.Backups), "backup", "backups") + truncated(l.Truncated)
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in listBackupsIn) envelope.Envelope[BackupList] {
			w := listBackupsWire{Path: in.Path}
			if in.Limit != nil {
				w.Limit = *in.Limit
			}
			env := fetch[BackupList](ctx, d, in.Target, protocol.OpPrivListBackups, w, d.budget())
			if env.OK && fitList(env.Data, &env.Data.Backups, d.maxOutput()) {
				env.Data.Truncated = true
			}
			return env
		},
	})
}
