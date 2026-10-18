package tools

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
)

// Delete tools (docs/TOOLS.md): shell_preview_delete (read) and
// shell_delete_path (destructive, approval-gated). STUB.

type deleteIn struct {
	targetArg
	Path      string `json:"path" jsonschema:"Absolute, clean path under a write root of the target policy. Never a write root itself; a final symlink is refused."`
	Recursive bool   `json:"recursive,omitzero" jsonschema:"Also delete everything under a directory, up to the target policy's max_delete_entries. Default false: only a file or an empty directory."`
	// expectedPreview is set only by an approved call: the preview_sha256
	// of its fresh preview (never an input).
	expectedPreview string
}

func (in *deleteIn) validate() *envelope.Error { return checkPath("path", in.Path) }

// DeletePreview is shell_preview_delete's data.
type DeletePreview struct {
	Path          string   `json:"path" jsonschema:"The path."`
	Type          string   `json:"type" jsonschema:"file, dir, symlink or other."`
	Entries       int      `json:"entries" jsonschema:"Entries that would be deleted, the path itself included."`
	Bytes         int64    `json:"bytes" jsonschema:"Total size of the regular files among them."`
	First         []string `json:"first" jsonschema:"The first entries (at most 50), the path first, then depth-first in byte order of names."`
	Truncated     bool     `json:"truncated" jsonschema:"True when first lists fewer entries than entries."`
	PreviewSHA256 string   `json:"preview_sha256" jsonschema:"SHA-256 over every entry's path, type, size and identity; a delete runs only while it is unchanged."`
}

// DeletePath is shell_delete_path's data.
type DeletePath struct {
	Path    string `json:"path" jsonschema:"The path."`
	Type    string `json:"type" jsonschema:"file, dir, symlink or other."`
	Entries int    `json:"entries" jsonschema:"Entries deleted, the path itself included."`
	Bytes   int64  `json:"bytes" jsonschema:"Total size of the regular files deleted."`
	Deleted bool   `json:"deleted" jsonschema:"True: everything the approved preview listed was deleted."`
}

func boundDelete(s *jsonschema.Schema) {
	boundCommon(s)
	strIn(s, "path", pathPattern, 4096)
}

func deleteAudit(in deleteIn) map[string]any {
	return map[string]any{"target": in.Target, "path": in.Path, "recursive": in.Recursive}
}

func previewDelete(d *Deps) Tool {
	return define(d, spec[deleteIn, DeletePreview]{
		name:        "shell_preview_delete",
		title:       "Preview delete",
		description: "Reports what deleting a path would remove, without removing anything: type, entry count, total bytes, the first 50 entries and a hash of the complete list.",
		tier:        TierRead,
		schema:      boundDelete,
		audit:       deleteAudit,
		run: func(context.Context, *mcp.CallToolRequest, deleteIn) envelope.Envelope[DeletePreview] {
			return envelope.Failure[DeletePreview]("", envelope.Errorf("internal", "not implemented"))
		},
	})
}

func deletePath(d *Deps) Tool {
	return define(d, spec[deleteIn, DeletePath]{
		name:        "shell_delete_path",
		title:       "Delete path",
		description: "Deletes a file, an empty directory, or with recursive a directory tree under the target policy's write roots, exactly as its approved preview listed it.",
		tier:        TierDestructive,
		schema:      boundDelete,
		audit:       deleteAudit,
		run: func(context.Context, *mcp.CallToolRequest, deleteIn) envelope.Envelope[DeletePath] {
			return envelope.Failure[DeletePath]("", envelope.Errorf("internal", "not implemented"))
		},
		approvalArgs: func(in deleteIn) any { return in.Path },
		describe:     func(deleteIn, string) string { return "" },
		preview: func(context.Context, deleteIn, string) (*preview, *envelope.Error) {
			return nil, envelope.Errorf("internal", "not implemented")
		},
	})
}
