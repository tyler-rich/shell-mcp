package tools

import (
	"context"
	"reflect"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged delete tools (docs/TOOLS.md, privileged tier; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-4: D2, D9, D10, P-2a, P-3, Q7):
// shell_priv_preview_delete (read) sends priv_delete_preview;
// shell_priv_delete_path (destructive, admin profile, always
// approval-gated) uses that preview as its approval preview, bound with
// both policies' hashes, and its re-call sends priv_delete with the fresh
// preview's preview_sha256 (taken before the server's redaction) as
// expected_preview_sha256, so the helper backs up and deletes exactly what
// that preview listed, or nothing.

type privDeleteIn struct {
	targetArg
	Path      string `json:"path" jsonschema:"Absolute, clean path under a write root of the host's privileged policy. Never a write root itself; a final symlink is refused."`
	Recursive bool   `json:"recursive,omitzero" jsonschema:"Also delete everything under a directory, up to the privileged policy's max_delete_entries. Default false: only a file or an empty directory."`
	// expectedPreview is set only by an approved call: the preview_sha256
	// of its fresh preview (never an input).
	expectedPreview string
}

func (in *privDeleteIn) validate() *envelope.Error { return checkPath("path", in.Path) }

// PrivDeleteBackup is what a privileged delete backs up first.
type PrivDeleteBackup struct {
	Written bool   `json:"written" jsonschema:"True when the delete writes a backup first (the privileged policy keeps backups)."`
	Kind    string `json:"kind,omitempty" jsonschema:"file, or tree for a directory (its directories and regular files)."`
	Bytes   int64  `json:"bytes" jsonschema:"Size of the backup: the file's bytes, or the tree's archive."`
}

// PrivDeletePreview is shell_priv_preview_delete's data.
type PrivDeletePreview struct {
	Path          string           `json:"path" jsonschema:"The path."`
	Type          string           `json:"type" jsonschema:"file, dir, symlink or other."`
	Entries       int              `json:"entries" jsonschema:"Entries that would be deleted, the path itself included."`
	Bytes         int64            `json:"bytes" jsonschema:"Total size of the regular files among them."`
	First         []string         `json:"first" jsonschema:"The first entries (at most 50), the path first, then depth-first in byte order of names."`
	Truncated     bool             `json:"truncated" jsonschema:"True when first lists fewer entries than entries."`
	Backup        PrivDeleteBackup `json:"backup" jsonschema:"The backup written before anything is removed."`
	PreviewSHA256 string           `json:"preview_sha256" jsonschema:"SHA-256 over the privileged policy and every entry's path, type, size and identity; a delete runs only while it is unchanged."`
}

// PrivDeletePath is shell_priv_delete_path's data.
type PrivDeletePath struct {
	Path      string   `json:"path" jsonschema:"The path."`
	Type      string   `json:"type" jsonschema:"file, dir, symlink or other."`
	Entries   int      `json:"entries" jsonschema:"Entries deleted, the path itself included."`
	Bytes     int64    `json:"bytes" jsonschema:"Total size of the regular files deleted."`
	Deleted   bool     `json:"deleted" jsonschema:"True: everything the approved preview listed was deleted."`
	BackupIDs []string `json:"backup_ids" jsonschema:"The backups written first (none when the privileged policy keeps no backups)."`
}

// privDeletePreviewWire is the helper's priv_delete_preview data (P-2a).
type privDeletePreviewWire struct {
	Path          string           `json:"path"`
	Type          string           `json:"type"`
	Entries       int              `json:"entries"`
	Bytes         int64            `json:"bytes"`
	First         []string         `json:"first"`
	Truncated     bool             `json:"truncated"`
	Backup        PrivDeleteBackup `json:"backup"`
	PolicySHA256  string           `json:"policy_sha256"`
	PreviewSHA256 string           `json:"preview_sha256"`
}

// privDeleteWire is the helper's priv_delete data.
type privDeleteWire struct {
	Path      string   `json:"path"`
	Type      string   `json:"type"`
	Entries   int      `json:"entries"`
	Bytes     int64    `json:"bytes"`
	First     []string `json:"first"`
	Deleted   bool     `json:"deleted"`
	BackupIDs []string `json:"backup_ids"`
}

func privDeleteAudit(in privDeleteIn) map[string]any {
	return map[string]any{"target": in.Target, "path": in.Path, "recursive": in.Recursive}
}

func privPreviewDelete(d *Deps) Tool {
	return define(d, spec[privDeleteIn, PrivDeletePreview]{
		name:        "shell_priv_preview_delete",
		title:       "Preview delete as root",
		description: "Reports, as root, what deleting a path within the host's privileged write roots would remove and back up, without changing anything: type, entry count, total bytes, the first 50 entries, the backup and a hash of the complete list.",
		tier:        TierRead,
		privileged:  true,
		schema:      boundDelete,
		audit:       privDeleteAudit,
		summary:     func(p *PrivDeletePreview) string { return deleteSummary(p.Entries, p.Bytes) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privDeleteIn) envelope.Envelope[PrivDeletePreview] {
			r := fetch[privDeletePreviewWire](ctx, d, in.Target, protocol.OpPrivDeletePreview, deletePreviewWire{Path: in.Path, Recursive: in.Recursive}, d.budget())
			if !r.OK {
				return envelope.Failure[PrivDeletePreview](r.Target, r.Error)
			}
			x := r.Data
			out := PrivDeletePreview{Path: x.Path, Type: x.Type, Entries: x.Entries, Bytes: x.Bytes, First: x.First, Backup: x.Backup,
				PreviewSHA256: x.PreviewSHA256}
			if out.First == nil {
				out.First = []string{}
			}
			out.Truncated = fitList(&out, &out.First, d.maxOutput()) || x.Truncated || len(out.First) < out.Entries
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
	})
}

func privDeletePath(d *Deps) Tool {
	return define(d, spec[privDeleteIn, PrivDeletePath]{
		name:        "shell_priv_delete_path",
		title:       "Delete path as root",
		description: "Deletes, as root, a file, an empty directory, or with recursive a directory tree within the host's privileged write roots, exactly as its approved preview listed it, after backing it up; returns the counts and the backup ids.",
		tier:        TierDestructive,
		privileged:  true,
		schema:      boundDelete,
		audit:       privDeleteAudit,
		summary:     func(p *PrivDeletePath) string { return "deleted as root: " + deleteSummary(p.Entries, p.Bytes) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privDeleteIn) envelope.Envelope[PrivDeletePath] {
			// Only an approved call reaches this, with its fresh preview's
			// hash; the helper refuses a delete without one anyway.
			if in.expectedPreview == "" {
				return envelope.Failure[PrivDeletePath](in.Target, envelope.Errorf("internal", "a delete needs the hash of an approved preview; nothing was sent"))
			}
			w := deleteWire{Path: in.Path, Recursive: in.Recursive, ExpectedPreviewSHA256: in.expectedPreview}
			r := fetch[privDeleteWire](ctx, d, in.Target, protocol.OpPrivDelete, w, d.budget())
			if !r.OK {
				return envelope.Failure[PrivDeletePath](r.Target, r.Error)
			}
			x := r.Data
			if !x.Deleted {
				return envelope.Failure[PrivDeletePath](r.Target, envelope.Errorf("internal", "the helper answered without confirming the deletion; preview the path to see what remains"))
			}
			ids := x.BackupIDs
			if ids == nil {
				ids = []string{}
			}
			env := envelope.Success(r.Target, PrivDeletePath{Path: x.Path, Type: x.Type, Entries: x.Entries, Bytes: x.Bytes, Deleted: true, BackupIDs: ids})
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privDeleteIn) any {
			return struct {
				Path      string `json:"path"`
				Recursive bool   `json:"recursive"`
			}{in.Path, in.Recursive}
		},
		describe: func(in privDeleteIn, target string) string {
			return "As root, delete " + plain(in.Path, "a path shown in the arguments") + underIt(in.Recursive) + " on " + target
		},
		preview: d.privDeletePreview,
		precondition: func(in *privDeleteIn, p *preview) {
			in.expectedPreview = p.contentSHA256
		},
	})
}

// privDeletePreview is shell_priv_delete_path's approval preview: the
// helper's priv_delete_preview result (path, type, entries, bytes, the
// first entries, the backup and preview_sha256), bound with both policies'
// hashes. The hash the re-call sends back as the precondition is taken from
// the helper's answer before the server's redaction, which could otherwise
// rewrite it.
func (d *Deps) privDeletePreview(ctx context.Context, in privDeleteIn, target string) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, protocol.OpPrivDeletePreview, deletePreviewWire{Path: in.Path, Recursive: in.Recursive}, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[privDeletePreviewWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	policy, e := privPolicy(resp)
	if e != nil {
		return nil, e
	}
	hash := env.Data.PreviewSHA256
	if !sha256RE.MatchString(hash) {
		return nil, envelope.Errorf("internal", "the helper's preview has no valid preview_sha256")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	if x.First == nil {
		x.First = []string{}
	}
	backup := map[string]any{"written": x.Backup.Written, "bytes": x.Backup.Bytes}
	if x.Backup.Kind != "" {
		backup["kind"] = x.Backup.Kind
	}
	// The helper's warning that the tools could not restore this backup
	// (handoff N-9), on the approval page and bound with it.
	if len(env.Warnings) > 0 {
		ws := make([]string, len(env.Warnings))
		for i, w := range env.Warnings {
			ws[i] = d.redactor().String(w)
		}
		backup["restore"] = strings.Join(ws, "; ")
	}
	value := map[string]any{"path": x.Path, "recursive": in.Recursive, "type": x.Type, "entries": x.Entries, "bytes": x.Bytes,
		"first": x.First, "truncated": x.Truncated || len(x.First) < x.Entries, "backup": backup, "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash}, nil
}
