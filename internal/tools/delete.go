package tools

import (
	"context"
	"fmt"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Delete tools (docs/TOOLS.md): shell_preview_delete (read tier) sends
// delete_preview; shell_delete_path (destructive, admin profile, always
// approval-gated) uses delete_preview's result as its approval preview,
// and its re-call sends delete with the fresh preview's preview_sha256 as
// expected_preview_sha256, so the gate deletes exactly what that preview
// listed or nothing at all.

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

// deletePlanWire is the gate's delete_preview and delete data (fsx.DeletePlan).
type deletePlanWire struct {
	Path          string   `json:"path"`
	Type          string   `json:"type"`
	Entries       int      `json:"entries"`
	Bytes         int64    `json:"bytes"`
	First         []string `json:"first"`
	PreviewSHA256 string   `json:"preview_sha256"`
	Deleted       bool     `json:"deleted"`
}

type deletePreviewWire struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

type deleteWire struct {
	Path                  string `json:"path"`
	Recursive             bool   `json:"recursive"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

func boundDelete(s *jsonschema.Schema) {
	boundCommon(s)
	strIn(s, "path", pathPattern, 4096)
	p := prop(s, "recursive")
	p.Type, p.Types = "boolean", nil
}

func deleteAudit(in deleteIn) map[string]any {
	return map[string]any{"target": in.Target, "path": in.Path, "recursive": in.Recursive}
}

func deleteSummary(entries int, bytes int64) string {
	return plural(entries, "entry", "entries") + ", " + fmt.Sprintf("%d bytes", bytes)
}

func previewDelete(d *Deps) Tool {
	return define(d, spec[deleteIn, DeletePreview]{
		name:        "shell_preview_delete",
		title:       "Preview delete",
		description: "Reports what deleting a path would remove, without removing anything: type, entry count, total bytes, the first 50 entries and a hash of the complete list.",
		tier:        TierRead,
		schema:      boundDelete,
		audit:       deleteAudit,
		summary:     func(p *DeletePreview) string { return deleteSummary(p.Entries, p.Bytes) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in deleteIn) envelope.Envelope[DeletePreview] {
			r := fetch[deletePlanWire](ctx, d, in.Target, protocol.OpDeletePreview, deletePreviewWire{Path: in.Path, Recursive: in.Recursive}, d.budget())
			if !r.OK {
				return envelope.Failure[DeletePreview](r.Target, r.Error)
			}
			x := r.Data
			out := DeletePreview{Path: x.Path, Type: x.Type, Entries: x.Entries, Bytes: x.Bytes, First: x.First, PreviewSHA256: x.PreviewSHA256}
			if out.First == nil {
				out.First = []string{}
			}
			out.Truncated = fitList(&out, &out.First, d.maxOutput()) || len(out.First) < out.Entries
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
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
		summary:     func(p *DeletePath) string { return "deleted " + deleteSummary(p.Entries, p.Bytes) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in deleteIn) envelope.Envelope[DeletePath] {
			// Only an approved call reaches this, with its fresh preview's
			// hash; the gate refuses a delete without one anyway.
			if in.expectedPreview == "" {
				return envelope.Failure[DeletePath](in.Target, envelope.Errorf("internal", "a delete needs the hash of an approved preview; nothing was sent"))
			}
			w := deleteWire{Path: in.Path, Recursive: in.Recursive, ExpectedPreviewSHA256: in.expectedPreview}
			r := fetch[deletePlanWire](ctx, d, in.Target, protocol.OpDelete, w, d.budget())
			if !r.OK {
				return envelope.Failure[DeletePath](r.Target, r.Error)
			}
			x := r.Data
			if !x.Deleted {
				return envelope.Failure[DeletePath](r.Target, envelope.Errorf("internal", "the gate answered without confirming the deletion; preview the path to see what remains"))
			}
			env := envelope.Success(r.Target, DeletePath{Path: x.Path, Type: x.Type, Entries: x.Entries, Bytes: x.Bytes, Deleted: true})
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in deleteIn) any {
			return struct {
				Path      string `json:"path"`
				Recursive bool   `json:"recursive"`
			}{in.Path, in.Recursive}
		},
		describe: func(in deleteIn, target string) string {
			what := "Delete " + plain(in.Path, "a path shown in the arguments")
			if in.Recursive {
				what += " and everything under it"
			}
			return what + " on " + target
		},
		preview: d.deletePreview,
		precondition: func(in *deleteIn, p *preview) {
			in.expectedPreview = p.contentSHA256
		},
	})
}

// deletePreview is shell_delete_path's approval preview: the gate's
// delete_preview result (path, type, entries, bytes, the first entries and
// preview_sha256). The hash the re-call sends back as the precondition is
// taken from the gate's answer before the server's redaction, which could
// otherwise rewrite it.
func (d *Deps) deletePreview(ctx context.Context, in deleteIn, target string) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, protocol.OpDeletePreview, deletePreviewWire{Path: in.Path, Recursive: in.Recursive}, d.budget())
	if e != nil {
		return nil, e
	}
	policy := ""
	if resp.Gate != nil {
		policy = resp.Gate.PolicySHA256
	}
	env := envelope.FromGate[deletePlanWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	hash := env.Data.PreviewSHA256
	if !sha256RE.MatchString(hash) {
		return nil, envelope.Errorf("internal", "the gate's preview has no valid preview_sha256")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	if x.First == nil {
		x.First = []string{}
	}
	value := map[string]any{"path": x.Path, "recursive": in.Recursive, "type": x.Type, "entries": x.Entries, "bytes": x.Bytes,
		"first": x.First, "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash}, nil
}
