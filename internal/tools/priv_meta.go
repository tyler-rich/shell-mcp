package tools

import (
	"context"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged chown and chmod tools (docs/TOOLS.md, privileged tier;
// handoff docs/handoff/S4C-PRIVILEGED.md S4c-3: D2, D4, D9, P-2b, P-3,
// P-4): shell_priv_change_owner and shell_priv_set_permissions. They are
// operator-tier and privileged, so always approval-gated (D-006). The
// approval preview is the helper's priv_chown_preview or priv_chmod_preview
// (every entry's identity and current owner, group and mode, hashed with
// the change and the privileged policy), bound with both policies' hashes;
// the re-call sends the fresh preview's preview_sha256, taken before the
// server's redaction, as expected_preview_sha256, so the helper changes
// exactly what the approver saw, or nothing.

type privChownIn struct {
	targetArg
	Path      string `json:"path" jsonschema:"Absolute, clean path under a write root of the host's privileged policy; never a write root itself. A final symlink is refused."`
	Owner     string `json:"owner,omitzero" jsonschema:"User to own it; it must be in the host's privileged policy's owners.users. At least one of owner and group."`
	Group     string `json:"group,omitzero" jsonschema:"Group to own it; it must be in the host's privileged policy's owners.groups. At least one of owner and group."`
	Recursive bool   `json:"recursive,omitzero" jsonschema:"Also change everything under a directory, up to the privileged policy's max_delete_entries entries; symlinks are never followed or changed. Default false."`
	// expectedPreview, entries and changes are what an approved call's
	// fresh preview saw (never inputs): its hash, sent as
	// expected_preview_sha256, and its counts.
	expectedPreview string
	entries         int
	changes         int
}

func (in *privChownIn) validate() *envelope.Error {
	if e := checkPath("path", in.Path); e != nil {
		return e
	}
	if in.Owner == "" && in.Group == "" {
		return invalid("owner or group is required")
	}
	if e := checkOwner("owner", in.Owner); e != nil {
		return e
	}
	return checkOwner("group", in.Group)
}

type privChmodIn struct {
	targetArg
	Path      string `json:"path" jsonschema:"Absolute, clean path under a write root of the host's privileged policy; never a write root itself. A final symlink is refused."`
	Mode      string `json:"mode" jsonschema:"Octal mode (3 or 4 digits, such as 0640) within the privileged policy's modes.max; never setuid, setgid, sticky or world-writable."`
	Recursive bool   `json:"recursive,omitzero" jsonschema:"Also set the mode of everything under a directory, up to the privileged policy's max_delete_entries entries; symlinks are never followed or changed. Default false."`
	// As privChownIn's (never inputs).
	expectedPreview string
	entries         int
	changes         int
}

func (in *privChmodIn) validate() *envelope.Error {
	if e := checkPath("path", in.Path); e != nil {
		return e
	}
	return checkMode(in.Mode, true)
}

// PrivChangeOwner is shell_priv_change_owner's data.
type PrivChangeOwner struct {
	Path      string `json:"path" jsonschema:"The path."`
	Recursive bool   `json:"recursive" jsonschema:"Whether everything under it was included."`
	Entries   int    `json:"entries" jsonschema:"Entries of the approved preview, the path itself included."`
	Changed   int    `json:"changed" jsonschema:"Entries whose owner or group was changed (the others already had them, or are symlinks)."`
	UID       uint32 `json:"uid" jsonschema:"The path's owner uid now."`
	GID       uint32 `json:"gid" jsonschema:"The path's group gid now."`
	Owner     string `json:"owner,omitempty" jsonschema:"The owner set, when one was given."`
	Group     string `json:"group,omitempty" jsonschema:"The group set, when one was given."`
}

// PrivSetPermissions is shell_priv_set_permissions' data.
type PrivSetPermissions struct {
	Path      string `json:"path" jsonschema:"The path."`
	Recursive bool   `json:"recursive" jsonschema:"Whether everything under it was included."`
	Entries   int    `json:"entries" jsonschema:"Entries of the approved preview, the path itself included."`
	Changed   int    `json:"changed" jsonschema:"Entries whose mode was changed (the others already had it, or are symlinks)."`
	OldMode   string `json:"old_mode" jsonschema:"The path's mode before (octal)."`
	Mode      string `json:"mode" jsonschema:"The path's mode now (octal)."`
}

type privChownWire struct {
	Path                  string `json:"path"`
	Owner                 string `json:"owner"`
	Group                 string `json:"group"`
	Recursive             bool   `json:"recursive"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256,omitzero"`
}

type privChmodWire struct {
	Path                  string `json:"path"`
	Mode                  string `json:"mode"`
	Recursive             bool   `json:"recursive"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256,omitzero"`
}

// privMetaPreviewWire is the helper's priv_chown_preview and
// priv_chmod_preview data (P-2b).
type privMetaPreviewWire struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Entries int    `json:"entries"`
	Changes int    `json:"changes"`
	First   []struct {
		Path     string `json:"path"`
		Type     string `json:"type"`
		UID      uint32 `json:"uid"`
		GID      uint32 `json:"gid"`
		Owner    string `json:"owner"`
		Group    string `json:"group"`
		Mode     string `json:"mode"`
		NewUID   uint32 `json:"new_uid"`
		NewGID   uint32 `json:"new_gid"`
		NewOwner string `json:"new_owner"`
		NewGroup string `json:"new_group"`
		NewMode  string `json:"new_mode"`
	} `json:"first"`
	Truncated     bool   `json:"truncated"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

type privChownResultWire struct {
	Path   string `json:"path"`
	OldUID uint32 `json:"old_uid"`
	OldGID uint32 `json:"old_gid"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type privChmodResultWire struct {
	Path    string `json:"path"`
	OldMode string `json:"old_mode"`
	Mode    string `json:"mode"`
}

// privMetaPreview is the approval preview of both tools: the helper's
// preview op's result, with what will be set, bound with both policies'
// hashes. The hash passed on as expected_preview_sha256 is the helper's,
// taken before the server's redaction.
func (d *Deps) privMetaPreview(ctx context.Context, target, op string, args any, recursive bool, set map[string]any) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, op, args, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[privMetaPreviewWire](target, resp)
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
	first := make([]map[string]any, 0, len(x.First))
	for i := range x.First {
		f := &x.First[i]
		e := map[string]any{"path": f.Path, "type": f.Type, "uid": f.UID, "gid": f.GID, "mode": f.Mode,
			"new_uid": f.NewUID, "new_gid": f.NewGID, "new_mode": f.NewMode}
		for k, v := range map[string]string{"owner": f.Owner, "group": f.Group, "new_owner": f.NewOwner, "new_group": f.NewGroup} {
			if v != "" {
				e[k] = v
			}
		}
		first = append(first, e)
	}
	value := map[string]any{"path": x.Path, "recursive": recursive, "type": x.Type, "entries": x.Entries, "changes": x.Changes,
		"first": first, "truncated": x.Truncated || len(x.First) < x.Entries, "set": set, "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash}, nil
}

func boundPrivMeta(s *jsonschema.Schema) {
	boundCommon(s)
	strIn(s, "path", pathPattern, 4096)
	p := prop(s, "recursive")
	p.Type, p.Types = "boolean", nil
}

func underIt(recursive bool) string {
	if recursive {
		return " and everything under it"
	}
	return ""
}

func privChangeOwner(d *Deps) Tool {
	return define(d, spec[privChownIn, PrivChangeOwner]{
		name:        "shell_priv_change_owner",
		title:       "Change owner as root",
		description: "Changes the owner and/or group of a file or directory as root (with recursive, also of everything under it) within the host's privileged write roots, exactly as its approved preview listed; returns the counts and the owner set.",
		tier:        TierOperator,
		privileged:  true,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundPrivMeta(s)
			boundOwner(s)
		},
		audit: func(in privChownIn) map[string]any {
			m := map[string]any{"target": in.Target, "path": in.Path, "recursive": in.Recursive}
			for k, v := range map[string]string{"owner": in.Owner, "group": in.Group} {
				if v != "" {
					m[k] = v
				}
			}
			return m
		},
		summary: func(c *PrivChangeOwner) string {
			return "owner changed as root: " + plural(c.Changed, "entry", "entries") + " of " + plural(c.Entries, "entry", "entries")
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privChownIn) envelope.Envelope[PrivChangeOwner] {
			// Only an approved call reaches this, with its fresh preview's
			// hash; the helper refuses one without it anyway.
			if in.expectedPreview == "" {
				return envelope.Failure[PrivChangeOwner](in.Target, envelope.Errorf("internal", "a change needs the hash of an approved preview; nothing was sent"))
			}
			w := privChownWire{Path: in.Path, Owner: in.Owner, Group: in.Group, Recursive: in.Recursive, ExpectedPreviewSHA256: in.expectedPreview}
			r := fetch[privChownResultWire](ctx, d, in.Target, protocol.OpPrivChown, w, d.budget())
			if !r.OK {
				return envelope.Failure[PrivChangeOwner](r.Target, r.Error)
			}
			x := r.Data
			env := envelope.Success(r.Target, PrivChangeOwner{Path: x.Path, Recursive: in.Recursive, Entries: in.entries, Changed: in.changes,
				UID: x.UID, GID: x.GID, Owner: in.Owner, Group: in.Group})
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privChownIn) any {
			return struct {
				Path      string `json:"path"`
				Owner     string `json:"owner"`
				Group     string `json:"group"`
				Recursive bool   `json:"recursive"`
			}{in.Path, in.Owner, in.Group, in.Recursive}
		},
		describe: func(in privChownIn, target string) string {
			what, to := "the owner and group", in.Owner+":"+in.Group
			switch {
			case in.Group == "":
				what, to = "the owner", in.Owner
			case in.Owner == "":
				what, to = "the group", in.Group
			}
			return "As root, change " + what + " of " + plain(in.Path, "a path shown in the arguments") + underIt(in.Recursive) + " to " + to + " on " + target
		},
		preview: func(ctx context.Context, in privChownIn, target string) (*preview, *envelope.Error) {
			set := map[string]any{"owner": willSet(in.Owner, "kept"), "group": willSet(in.Group, "kept")}
			args := privChownWire{Path: in.Path, Owner: in.Owner, Group: in.Group, Recursive: in.Recursive}
			return d.privMetaPreview(ctx, target, protocol.OpPrivChownPreview, args, in.Recursive, set)
		},
		precondition: func(in *privChownIn, p *preview) { in.expectedPreview, in.entries, in.changes = metaPrecondition(p) },
	})
}

// metaPrecondition is what the fresh preview passes on: its hash, and its
// counts, read from its value (which the approval bound).
func metaPrecondition(p *preview) (hash string, entries, changes int) {
	if v, ok := p.value.(map[string]any); ok {
		entries, _ = v["entries"].(int)
		changes, _ = v["changes"].(int)
	}
	return p.contentSHA256, entries, changes
}

func privSetPermissions(d *Deps) Tool {
	return define(d, spec[privChmodIn, PrivSetPermissions]{
		name:        "shell_priv_set_permissions",
		title:       "Set permissions as root",
		description: "Sets the mode of a file or directory as root (with recursive, also of everything under it) within the host's privileged write roots, exactly as its approved preview listed; returns the counts and the old and new mode.",
		tier:        TierOperator,
		privileged:  true,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundPrivMeta(s)
			strIn(s, "mode", modePattern, 4)
		},
		audit: func(in privChmodIn) map[string]any {
			return map[string]any{"target": in.Target, "path": in.Path, "mode": in.Mode, "recursive": in.Recursive}
		},
		summary: func(c *PrivSetPermissions) string {
			return "mode set as root: " + plural(c.Changed, "entry", "entries") + " of " + plural(c.Entries, "entry", "entries")
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privChmodIn) envelope.Envelope[PrivSetPermissions] {
			if in.expectedPreview == "" {
				return envelope.Failure[PrivSetPermissions](in.Target, envelope.Errorf("internal", "a change needs the hash of an approved preview; nothing was sent"))
			}
			w := privChmodWire{Path: in.Path, Mode: in.Mode, Recursive: in.Recursive, ExpectedPreviewSHA256: in.expectedPreview}
			r := fetch[privChmodResultWire](ctx, d, in.Target, protocol.OpPrivChmod, w, d.budget())
			if !r.OK {
				return envelope.Failure[PrivSetPermissions](r.Target, r.Error)
			}
			x := r.Data
			env := envelope.Success(r.Target, PrivSetPermissions{Path: x.Path, Recursive: in.Recursive, Entries: in.entries, Changed: in.changes,
				OldMode: x.OldMode, Mode: x.Mode})
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privChmodIn) any {
			return struct {
				Path      string `json:"path"`
				Mode      string `json:"mode"`
				Recursive bool   `json:"recursive"`
			}{in.Path, in.Mode, in.Recursive}
		},
		describe: func(in privChmodIn, target string) string {
			return "As root, set the mode of " + plain(in.Path, "a path shown in the arguments") + underIt(in.Recursive) + " to " + in.Mode + " on " + target
		},
		preview: func(ctx context.Context, in privChmodIn, target string) (*preview, *envelope.Error) {
			args := privChmodWire{Path: in.Path, Mode: in.Mode, Recursive: in.Recursive}
			return d.privMetaPreview(ctx, target, protocol.OpPrivChmodPreview, args, in.Recursive, map[string]any{"mode": in.Mode})
		},
		precondition: func(in *privChmodIn, p *preview) { in.expectedPreview, in.entries, in.changes = metaPrecondition(p) },
	})
}
