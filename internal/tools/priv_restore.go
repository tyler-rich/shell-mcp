package tools

import (
	"context"
	"reflect"
	"regexp"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged restore tool (docs/TOOLS.md, privileged tier; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-5: D3, D9, P-2c, P-3, P-10):
// shell_priv_restore_backup (operator, admin profile, always
// approval-gated) uses the helper's priv_restore_preview as its approval
// preview, bound with both policies' hashes, and its re-call sends
// priv_restore_backup with the fresh preview's preview_sha256 (taken before
// the server's redaction) as expected_preview_sha256, so the helper restores
// exactly the backup and over exactly the file that preview showed, or
// nothing.

// backupIDPattern is a backup id as the helper makes it.
const backupIDPattern = `^\d{8}T\d{6}Z-[0-9a-f]{16}$`

var backupIDRE = regexp.MustCompile(backupIDPattern)

type privRestoreIn struct {
	targetArg
	BackupID string `json:"backup_id" jsonschema:"The backup to restore, as shell_priv_list_backups lists it: YYYYMMDDTHHMMSSZ-<16 hex>."`
	// expectedPreview is set only by an approved call: the preview_sha256
	// of its fresh preview (never an input).
	expectedPreview string
}

func (in *privRestoreIn) validate() *envelope.Error {
	if !backupIDRE.MatchString(in.BackupID) {
		return invalid("backup_id must be a backup id (YYYYMMDDTHHMMSSZ-<16 lowercase hex>)")
	}
	return nil
}

// PrivRestoreEntry is one tree entry's recorded mode and the mode it gets.
type PrivRestoreEntry struct {
	Path         string `json:"path" jsonschema:"The entry's path."`
	Type         string `json:"type" jsonschema:"file or dir."`
	RecordedMode string `json:"recorded_mode" jsonschema:"The mode the backup recorded, in octal."`
	Mode         string `json:"mode" jsonschema:"The mode set, in octal: the recorded one without setuid, setgid, sticky and world-write, masked by the host's modes.max."`
}

// PrivRestore is shell_priv_restore_backup's data.
type PrivRestore struct {
	ID           string             `json:"id" jsonschema:"The backup restored."`
	Path         string             `json:"path" jsonschema:"Where it was restored."`
	Kind         string             `json:"kind" jsonschema:"file, or tree for a directory."`
	SHA256       string             `json:"sha256,omitempty" jsonschema:"A restored file's SHA-256, read back."`
	Entries      int                `json:"entries,omitempty" jsonschema:"A restored tree's entries, its own directory not included."`
	BackupIDs    []string           `json:"backup_ids" jsonschema:"The backup of the version the restore replaced (none for a tree or an absent file); it can be restored in turn."`
	Mode         string             `json:"mode" jsonschema:"The mode set on the file or the tree's directory, in octal."`
	RecordedMode string             `json:"recorded_mode" jsonschema:"The mode the backup recorded for it, in octal."`
	Narrowed     int                `json:"narrowed" jsonschema:"How many entries (the file or the tree's directory included) got a narrower mode than recorded."`
	First        []PrivRestoreEntry `json:"first" jsonschema:"For a tree, its first entries (at most 50) with their recorded and resulting modes."`
	Truncated    bool               `json:"truncated" jsonschema:"True when first lists fewer entries than the tree has."`
}

// privRestorePreviewWire is the helper's priv_restore_preview data (P-2c).
type privRestorePreviewWire struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Backup struct {
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
		Entries int    `json:"entries"`
		UID     uint32 `json:"uid"`
		GID     uint32 `json:"gid"`
		Owner   string `json:"owner,omitempty"`
		Group   string `json:"group,omitempty"`
		Mode    string `json:"mode"`
		Created string `json:"created"`
		Op      string `json:"op"`
	} `json:"backup"`
	Current struct {
		State  string  `json:"state"`
		Size   *int64  `json:"size,omitempty"`
		Mode   string  `json:"mode,omitempty"`
		UID    *uint32 `json:"uid,omitempty"`
		GID    *uint32 `json:"gid,omitempty"`
		Owner  string  `json:"owner,omitempty"`
		Group  string  `json:"group,omitempty"`
		SHA256 string  `json:"sha256,omitempty"`
	} `json:"current"`
	Restore struct {
		UID          uint32             `json:"uid"`
		GID          uint32             `json:"gid"`
		Mode         string             `json:"mode"`
		RecordedMode string             `json:"recorded_mode"`
		Narrowed     int                `json:"narrowed"`
		First        []PrivRestoreEntry `json:"first"`
		Truncated    bool               `json:"truncated"`
	} `json:"restore"`
	CurrentBackup struct {
		Written bool   `json:"written"`
		Kind    string `json:"kind,omitempty"`
		Bytes   int64  `json:"bytes"`
	} `json:"current_backup"`
	PolicySHA256  string `json:"policy_sha256"`
	PreviewSHA256 string `json:"preview_sha256"`
}

// privRestoreWire is the helper's priv_restore_backup data.
type privRestoreWire struct {
	ID           string             `json:"id"`
	Path         string             `json:"path"`
	Kind         string             `json:"kind"`
	SHA256       string             `json:"sha256,omitempty"`
	Entries      int                `json:"entries,omitempty"`
	Verified     bool               `json:"verified"`
	BackupIDs    []string           `json:"backup_ids"`
	Mode         string             `json:"mode"`
	RecordedMode string             `json:"recorded_mode"`
	Narrowed     int                `json:"narrowed"`
	First        []PrivRestoreEntry `json:"first"`
	Truncated    bool               `json:"truncated"`
}

type restorePreviewWire struct {
	ID string `json:"id"`
}

type restoreWire struct {
	ID                    string `json:"id"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

func privRestoreBackup(d *Deps) Tool {
	return define(d, spec[privRestoreIn, PrivRestore]{
		name:        "shell_priv_restore_backup",
		title:       "Restore backup as root",
		description: "Restores, as root, a backup the privileged helper kept, over exactly the version its approved preview showed (that version is backed up first), with the recorded owner and the recorded mode within the host's mask; returns the modes set and the new backup's id.",
		tier:        TierOperator,
		privileged:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "backup_id", backupIDPattern, 33)
		},
		audit: func(in privRestoreIn) map[string]any {
			return map[string]any{"target": in.Target, "backup_id": in.BackupID}
		},
		summary: func(p *PrivRestore) string {
			if p.Kind == "tree" {
				return "restored as root: " + plural(p.Entries, "entry", "entries")
			}
			return "restored as root: a file"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privRestoreIn) envelope.Envelope[PrivRestore] {
			// Only an approved call reaches this, with its fresh preview's
			// hash; the helper refuses a restore without one anyway.
			if in.expectedPreview == "" {
				return envelope.Failure[PrivRestore](in.Target, envelope.Errorf("internal", "a restore needs the hash of an approved preview; nothing was sent"))
			}
			r := fetch[privRestoreWire](ctx, d, in.Target, protocol.OpPrivRestoreBackup, restoreWire{ID: in.BackupID, ExpectedPreviewSHA256: in.expectedPreview}, d.budget())
			if !r.OK {
				return envelope.Failure[PrivRestore](r.Target, r.Error)
			}
			x := r.Data
			if !x.Verified {
				return verifiedFailure[PrivRestore](r.Target)
			}
			out := PrivRestore{ID: x.ID, Path: x.Path, Kind: x.Kind, SHA256: x.SHA256, Entries: x.Entries, BackupIDs: x.BackupIDs, Mode: x.Mode,
				RecordedMode: x.RecordedMode, Narrowed: x.Narrowed, First: x.First, Truncated: x.Truncated}
			if out.BackupIDs == nil {
				out.BackupIDs = []string{}
			}
			if out.First == nil {
				out.First = []PrivRestoreEntry{}
			}
			if fitList(&out, &out.First, d.maxOutput()) {
				out.Truncated = true
			}
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings, env.Verified = r.Gate, r.Warnings, new(true)
			return env
		},
		approvalArgs: func(in privRestoreIn) any {
			return struct {
				BackupID string `json:"backup_id"`
			}{in.BackupID}
		},
		describe: func(in privRestoreIn, target string) string {
			return "As root, restore backup " + in.BackupID + " on " + target
		},
		preview: d.privRestorePreview,
		precondition: func(in *privRestoreIn, p *preview) {
			in.expectedPreview = p.contentSHA256
		},
	})
}

// privRestorePreview is shell_priv_restore_backup's approval preview: the
// helper's priv_restore_preview result (the backup's record, the current
// state at its path, what will be set, whether the current version is
// backed up, and preview_sha256), bound with both policies' hashes. The
// hash the re-call sends back as the precondition is taken from the
// helper's answer before the server's redaction.
func (d *Deps) privRestorePreview(ctx context.Context, in privRestoreIn, target string) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, protocol.OpPrivRestorePreview, restorePreviewWire{ID: in.BackupID}, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[privRestorePreviewWire](target, resp)
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
	b := x.Backup
	backup := map[string]any{"size": b.Size, "sha256": b.SHA256, "entries": b.Entries, "uid": b.UID, "gid": b.GID, "mode": b.Mode, "created": b.Created, "op": b.Op}
	optNames(backup, b.Owner, b.Group)
	c := x.Current
	current := map[string]any{"state": c.State}
	if c.State == "file" {
		current["mode"], current["sha256"] = c.Mode, c.SHA256
		if c.Size != nil {
			current["size"] = *c.Size
		}
		if c.UID != nil && c.GID != nil {
			current["uid"], current["gid"] = *c.UID, *c.GID
		}
		optNames(current, c.Owner, c.Group)
	}
	rs := x.Restore
	first := rs.First
	if first == nil {
		first = []PrivRestoreEntry{}
	}
	entries := make([]any, 0, len(first))
	for _, e := range first {
		entries = append(entries, map[string]any{"path": e.Path, "type": e.Type, "recorded_mode": e.RecordedMode, "mode": e.Mode})
	}
	restore := map[string]any{"uid": rs.UID, "gid": rs.GID, "mode": rs.Mode, "recorded_mode": rs.RecordedMode, "narrowed": rs.Narrowed,
		"first": entries, "truncated": rs.Truncated}
	value := map[string]any{"id": x.ID, "kind": x.Kind, "path": x.Path, "backup": backup, "current": current, "restore": restore,
		"current_backup": map[string]any{"written": x.CurrentBackup.Written, "bytes": x.CurrentBackup.Bytes}, "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash}, nil
}

// optNames adds owner and group names to m when the helper gave them.
func optNames(m map[string]any, owner, group string) {
	if owner != "" {
		m["owner"] = owner
	}
	if group != "" {
		m["group"] = group
	}
}
