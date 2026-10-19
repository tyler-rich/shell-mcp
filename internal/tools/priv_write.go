package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged write tools (docs/TOOLS.md, privileged tier; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-2): shell_priv_write_file,
// shell_priv_make_directory, shell_priv_copy_path and shell_priv_move_path.
// The host's helper runs them as root under its privileged policy. They are
// operator-tier and privileged, so always approval-gated (D-006), and their
// previews are composed from the helper's read ops (D2): priv_stat,
// priv_read_file for a content hash, and priv_backup_check (P-11), which
// also requires the path to be one the helper may write. What the fresh
// preview saw is passed on as the operation's precondition: expected_sha256
// or expect_absent for a write, expected_destination_sha256 (P-9) or
// overwrite false for a copy or move. The helper re-checks everything
// (roots, deny list, owners, modes, sizes) at the operation.

const (
	// ownerNamePattern is a user or group name as the privileged policy's
	// owners lists hold them.
	ownerNamePattern = `^[a-z_][a-z0-9_-]{0,31}$`
	// maxPrivBackupBytes is the helper's bound on one backup (PRIVILEGED §6).
	maxPrivBackupBytes = 64 << 20
	// maxMkdirDepth bounds the ancestors a mkdir preview stats.
	maxMkdirDepth = 64
)

var ownerNameRE = regexp.MustCompile(ownerNamePattern)

func checkOwner(field, v string) *envelope.Error {
	if v != "" && !ownerNameRE.MatchString(v) {
		return invalid("%s must be a user or group name (lowercase letters, digits, _ and -, at most 32 characters)", field)
	}
	return nil
}

// ownerArgs are the optional owner and group of a new or written inode.
type ownerArgs struct {
	Owner string `json:"owner,omitzero" jsonschema:"User to own the result; it must be in the host's privileged policy's owners.users. Default: an existing file keeps its owner; a new one is root's."`
	Group string `json:"group,omitzero" jsonschema:"Group of the result; it must be in the host's privileged policy's owners.groups. Default: an existing file keeps its group; a new one is root's."`
}

func (a ownerArgs) validate() *envelope.Error {
	if e := checkOwner("owner", a.Owner); e != nil {
		return e
	}
	return checkOwner("group", a.Group)
}

func boundOwner(s *jsonschema.Schema) {
	strIn(s, "owner", ownerNamePattern, 32)
	strIn(s, "group", ownerNamePattern, 32)
}

// willSet is what the approver is shown will be set: the value requested,
// or in words what the helper does without one (N-3: a new inode without
// an owner is root's).
func willSet(requested, otherwise string) string {
	if requested != "" {
		return requested
	}
	return otherwise
}

// backupCheckWire is priv_backup_check's data (P-11).
type backupCheckWire struct {
	Written       bool  `json:"written"`
	Bytes         int64 `json:"bytes"`
	Fits          bool  `json:"fits"`
	StoreBytes    int64 `json:"store_bytes"`
	MaxStoreBytes int64 `json:"max_store_bytes"`
}

// backupPreview asks the helper whether an overwrite of p would write a
// backup and whether it fits the store's cap. A backup that would not fit
// refuses the preview (backup_failed), so no approval is requested for an
// operation the helper would refuse; the store's moving byte counts are in
// the message only, never in the preview (which must hash the same at the
// re-call).
func (d *Deps) backupPreview(ctx context.Context, target, p string, acc *policyAcc) (map[string]any, *envelope.Error) {
	c, _, pol, e := previewFetch[backupCheckWire](ctx, d, target, protocol.OpPrivBackupCheck, pathWire{Path: p}, false)
	acc.add(pol)
	if e != nil {
		return nil, e
	}
	if c.Written && !c.Fits {
		if c.Bytes > maxPrivBackupBytes {
			return nil, envelope.Errorf(protocol.CodeBackupFailed,
				"what would be replaced exceeds the helper's %d MiB backup limit; nothing was requested", maxPrivBackupBytes>>20)
		}
		return nil, envelope.Errorf(protocol.CodeBackupFailed,
			"the backup store is full (%d of %d bytes used), so this operation's backup would not fit; nothing was requested; remove old backups on the host or raise backups.max_store_bytes",
			c.StoreBytes, c.MaxStoreBytes)
	}
	return map[string]any{"written": c.Written, "bytes": c.Bytes}, nil
}

// privFilePreview is a regular file's state with its content hash: its
// stat and the helper's whole-file SHA-256 (nil when it was removed between
// the two reads). A file the helper gives no hash for (above 256 MiB)
// cannot be bound and is refused.
func (d *Deps) privFilePreview(ctx context.Context, target string, st *Entry, acc *policyAcc) (map[string]any, *FileContent, *envelope.Error) {
	return d.boundFilePreview(ctx, target, protocol.OpPrivReadFile, "helper", st, acc)
}

// boundFilePreview is a regular file's state with its content hash, read
// through op (the gate's read_file or the helper's priv_read_file; who
// names it in a refusal): its stat and the whole-file SHA-256 (nil when it
// was removed between the two reads). A file given no hash (above 256 MiB)
// cannot be bound and is refused.
func (d *Deps) boundFilePreview(ctx context.Context, target, op, who string, st *Entry, acc *policyAcc) (map[string]any, *FileContent, *envelope.Error) {
	f, warns, pol, e := previewFetch[FileContent](ctx, d, target, op, readFileWire{Path: st.Path}, true)
	acc.add(pol)
	if e != nil || f == nil {
		return nil, nil, e
	}
	if f.SHA256 == "" {
		return nil, nil, envelope.Errorf(protocol.CodeTooLarge,
			"the file is larger than the %s hashes (256 MiB), so an approval could not be bound to its content; nothing was requested", who)
	}
	cur := entryPreview(st)
	cur["state"], cur["sha256"] = "file", f.SHA256
	delete(cur, "mtime")
	cur["lines"] = nil
	if !f.Binary && !f.Truncated && f.Offset == 0 && int64(len(f.Content)) == f.Size && len(warns) == 0 {
		cur["lines"] = countLines([]byte(f.Content))
	}
	return cur, f, nil
}

// refuseNonFile refuses an existing path that a write would not replace.
func refuseNonFile(what string, st *Entry) *envelope.Error {
	switch st.Type {
	case "file":
		return nil
	case "dir":
		return envelope.Errorf(protocol.CodeIsADirectory, "the %s is a directory; nothing was requested", what)
	case "symlink":
		return envelope.Errorf(protocol.CodePathDenied, "the %s is a symlink, which is never followed or replaced; nothing was requested", what)
	}
	return envelope.Errorf(protocol.CodeBadRequest, "the %s is not a regular file; nothing was requested", what)
}

// verifiedPriv returns a success carrying out with the envelope's verified
// set, or verify_failed when the helper did not confirm its read-back.
func verifiedPriv[T any](w envelope.Envelope[privWriteResultWire], out T) envelope.Envelope[T] {
	if !w.Data.Verified {
		return verifiedFailure[T](w.Target)
	}
	env := envelope.Success(w.Target, out)
	env.Gate, env.Warnings, env.Verified = w.Gate, w.Warnings, new(true)
	return env
}

// privWriteResultWire is the helper's priv_write_file and priv_copy data.
type privWriteResultWire struct {
	writeResultWire
	UID       uint32   `json:"uid"`
	GID       uint32   `json:"gid"`
	Owner     string   `json:"owner"`
	Group     string   `json:"group"`
	BackupIDs []string `json:"backup_ids"`
}

func backupIDs(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// --- shell_priv_write_file -------------------------------------------------

type privWriteIn struct {
	targetArg
	Path    string  `json:"path" jsonschema:"Absolute, clean path of the file under a write root of the host's privileged policy."`
	Content *string `json:"content" jsonschema:"The complete new content: UTF-8 text, at most 1048576 bytes and at most the privileged policy's max_write_bytes."`
	ownerArgs
	Mode           string `json:"mode,omitzero" jsonschema:"Octal mode (3 or 4 digits, such as 0640) within the privileged policy's modes.max. Default: an existing file keeps its mode and a new one gets 0640, each masked by modes.max."`
	Create         *bool  `json:"create,omitzero" jsonschema:"Create the file when it does not exist. Default true."`
	ExpectedSHA256 string `json:"expected_sha256,omitzero" jsonschema:"Lowercase hex SHA-256 of the file's current content; the write is refused when the file has changed since."`
	// expectAbsent is set only by an approved call whose preview saw no
	// file (never an input).
	expectAbsent bool
}

func (in *privWriteIn) validate() *envelope.Error {
	if e := checkPath("path", in.Path); e != nil {
		return e
	}
	if in.Content == nil {
		return invalid("content is required (an empty string writes an empty file)")
	}
	if len(*in.Content) > maxWriteCeiling || !utf8.ValidString(*in.Content) {
		return invalid("content must be UTF-8 text of at most %d bytes", maxWriteCeiling)
	}
	if e := checkMode(in.Mode, false); e != nil {
		return e
	}
	if in.ExpectedSHA256 != "" && !sha256RE.MatchString(in.ExpectedSHA256) {
		return invalid("expected_sha256 must be 64 lowercase hex digits")
	}
	return in.ownerArgs.validate()
}

// PrivWriteFile is shell_priv_write_file's data: hashes, line counts and
// what was set, never the content. The envelope's verified is true: the
// helper re-read the file and its SHA-256 matched what was written.
type PrivWriteFile struct {
	Path           string   `json:"path" jsonschema:"The file."`
	Created        bool     `json:"created" jsonschema:"True when the file did not exist before."`
	Bytes          int      `json:"bytes" jsonschema:"Size of the new content in bytes."`
	Mode           string   `json:"mode" jsonschema:"The mode set (octal), after the privileged policy's modes.max."`
	UID            uint32   `json:"uid" jsonschema:"The owner's uid."`
	GID            uint32   `json:"gid" jsonschema:"The group's gid."`
	Owner          string   `json:"owner,omitempty" jsonschema:"The owner's name, when it is on the privileged policy's owners.users."`
	Group          string   `json:"group,omitempty" jsonschema:"The group's name, when it is on the privileged policy's owners.groups."`
	OldSHA256      string   `json:"old_sha256" jsonschema:"SHA-256 of the previous content; empty when the file was created."`
	NewSHA256      string   `json:"new_sha256" jsonschema:"SHA-256 of the new content, as read back from the file."`
	LinesOld       int      `json:"lines_old" jsonschema:"Lines in the previous content (0 when created)."`
	LinesNew       int      `json:"lines_new" jsonschema:"Lines in the new content."`
	LinesDelta     int      `json:"lines_delta" jsonschema:"lines_new minus lines_old."`
	OwnerPreserved bool     `json:"owner_preserved" jsonschema:"True when an existing file kept its owner and group."`
	BackupIDs      []string `json:"backup_ids" jsonschema:"Ids of the backups written of what was replaced (shell_priv_list_backups lists them)."`
}

type privWriteWire struct {
	Path           string `json:"path"`
	ContentB64     string `json:"content_b64"`
	Mode           string `json:"mode"`
	Owner          string `json:"owner"`
	Group          string `json:"group"`
	Create         bool   `json:"create"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ExpectAbsent   bool   `json:"expect_absent,omitzero"`
}

func privWriteFile(d *Deps) Tool {
	return define(d, spec[privWriteIn, PrivWriteFile]{
		name:        "shell_priv_write_file",
		title:       "Write file as root",
		description: "Atomically writes a text file as root within the host's privileged write roots, backing up what it replaces and verifying by read-back; returns the hashes, line counts, mode, owner and backup ids.",
		tier:        TierOperator,
		privileged:  true,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "path", pathPattern, 4096)
			c := prop(s, "content")
			c.Type, c.Types = "string", nil
			c.Pattern, c.MaxLength = anyPattern, new(maxWriteCeiling)
			strIn(s, "mode", modePattern, 4)
			strIn(s, "expected_sha256", sha256Pattern, 64)
			boundOwner(s)
			p := prop(s, "create")
			p.Type, p.Types = "boolean", nil
		},
		audit: func(in privWriteIn) map[string]any {
			m := map[string]any{"target": in.Target, "path": in.Path, "create": in.Create == nil || *in.Create}
			if in.Content != nil {
				m["content_bytes"] = len(*in.Content)
			}
			for k, v := range map[string]string{"mode": in.Mode, "owner": in.Owner, "group": in.Group} {
				if v != "" {
					m[k] = v
				}
			}
			return m
		},
		summary: func(w *PrivWriteFile) string {
			what := "written"
			if w.Created {
				what = "created"
			}
			return fmt.Sprintf("%s as root, %s, %d to %d lines, %s, verified", what, plural(w.Bytes, "byte", "bytes"), w.LinesOld, w.LinesNew,
				plural(len(w.BackupIDs), "backup", "backups"))
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privWriteIn) envelope.Envelope[PrivWriteFile] {
			w := privWriteWire{Path: in.Path, ContentB64: base64.StdEncoding.EncodeToString([]byte(*in.Content)), Mode: in.Mode,
				Owner: in.Owner, Group: in.Group, Create: in.Create == nil || *in.Create, ExpectedSHA256: in.ExpectedSHA256, ExpectAbsent: in.expectAbsent}
			r := fetch[privWriteResultWire](ctx, d, in.Target, protocol.OpPrivWriteFile, w, d.budget())
			if !r.OK {
				return envelope.Failure[PrivWriteFile](r.Target, r.Error)
			}
			x := r.Data
			return verifiedPriv(r, PrivWriteFile{Path: x.Path, Created: x.Created, Bytes: x.Bytes, Mode: x.Mode, UID: x.UID, GID: x.GID,
				Owner: x.Owner, Group: x.Group, OldSHA256: x.OldSHA256, NewSHA256: x.SHA256, LinesOld: x.LinesOld, LinesNew: x.LinesNew,
				LinesDelta: x.LinesNew - x.LinesOld, OwnerPreserved: x.OwnerPreserved, BackupIDs: backupIDs(x.BackupIDs)})
		},
		approvalArgs: func(in privWriteIn) any {
			return struct {
				Path           string `json:"path"`
				Content        string `json:"content"`
				Owner          string `json:"owner"`
				Group          string `json:"group"`
				Mode           string `json:"mode"`
				Create         bool   `json:"create"`
				ExpectedSHA256 string `json:"expected_sha256"`
			}{in.Path, *in.Content, in.Owner, in.Group, in.Mode, in.Create == nil || *in.Create, in.ExpectedSHA256}
		},
		describe: func(in privWriteIn, target string) string {
			return "As root, write " + describeBytes(len(*in.Content)) + " to " + plain(in.Path, "a file whose path is shown in the arguments") + " on " + target
		},
		preview: func(ctx context.Context, in privWriteIn, target string) (*preview, *envelope.Error) {
			return d.privWritePreview(ctx, &in, target)
		},
		precondition: func(in *privWriteIn, p *preview) {
			// As shell_write_file: expected_sha256 of the content the fresh
			// preview saw, or expect_absent when it saw no file; a caller's
			// own expected_sha256 is kept (it is bound).
			if in.ExpectedSHA256 == "" {
				in.ExpectedSHA256 = p.contentSHA256
				in.expectAbsent = p.absent
			}
		},
	})
}

// privWritePreview: the file's current state (absent; or its size, mode,
// owner, content SHA-256 and lines), the new content's size, SHA-256 and
// lines, what will be set, and the backup that will be written.
func (d *Deps) privWritePreview(ctx context.Context, in *privWriteIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	content := []byte(*in.Content)
	newLines := countLines(content)
	value := map[string]any{"path": in.Path, "new": map[string]any{"bytes": len(content), "sha256": sha256Hex(content), "lines": newLines}}
	st, e := d.statPreviewOp(ctx, target, protocol.OpPrivStat, in.Path, &acc)
	if e != nil {
		return nil, e
	}
	if st != nil {
		if re := refuseNonFile("path", st); re != nil {
			return nil, re
		}
	}
	var cur map[string]any
	var f *FileContent
	if st != nil {
		if cur, f, e = d.privFilePreview(ctx, target, st, &acc); e != nil {
			return nil, e
		}
	}
	backup, e := d.backupPreview(ctx, target, in.Path, &acc)
	if e != nil {
		return nil, e
	}
	value["backup"] = backup
	if cur == nil {
		value["current"] = map[string]any{"state": "absent"}
		value["lines_delta"] = newLines
		value["set"] = map[string]any{
			"owner": willSet(in.Owner, "root (a new file without an owner is root's)"),
			"group": willSet(in.Group, "root (a new file without a group is root's)"),
			"mode":  willSet(in.Mode, "0640, masked by the host's modes.max"),
		}
		return acc.absentResult(value)
	}
	value["current"] = cur
	value["lines_delta"] = nil
	if n, ok := cur["lines"].(int); ok {
		value["lines_delta"] = newLines - n
	}
	value["set"] = map[string]any{
		"owner": willSet(in.Owner, "kept: the file's current owner"),
		"group": willSet(in.Group, "kept: the file's current group"),
		"mode":  willSet(in.Mode, "kept: the file's current mode, masked by the host's modes.max"),
	}
	return acc.result(value, f.SHA256)
}

// --- shell_priv_make_directory ----------------------------------------------

type privMkdirIn struct {
	targetArg
	Path string `json:"path" jsonschema:"Absolute, clean path of the new directory under a write root of the host's privileged policy."`
	ownerArgs
	Mode    string `json:"mode,omitzero" jsonschema:"Octal mode (3 or 4 digits, such as 0750) within the privileged policy's modes.max. Default 0750 masked by modes.max."`
	Parents bool   `json:"parents,omitzero" jsonschema:"Also create missing parent directories inside the write root, each with the same owner and mode. Default false."`
}

func (in *privMkdirIn) validate() *envelope.Error {
	if e := checkPath("path", in.Path); e != nil {
		return e
	}
	if e := checkMode(in.Mode, false); e != nil {
		return e
	}
	return in.ownerArgs.validate()
}

// PrivMakeDirectory is shell_priv_make_directory's data.
type PrivMakeDirectory struct {
	Path    string `json:"path" jsonschema:"The directory."`
	Created bool   `json:"created" jsonschema:"True when the directory was created."`
	Mode    string `json:"mode" jsonschema:"The mode set (octal), after the privileged policy's modes.max."`
	UID     uint32 `json:"uid" jsonschema:"The owner's uid."`
	GID     uint32 `json:"gid" jsonschema:"The group's gid."`
	Owner   string `json:"owner,omitempty" jsonschema:"The owner's name, when it is on the privileged policy's owners.users."`
	Group   string `json:"group,omitempty" jsonschema:"The group's name, when it is on the privileged policy's owners.groups."`
}

type privMkdirWire struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Parents bool   `json:"parents"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
}

func privMakeDirectory(d *Deps) Tool {
	return define(d, spec[privMkdirIn, PrivMakeDirectory]{
		name:        "shell_priv_make_directory",
		title:       "Make directory as root",
		description: "Creates a directory as root, and optionally its missing parents, within the host's privileged write roots; returns its mode and owner.",
		tier:        TierOperator,
		privileged:  true,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "path", pathPattern, 4096)
			strIn(s, "mode", modePattern, 4)
			boundOwner(s)
		},
		audit: func(in privMkdirIn) map[string]any {
			m := map[string]any{"target": in.Target, "path": in.Path, "parents": in.Parents}
			for k, v := range map[string]string{"mode": in.Mode, "owner": in.Owner, "group": in.Group} {
				if v != "" {
					m[k] = v
				}
			}
			return m
		},
		summary: func(m *PrivMakeDirectory) string {
			if !m.Created {
				return "directory already there"
			}
			return "directory created as root"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privMkdirIn) envelope.Envelope[PrivMakeDirectory] {
			w := privMkdirWire{Path: in.Path, Mode: in.Mode, Parents: in.Parents, Owner: in.Owner, Group: in.Group}
			return fetch[PrivMakeDirectory](ctx, d, in.Target, protocol.OpPrivMkdir, w, d.budget())
		},
		approvalArgs: func(in privMkdirIn) any {
			return struct {
				Path    string `json:"path"`
				Owner   string `json:"owner"`
				Group   string `json:"group"`
				Mode    string `json:"mode"`
				Parents bool   `json:"parents"`
			}{in.Path, in.Owner, in.Group, in.Mode, in.Parents}
		},
		describe: func(in privMkdirIn, target string) string {
			what := "As root, create directory " + plain(in.Path, "a directory whose path is shown in the arguments")
			if in.Parents {
				what += " and its missing parents"
			}
			return what + " on " + target
		},
		preview: func(ctx context.Context, in privMkdirIn, target string) (*preview, *envelope.Error) {
			return d.privMkdirPreview(ctx, &in, target)
		},
	})
}

// privMkdirPreview: the path's state, every directory that will be created
// (with parents, each missing ancestor up to the first that exists), and
// the owner and mode they will be given.
func (d *Deps) privMkdirPreview(ctx context.Context, in *privMkdirIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	st, e := d.statPreviewOp(ctx, target, protocol.OpPrivStat, in.Path, &acc)
	if e != nil {
		return nil, e
	}
	create := []string{}
	switch {
	case st != nil && st.Type != "dir":
		return nil, envelope.Errorf(protocol.CodeNotADirectory, "the path exists and is not a directory; nothing was requested")
	case st != nil && !in.Parents:
		return nil, envelope.Errorf(protocol.CodeExists, "the directory already exists; nothing was requested")
	case st == nil:
		create = append(create, in.Path)
		for p := path.Dir(in.Path); ; p = path.Dir(p) {
			if len(create) > maxMkdirDepth {
				return nil, envelope.Errorf(protocol.CodeTooLarge, "more than %d directories would be created; nothing was requested", maxMkdirDepth)
			}
			a, e := d.statPreviewOp(ctx, target, protocol.OpPrivStat, p, &acc)
			if e != nil {
				return nil, e
			}
			if a != nil {
				if a.Type != "dir" {
					return nil, envelope.Errorf(protocol.CodeNotADirectory, "a parent exists and is not a directory; nothing was requested")
				}
				break
			}
			if !in.Parents {
				return nil, envelope.Errorf(protocol.CodeNotFound, "the parent directory does not exist (pass parents to create it); nothing was requested")
			}
			if p == "/" {
				break
			}
			create = append([]string{p}, create...)
		}
	}
	// The helper's write-root check (nothing is backed up), at the topmost
	// directory to be created: the helper resolves a path only when its
	// parent exists.
	check := in.Path
	if len(create) > 0 {
		check = create[0]
	}
	if _, e := d.backupPreview(ctx, target, check, &acc); e != nil {
		return nil, e
	}
	return acc.result(map[string]any{
		"path":   entryPreview(st),
		"create": create,
		"set": map[string]any{
			"owner": willSet(in.Owner, "root (a new directory without an owner is root's)"),
			"group": willSet(in.Group, "root (a new directory without a group is root's)"),
			"mode":  willSet(in.Mode, "0750, masked by the host's modes.max"),
		},
	}, "")
}

// --- shell_priv_copy_path and shell_priv_move_path --------------------------

type privSrcDstIn struct {
	targetArg
	Source      string `json:"source" jsonschema:"Absolute, clean path of the source within the host's privileged read or write roots (a move: write roots)."`
	Destination string `json:"destination" jsonschema:"Absolute, clean path of the destination under a write root of the host's privileged policy."`
	Overwrite   bool   `json:"overwrite,omitzero" jsonschema:"Replace an existing destination file (backed up first). Default false."`
	// expectedDest and createOnly are set only by an approved call from what
	// its fresh preview saw (never inputs): the destination's content hash,
	// or that there was none, so the operation is sent without overwrite.
	expectedDest string
	createOnly   bool
}

func (in *privSrcDstIn) validate() *envelope.Error {
	if e := checkPath("source", in.Source); e != nil {
		return e
	}
	return checkPath("destination", in.Destination)
}

func (in *privSrcDstIn) wire() srcDstWire {
	return newSrcDstWire(in.Source, in.Destination, in.Overwrite, in.expectedDest, in.createOnly)
}

func privSrcDstSpec(verb string) (canon func(privSrcDstIn) any, describe func(privSrcDstIn, string) string, audit func(privSrcDstIn) map[string]any) {
	canon = func(in privSrcDstIn) any {
		return struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
			Overwrite   bool   `json:"overwrite"`
		}{in.Source, in.Destination, in.Overwrite}
	}
	describe = func(in privSrcDstIn, target string) string {
		what := "As root, " + verb + " " + plain(in.Source, "a path shown in the arguments") + " to " + plain(in.Destination, "a destination shown in the arguments")
		if in.Overwrite {
			return what + ", replacing an existing destination, on " + target
		}
		return what + " on " + target
	}
	audit = func(in privSrcDstIn) map[string]any {
		return map[string]any{"target": in.Target, "source": in.Source, "destination": in.Destination, "overwrite": in.Overwrite}
	}
	return canon, describe, audit
}

// precondition passes on what the fresh preview saw of the destination
// (P-9, destPrecondition).
func (in *privSrcDstIn) precondition(p *preview) {
	in.expectedDest, in.createOnly = destPrecondition(in.Overwrite, p)
}

// privSrcDstPreview: the source's stat, the destination's state (absent, or
// a regular file with its content hash), overwrite, what a copy will be set
// to, and the backup. A destination that would not be replaced (a
// directory, a symlink, or any file without overwrite) refuses the
// preview.
func (d *Deps) privSrcDstPreview(ctx context.Context, in *privSrcDstIn, target string, isCopy bool) (*preview, *envelope.Error) {
	var acc policyAcc
	src, _, pol, e := previewFetch[Entry](ctx, d, target, protocol.OpPrivStat, pathWire{Path: in.Source}, false)
	acc.add(pol)
	if e != nil {
		return nil, e
	}
	switch {
	case src.Type == "symlink":
		return nil, envelope.Errorf(protocol.CodePathDenied, "the source is a symlink, which is never followed; nothing was requested")
	case isCopy && src.Type == "dir":
		return nil, envelope.Errorf(protocol.CodeIsADirectory, "a copy handles regular files only; nothing was requested")
	case isCopy && src.Type != "file", !isCopy && src.Type != "file" && src.Type != "dir":
		return nil, envelope.Errorf(protocol.CodeBadRequest, "the source is not a regular file or directory; nothing was requested")
	}
	dst, e := d.statPreviewOp(ctx, target, protocol.OpPrivStat, in.Destination, &acc)
	if e != nil {
		return nil, e
	}
	var cur map[string]any
	var f *FileContent
	if dst != nil {
		if re := refuseDestination(dst, src.Type, isCopy, in.Overwrite); re != nil {
			return nil, re
		}
		if cur, f, e = d.privFilePreview(ctx, target, dst, &acc); e != nil {
			return nil, e
		}
		delete(cur, "lines")
	}
	backup, e := d.backupPreview(ctx, target, in.Destination, &acc)
	if e != nil {
		return nil, e
	}
	value := map[string]any{"source": entryPreview(src), "overwrite": in.Overwrite, "backup": backup}
	if isCopy {
		if cur == nil {
			value["set"] = map[string]any{"owner": "root (a new copy is root's)", "group": "root (a new copy is root's)",
				"mode": "the source's mode, without setuid, setgid, sticky and world-write, masked by the host's modes.max"}
		} else {
			value["set"] = map[string]any{"owner": "kept: the destination's current owner", "group": "kept: the destination's current group",
				"mode": "the destination's current mode, masked by the host's modes.max"}
		}
	}
	if cur == nil {
		value["destination"] = map[string]any{"state": "absent"}
		return acc.absentResult(value)
	}
	value["destination"] = cur
	return acc.result(value, f.SHA256)
}

// PrivCopyPath is shell_priv_copy_path's data. The envelope's verified is
// true: the helper re-read the copy and its SHA-256 matched.
type PrivCopyPath struct {
	Source      string   `json:"source" jsonschema:"The source file."`
	Destination string   `json:"destination" jsonschema:"The new file."`
	Created     bool     `json:"created" jsonschema:"True when the destination did not exist before."`
	Bytes       int      `json:"bytes" jsonschema:"Size of the copy in bytes."`
	Mode        string   `json:"mode" jsonschema:"The copy's mode (octal), after the privileged policy's modes.max."`
	UID         uint32   `json:"uid" jsonschema:"The copy's owner uid."`
	GID         uint32   `json:"gid" jsonschema:"The copy's group gid."`
	Owner       string   `json:"owner,omitempty" jsonschema:"The owner's name, when it is on the privileged policy's owners.users."`
	Group       string   `json:"group,omitempty" jsonschema:"The group's name, when it is on the privileged policy's owners.groups."`
	SHA256      string   `json:"sha256" jsonschema:"SHA-256 of the copy, as read back."`
	OldSHA256   string   `json:"old_sha256" jsonschema:"SHA-256 of the replaced destination; empty when it was created."`
	BackupIDs   []string `json:"backup_ids" jsonschema:"Ids of the backups written of what was replaced."`
}

func privCopyPath(d *Deps) Tool {
	canon, describe, audit := privSrcDstSpec("copy")
	return define(d, spec[privSrcDstIn, PrivCopyPath]{
		name:        "shell_priv_copy_path",
		title:       "Copy file as root",
		description: "Copies a regular file as root to a destination within the host's privileged write roots, backing up a replaced destination and verifying by read-back; returns the hashes, mode, owner and backup ids.",
		tier:        TierOperator,
		privileged:  true,
		idempotent:  true,
		schema:      boundSrcDst,
		audit:       audit,
		summary: func(c *PrivCopyPath) string {
			return "copied as root, " + plural(c.Bytes, "byte", "bytes") + ", " + plural(len(c.BackupIDs), "backup", "backups") + ", verified"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privSrcDstIn) envelope.Envelope[PrivCopyPath] {
			r := fetch[privWriteResultWire](ctx, d, in.Target, protocol.OpPrivCopy, in.wire(), d.budget())
			if !r.OK {
				return envelope.Failure[PrivCopyPath](r.Target, r.Error)
			}
			x := r.Data
			return verifiedPriv(r, PrivCopyPath{Source: in.Source, Destination: x.Path, Created: x.Created, Bytes: x.Bytes, Mode: x.Mode,
				UID: x.UID, GID: x.GID, Owner: x.Owner, Group: x.Group, SHA256: x.SHA256, OldSHA256: x.OldSHA256, BackupIDs: backupIDs(x.BackupIDs)})
		},
		approvalArgs: canon,
		describe:     describe,
		preview: func(ctx context.Context, in privSrcDstIn, target string) (*preview, *envelope.Error) {
			return d.privSrcDstPreview(ctx, &in, target, true)
		},
		precondition: func(in *privSrcDstIn, p *preview) { in.precondition(p) },
	})
}

// PrivMovePath is shell_priv_move_path's data.
type PrivMovePath struct {
	Source      string   `json:"source" jsonschema:"The old path."`
	Destination string   `json:"destination" jsonschema:"The new path."`
	Type        string   `json:"type" jsonschema:"What was moved: file or dir."`
	Replaced    bool     `json:"replaced" jsonschema:"True when an existing destination file was replaced."`
	BackupIDs   []string `json:"backup_ids" jsonschema:"Ids of the backups written of what was replaced."`
}

type privMoveWire struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Replaced    bool     `json:"replaced"`
	BackupIDs   []string `json:"backup_ids"`
}

func privMovePath(d *Deps) Tool {
	canon, describe, audit := privSrcDstSpec("move")
	return define(d, spec[privSrcDstIn, PrivMovePath]{
		name:        "shell_priv_move_path",
		title:       "Move path as root",
		description: "Renames a file or directory as root within one of the host's privileged write roots (same filesystem only), backing up a replaced destination file; returns what was moved and the backup ids.",
		tier:        TierOperator,
		privileged:  true,
		idempotent:  false,
		schema:      boundSrcDst,
		audit:       audit,
		summary: func(m *PrivMovePath) string {
			if m.Replaced {
				return "moved as root, destination replaced, " + plural(len(m.BackupIDs), "backup", "backups")
			}
			return "moved as root"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privSrcDstIn) envelope.Envelope[PrivMovePath] {
			r := fetch[privMoveWire](ctx, d, in.Target, protocol.OpPrivMove, in.wire(), d.budget())
			if !r.OK {
				return envelope.Failure[PrivMovePath](r.Target, r.Error)
			}
			x := r.Data
			env := envelope.Success(r.Target, PrivMovePath{Source: x.Source, Destination: x.Destination, Type: x.Type, Replaced: x.Replaced, BackupIDs: backupIDs(x.BackupIDs)})
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: canon,
		describe:     describe,
		preview: func(ctx context.Context, in privSrcDstIn, target string) (*preview, *envelope.Error) {
			return d.privSrcDstPreview(ctx, &in, target, false)
		},
		precondition: func(in *privSrcDstIn, p *preview) { in.precondition(p) },
	})
}
