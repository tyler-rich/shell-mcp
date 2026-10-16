package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Operator tools (docs/TOOLS.md, operator tier): service control, file
// writes, git pull and policy commands of tier read or operator. Each one
// validates its input, sends one gate request at ceiling operator and
// shapes the result. The gate re-validates everything against its policy:
// write roots, the deny list, the protected set (.git included), modes,
// units and verbs, repositories and remotes, command tiers and templates.
// Results never carry the content written or the stdin sent.

const (
	// maxWriteCeiling is the highest policy max_write_bytes (1 MiB).
	maxWriteCeiling = 1 << 20
	// maxStdinCeiling is the highest policy max_stdin_bytes (1 MiB).
	maxStdinCeiling = 1 << 20
)

const (
	modePattern   = `^[0-7]{3,4}$`
	sha256Pattern = `^[0-9a-f]{64}$`
	// anyPattern is informational: content and stdin are any UTF-8 text.
	anyPattern = `^[\s\S]*$`
)

var (
	modeRE   = regexp.MustCompile(modePattern)
	sha256RE = regexp.MustCompile(sha256Pattern)
)

// checkMode: an octal mode string of 3 or 4 digits. Which bits are
// allowed (no setuid, setgid, sticky or world-write) is the gate's rule.
func checkMode(m string, required bool) *envelope.Error {
	if m == "" && !required {
		return nil
	}
	if !modeRE.MatchString(m) {
		return invalid("mode must be 3 or 4 octal digits, such as 0640")
	}
	return nil
}

// verifiedFailure is the result of a write the gate answered without a
// successful read-back: a failure, never a success with a warning.
func verifiedFailure[T any](target string) envelope.Envelope[T] {
	return envelope.Failure[T](target, envelope.Errorf(protocol.CodeVerifyFailed,
		"the gate did not confirm the read-back of what it wrote; treat the file's content as unknown and read it back"))
}

// --- shell_control_service ----------------------------------------------------

type controlIn struct {
	targetArg
	Unit   string `json:"unit" jsonschema:"Exact unit name with its type suffix, such as example-app.service (no globs). It must be listed in the target policy's services.control.units."`
	Action string `json:"action" jsonschema:"start, stop, restart or reload; it must be listed in the target policy's services.control.verbs."`
	timeoutArg
}

var controlActions = []string{"start", "stop", "restart", "reload"}

func (in *controlIn) validate() *envelope.Error {
	if e := checkUnit(in.Unit); e != nil {
		return e
	}
	if !slices.Contains(controlActions, in.Action) {
		return invalid("action must be start, stop, restart or reload")
	}
	return nil
}

// ServiceControl is shell_control_service's data.
type ServiceControl struct {
	Unit   string        `json:"unit" jsonschema:"The unit."`
	Action string        `json:"action" jsonschema:"The action performed."`
	Status ServiceStatus `json:"status" jsonschema:"The unit's status, re-read after the action (empty fields and a warning when it could not be re-read)."`
}

type controlWire struct {
	Unit   string `json:"unit"`
	Action string `json:"action"`
}

func controlService(d *Deps) Tool {
	return define(d, spec[controlIn, ServiceControl]{
		name:        "shell_control_service",
		title:       "Control service",
		description: "Starts, stops, restarts or reloads a systemd unit the target policy allows, and returns the unit's status re-read after the action.",
		tier:        TierOperator,
		idempotent:  false,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "unit", unitPattern, 256)
			enumIn(s, "action", controlActions...)
		},
		audit: func(in controlIn) map[string]any {
			return map[string]any{"target": in.Target, "unit": in.Unit, "action": in.Action}
		},
		summary: func(c *ServiceControl) string {
			if c.Status.ActiveState == "" {
				return "action done, status not re-read"
			}
			return "action done, status re-read"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in controlIn) envelope.Envelope[ServiceControl] {
			budget, e := d.timeoutFor(in.timeoutArg)
			if e != nil {
				return envelope.Failure[ServiceControl](in.Target, e)
			}
			return fetch[ServiceControl](ctx, d, in.Target, protocol.OpServiceControl, controlWire{Unit: in.Unit, Action: in.Action}, budget)
		},
	})
}

// --- shell_write_file ----------------------------------------------------------

type writeIn struct {
	targetArg
	Path           string  `json:"path" jsonschema:"Absolute, clean path of the file under a write root of the target policy."`
	Content        *string `json:"content" jsonschema:"The complete new content: UTF-8 text, at most 1048576 bytes and at most the target policy's max_write_bytes."`
	Mode           string  `json:"mode,omitzero" jsonschema:"Octal mode for a new file (3 or 4 digits, such as 0640). Default: an existing file keeps its mode; a new one gets 0640. Setuid, setgid, sticky and world-writable modes are refused."`
	Create         *bool   `json:"create,omitzero" jsonschema:"Create the file when it does not exist. Default true."`
	ExpectedSHA256 string  `json:"expected_sha256,omitzero" jsonschema:"Lowercase hex SHA-256 of the file's current content; the write is refused when the file has changed since (optimistic concurrency)."`
}

func (in *writeIn) validate() *envelope.Error {
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
	return nil
}

// WriteFile is shell_write_file's data: hashes and line counts, never the
// content. The envelope's verified is true: the gate re-read the file and
// its SHA-256 matched what was written.
type WriteFile struct {
	Path           string `json:"path" jsonschema:"The file."`
	Created        bool   `json:"created" jsonschema:"True when the file did not exist before."`
	Bytes          int    `json:"bytes" jsonschema:"Size of the new content in bytes."`
	Mode           string `json:"mode" jsonschema:"The file's mode after the write (octal)."`
	OldSHA256      string `json:"old_sha256" jsonschema:"SHA-256 of the previous content; empty when the file was created."`
	NewSHA256      string `json:"new_sha256" jsonschema:"SHA-256 of the new content, as read back from the file."`
	LinesOld       int    `json:"lines_old" jsonschema:"Lines in the previous content (0 when created)."`
	LinesNew       int    `json:"lines_new" jsonschema:"Lines in the new content."`
	LinesDelta     int    `json:"lines_delta" jsonschema:"lines_new minus lines_old."`
	OwnerPreserved bool   `json:"owner_preserved" jsonschema:"True when an existing file kept its owner and group."`
}

type writeWire struct {
	Path           string `json:"path"`
	ContentB64     string `json:"content_b64"`
	Mode           string `json:"mode"`
	Create         bool   `json:"create"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// writeResultWire is the gate's write_file and copy data (fsx.WriteResult).
type writeResultWire struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	OldSHA256      string `json:"old_sha256"`
	Bytes          int    `json:"bytes"`
	Created        bool   `json:"created"`
	Mode           string `json:"mode"`
	LinesOld       int    `json:"lines_old"`
	LinesNew       int    `json:"lines_new"`
	OwnerPreserved bool   `json:"owner_preserved"`
	Verified       bool   `json:"verified"`
}

// verified returns a success carrying out, with the envelope's verified
// set, or verify_failed when the gate did not confirm the read-back.
func verified[T any](w envelope.Envelope[writeResultWire], out T) envelope.Envelope[T] {
	if !w.Data.Verified {
		return verifiedFailure[T](w.Target)
	}
	env := envelope.Success(w.Target, out)
	env.Gate, env.Warnings, env.Verified = w.Gate, w.Warnings, new(true)
	return env
}

func writeFile(d *Deps) Tool {
	return define(d, spec[writeIn, WriteFile]{
		name:        "shell_write_file",
		title:       "Write file",
		description: "Atomically replaces or creates a text file under the target policy's write roots and verifies it by reading it back, returning the old and new SHA-256 and line counts.",
		tier:        TierOperator,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "path", pathPattern, 4096)
			c := prop(s, "content")
			c.Type, c.Types = "string", nil
			c.Pattern, c.MaxLength = anyPattern, new(maxWriteCeiling)
			strIn(s, "mode", modePattern, 4)
			strIn(s, "expected_sha256", sha256Pattern, 64)
			p := prop(s, "create")
			p.Type, p.Types = "boolean", nil
		},
		audit: func(in writeIn) map[string]any {
			m := map[string]any{"target": in.Target, "path": in.Path, "create": in.Create == nil || *in.Create}
			if in.Content != nil {
				m["content_bytes"] = len(*in.Content)
			}
			if in.Mode != "" {
				m["mode"] = in.Mode
			}
			return m
		},
		summary: func(w *WriteFile) string {
			what := "written"
			if w.Created {
				what = "created"
			}
			return fmt.Sprintf("%s, %s, %d to %d lines, verified", what, plural(w.Bytes, "byte", "bytes"), w.LinesOld, w.LinesNew)
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in writeIn) envelope.Envelope[WriteFile] {
			w := writeWire{Path: in.Path, ContentB64: base64.StdEncoding.EncodeToString([]byte(*in.Content)), Mode: in.Mode,
				Create: in.Create == nil || *in.Create, ExpectedSHA256: in.ExpectedSHA256}
			r := fetch[writeResultWire](ctx, d, in.Target, protocol.OpWriteFile, w, d.budget())
			if !r.OK {
				return envelope.Failure[WriteFile](r.Target, r.Error)
			}
			x := r.Data
			return verified(r, WriteFile{Path: x.Path, Created: x.Created, Bytes: x.Bytes, Mode: x.Mode, OldSHA256: x.OldSHA256,
				NewSHA256: x.SHA256, LinesOld: x.LinesOld, LinesNew: x.LinesNew, LinesDelta: x.LinesNew - x.LinesOld, OwnerPreserved: x.OwnerPreserved})
		},
	})
}

// --- shell_make_directory -----------------------------------------------------

type mkdirIn struct {
	targetArg
	Path    string `json:"path" jsonschema:"Absolute, clean path of the new directory under a write root of the target policy."`
	Mode    string `json:"mode,omitzero" jsonschema:"Octal mode (3 or 4 digits, such as 0750). Default 0750. Setuid, setgid, sticky and world-writable modes are refused."`
	Parents bool   `json:"parents,omitzero" jsonschema:"Also create missing parent directories inside the write root. Default false."`
}

func (in *mkdirIn) validate() *envelope.Error {
	if e := checkPath("path", in.Path); e != nil {
		return e
	}
	return checkMode(in.Mode, false)
}

// MakeDirectory is shell_make_directory's data.
type MakeDirectory struct {
	Path    string `json:"path" jsonschema:"The directory."`
	Created bool   `json:"created" jsonschema:"True when the directory was created."`
	Mode    string `json:"mode" jsonschema:"The mode requested for it (octal)."`
}

type mkdirWire struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Parents bool   `json:"parents"`
}

func makeDirectory(d *Deps) Tool {
	return define(d, spec[mkdirIn, MakeDirectory]{
		name:        "shell_make_directory",
		title:       "Make directory",
		description: "Creates a directory, and optionally its missing parents, under the target policy's write roots.",
		tier:        TierOperator,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "path", pathPattern, 4096)
			strIn(s, "mode", modePattern, 4)
		},
		audit: func(in mkdirIn) map[string]any {
			m := map[string]any{"target": in.Target, "path": in.Path, "parents": in.Parents}
			if in.Mode != "" {
				m["mode"] = in.Mode
			}
			return m
		},
		summary: func(*MakeDirectory) string { return "directory created" },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in mkdirIn) envelope.Envelope[MakeDirectory] {
			return fetch[MakeDirectory](ctx, d, in.Target, protocol.OpMkdir, mkdirWire{Path: in.Path, Mode: in.Mode, Parents: in.Parents}, d.budget())
		},
	})
}

// --- shell_copy_path and shell_move_path ------------------------------------

type srcDstIn struct {
	targetArg
	Source      string `json:"source" jsonschema:"Absolute, clean path of the source."`
	Destination string `json:"destination" jsonschema:"Absolute, clean path of the destination under a write root of the target policy."`
	Overwrite   bool   `json:"overwrite,omitzero" jsonschema:"Replace an existing destination file. Default false."`
}

func (in *srcDstIn) validate() *envelope.Error {
	if e := checkPath("source", in.Source); e != nil {
		return e
	}
	return checkPath("destination", in.Destination)
}

func boundSrcDst(s *jsonschema.Schema) {
	boundCommon(s)
	strIn(s, "source", pathPattern, 4096)
	strIn(s, "destination", pathPattern, 4096)
}

func srcDstAudit(in srcDstIn) map[string]any {
	return map[string]any{"target": in.Target, "source": in.Source, "destination": in.Destination, "overwrite": in.Overwrite}
}

type srcDstWire struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Overwrite   bool   `json:"overwrite"`
}

// CopyPath is shell_copy_path's data. The envelope's verified is true: the
// gate re-read the copy and its SHA-256 matched.
type CopyPath struct {
	Source      string `json:"source" jsonschema:"The source file."`
	Destination string `json:"destination" jsonschema:"The new file."`
	Created     bool   `json:"created" jsonschema:"True when the destination did not exist before."`
	Bytes       int    `json:"bytes" jsonschema:"Size of the copy in bytes."`
	Mode        string `json:"mode" jsonschema:"The copy's mode (octal)."`
	SHA256      string `json:"sha256" jsonschema:"SHA-256 of the copy, as read back."`
	OldSHA256   string `json:"old_sha256" jsonschema:"SHA-256 of the replaced destination; empty when it was created."`
}

func copyPath(d *Deps) Tool {
	return define(d, spec[srcDstIn, CopyPath]{
		name:        "shell_copy_path",
		title:       "Copy file",
		description: "Copies a regular file to a destination under the target policy's write roots, verified by reading the copy back.",
		tier:        TierOperator,
		idempotent:  true,
		schema:      boundSrcDst,
		audit:       srcDstAudit,
		summary: func(c *CopyPath) string {
			return "copied, " + plural(c.Bytes, "byte", "bytes") + ", verified"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in srcDstIn) envelope.Envelope[CopyPath] {
			w := srcDstWire{Source: in.Source, Destination: in.Destination, Overwrite: in.Overwrite}
			r := fetch[writeResultWire](ctx, d, in.Target, protocol.OpCopy, w, d.budget())
			if !r.OK {
				return envelope.Failure[CopyPath](r.Target, r.Error)
			}
			x := r.Data
			return verified(r, CopyPath{Source: in.Source, Destination: x.Path, Created: x.Created, Bytes: x.Bytes, Mode: x.Mode,
				SHA256: x.SHA256, OldSHA256: x.OldSHA256})
		},
	})
}

// MovePath is shell_move_path's data.
type MovePath struct {
	Source      string `json:"source" jsonschema:"The old path."`
	Destination string `json:"destination" jsonschema:"The new path."`
	Type        string `json:"type" jsonschema:"What was moved: file, dir or symlink."`
	Replaced    bool   `json:"replaced" jsonschema:"True when an existing destination was replaced."`
}

func movePath(d *Deps) Tool {
	return define(d, spec[srcDstIn, MovePath]{
		name:        "shell_move_path",
		title:       "Move path",
		description: "Renames a file or directory within one write root of the target policy (same filesystem only).",
		tier:        TierOperator,
		idempotent:  false,
		schema:      boundSrcDst,
		audit:       srcDstAudit,
		summary: func(m *MovePath) string {
			if m.Replaced {
				return "moved, destination replaced"
			}
			return "moved"
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in srcDstIn) envelope.Envelope[MovePath] {
			w := srcDstWire{Source: in.Source, Destination: in.Destination, Overwrite: in.Overwrite}
			return fetch[MovePath](ctx, d, in.Target, protocol.OpMove, w, d.budget())
		},
	})
}

// --- shell_set_permissions ------------------------------------------------------

type chmodIn struct {
	targetArg
	Path string `json:"path" jsonschema:"Absolute, clean path under a write root of the target policy."`
	Mode string `json:"mode" jsonschema:"Octal mode (3 or 4 digits, such as 0640). Setuid, setgid, sticky and world-writable modes are refused."`
}

func (in *chmodIn) validate() *envelope.Error {
	if e := checkPath("path", in.Path); e != nil {
		return e
	}
	return checkMode(in.Mode, true)
}

// SetPermissions is shell_set_permissions' data.
type SetPermissions struct {
	Path    string `json:"path" jsonschema:"The path."`
	OldMode string `json:"old_mode" jsonschema:"The mode before (octal)."`
	Mode    string `json:"mode" jsonschema:"The mode now (octal)."`
}

type chmodWire struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

func setPermissions(d *Deps) Tool {
	return define(d, spec[chmodIn, SetPermissions]{
		name:        "shell_set_permissions",
		title:       "Set permissions",
		description: "Sets the permission bits of a file or directory under the target policy's write roots, and returns the old and new mode.",
		tier:        TierOperator,
		idempotent:  true,
		schema: func(s *jsonschema.Schema) {
			boundCommon(s)
			strIn(s, "path", pathPattern, 4096)
			strIn(s, "mode", modePattern, 4)
		},
		audit: func(in chmodIn) map[string]any {
			return map[string]any{"target": in.Target, "path": in.Path, "mode": in.Mode}
		},
		summary: func(*SetPermissions) string { return "mode set" },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in chmodIn) envelope.Envelope[SetPermissions] {
			return fetch[SetPermissions](ctx, d, in.Target, protocol.OpChmod, chmodWire{Path: in.Path, Mode: in.Mode}, d.budget())
		},
	})
}

// --- shell_git_pull ---------------------------------------------------------------

// GitPull is shell_git_pull's data.
type GitPull struct {
	Repo         string `json:"repo" jsonschema:"The repository."`
	OldHead      string `json:"old_head" jsonschema:"HEAD before the pull (empty for an unborn branch)."`
	NewHead      string `json:"new_head" jsonschema:"HEAD after the pull."`
	ChangedFiles int    `json:"changed_files" jsonschema:"Files that differ between the old and the new HEAD."`
	Updated      bool   `json:"updated" jsonschema:"True when HEAD moved."`
}

func gitPull(d *Deps) Tool {
	return define(d, spec[repoIn, GitPull]{
		name:        "shell_git_pull",
		title:       "Pull git repository",
		description: "Fast-forwards a repository listed in the target policy from its pinned remote, refusing uncommitted changes to tracked files and diverged history, and returns the old and new HEAD.",
		tier:        TierOperator,
		idempotent:  false,
		schema:      boundRepo,
		audit:       func(in repoIn) map[string]any { return map[string]any{"target": in.Target, "repo": in.Repo} },
		summary: func(g *GitPull) string {
			if !g.Updated {
				return "already up to date"
			}
			return "updated, " + plural(g.ChangedFiles, "changed file", "changed files")
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in repoIn) envelope.Envelope[GitPull] {
			budget, e := d.timeoutFor(in.timeoutArg)
			if e != nil {
				return envelope.Failure[GitPull](in.Target, e)
			}
			return fetch[GitPull](ctx, d, in.Target, protocol.OpGitPull, repoWire{Repo: in.Repo}, budget)
		},
	})
}

// --- shell_run_command ------------------------------------------------------------

type runCommandIn struct {
	targetArg
	CommandID string   `json:"command_id" jsonschema:"Id of a command declared in the target policy with tier read or operator."`
	Args      []string `json:"args,omitzero" jsonschema:"Arguments; they must match one of the command's templates exactly (at most 64, each at most 1024 bytes, no NUL or line breaks)."`
	Cwd       string   `json:"cwd,omitzero" jsonschema:"Working directory: an absolute, clean path under a read root. Default /."`
	Stdin     string   `json:"stdin,omitzero" jsonschema:"Standard input: UTF-8 text of at most 1048576 bytes and at most the target policy's max_stdin_bytes. Default: none."`
	timeoutArg
	outputArg
}

func (in *runCommandIn) validate() *envelope.Error {
	if e := checkCommand(in.CommandID, in.Args, in.Cwd); e != nil {
		return e
	}
	if len(in.Stdin) > maxStdinCeiling || !utf8.ValidString(in.Stdin) {
		return invalid("stdin must be UTF-8 text of at most %d bytes", maxStdinCeiling)
	}
	return nil
}

type runCommandWire struct {
	CommandID      string   `json:"command_id"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	StdinB64       string   `json:"stdin_b64"`
	MaxOutputBytes int      `json:"max_output_bytes"`
}

func (w *runCommandWire) normalize() {
	if w.Args == nil {
		w.Args = []string{}
	}
}

func runCommand(d *Deps) Tool {
	return define(d, spec[runCommandIn, CommandOutput]{
		name:        "shell_run_command",
		title:       "Run command",
		description: "Runs a read- or operator-tier command declared in the target policy with arguments matching one of its templates and optional standard input, and returns its exit status and redacted, size-capped output.",
		tier:        TierOperator,
		idempotent:  false,
		schema: func(s *jsonschema.Schema) {
			boundCommand(s)
			strIn(s, "stdin", anyPattern, maxStdinCeiling)
		},
		audit: func(in runCommandIn) map[string]any {
			m := commandAudit(in.Target, in.CommandID, in.Args, in.Cwd)
			if in.Stdin != "" {
				m["stdin_bytes"] = len(in.Stdin)
			}
			return m
		},
		summary: commandSummary,
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in runCommandIn) envelope.Envelope[CommandOutput] {
			w := runCommandWire{CommandID: in.CommandID, Args: in.Args, Cwd: in.Cwd}
			if in.Stdin != "" {
				w.StdinB64 = base64.StdEncoding.EncodeToString([]byte(in.Stdin))
			}
			if in.MaxOutputBytes != nil {
				w.MaxOutputBytes = *in.MaxOutputBytes
			}
			return d.runExec(ctx, in.Target, &w, in.timeoutArg, in.outputArg)
		},
	})
}
