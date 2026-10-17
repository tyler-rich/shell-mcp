package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// Approval previews of the operator tools (docs/TOOLS.md, "Approval
// previews"). Each is built from the gate's existing read operations and
// holds only what does not change by itself between the request and the
// re-call (no memory figures, timestamps of the unit's state or durations),
// so that a fresh preview hashes the same unless the target changed.

// previewFetch sends one preview read and decodes its data strictly. With
// absentOK a not_found answer is no error: data is nil. The policy hash of
// the gate block is returned in every case the gate answered.
func previewFetch[T any](ctx context.Context, d *Deps, target, op string, args any, absentOK bool) (data *T, warnings []string, policy string, e *envelope.Error) {
	resp, e := d.call(ctx, target, op, args, d.budget())
	if e != nil {
		return nil, nil, "", e
	}
	if resp.Gate != nil {
		policy = resp.Gate.PolicySHA256
	}
	if !resp.OK && absentOK && resp.Error != nil && resp.Error.Code == protocol.CodeNotFound {
		return nil, nil, policy, nil
	}
	env := envelope.FromGate[T](target, resp)
	if !env.OK {
		return nil, nil, policy, env.Error
	}
	redactStrings(d.redactor(), reflect.ValueOf(env.Data))
	return env.Data, env.Warnings, policy, nil
}

// entryPreview is a path's state: absent, or its stat.
func entryPreview(e *Entry) map[string]any {
	if e == nil {
		return map[string]any{"state": "absent"}
	}
	m := map[string]any{"state": "present", "type": e.Type, "size": e.Size, "mode": e.Mode, "uid": e.UID, "gid": e.GID, "mtime": e.MTime}
	if e.Owner != "" {
		m["owner"] = e.Owner
	}
	if e.Group != "" {
		m["group"] = e.Group
	}
	if e.LinkTarget != "" {
		m["link_target"] = e.LinkTarget
	}
	return m
}

func (d *Deps) statPreview(ctx context.Context, target, path string, acc *policyAcc) (*Entry, *envelope.Error) {
	e, _, pol, err := previewFetch[Entry](ctx, d, target, protocol.OpStat, pathWire{Path: path}, true)
	acc.add(pol)
	return e, err
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// countLines counts lines as the gate's write result does.
func countLines(b []byte) int {
	n := bytes.Count(b, []byte("\n"))
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// writePreview: the file's current state (absent; or its size, mode,
// content SHA-256 and line count; or another type), the new content's size,
// SHA-256 and line count, and the line delta. Lines are counted only when
// the gate returned the whole file as text, unredacted; otherwise null.
func (d *Deps) writePreview(ctx context.Context, in writeIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	content := []byte(*in.Content)
	newLines := countLines(content)
	next := map[string]any{"bytes": len(content), "sha256": sha256Hex(content), "lines": newLines}
	st, e := d.statPreview(ctx, target, in.Path, &acc)
	if e != nil {
		return nil, e
	}
	value := map[string]any{"path": in.Path, "new": next}
	if st == nil {
		value["current"] = map[string]any{"state": "absent"}
		value["lines_delta"] = newLines
		return acc.result(value, "")
	}
	if st.Type != "file" {
		value["current"] = entryPreview(st)
		value["lines_delta"] = nil
		return acc.result(value, "")
	}
	f, warns, pol, e := previewFetch[FileContent](ctx, d, target, protocol.OpReadFile, readFileWire{Path: in.Path}, true)
	acc.add(pol)
	if e != nil {
		return nil, e
	}
	if f == nil { // removed between the two reads
		value["current"] = map[string]any{"state": "absent"}
		value["lines_delta"] = newLines
		return acc.result(value, "")
	}
	cur := map[string]any{"state": "file", "size": st.Size, "mode": st.Mode, "sha256": f.SHA256, "lines": nil}
	value["lines_delta"] = nil
	if !f.Binary && !f.Truncated && f.Offset == 0 && int64(len(f.Content)) == f.Size && len(warns) == 0 {
		n := countLines([]byte(f.Content))
		cur["lines"] = n
		value["lines_delta"] = newLines - n
	}
	value["current"] = cur
	return acc.result(value, f.SHA256)
}

// srcDstPreview: the stat of the source and of the destination (each
// possibly absent).
func (d *Deps) srcDstPreview(ctx context.Context, in srcDstIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	src, e := d.statPreview(ctx, target, in.Source, &acc)
	if e != nil {
		return nil, e
	}
	dst, e := d.statPreview(ctx, target, in.Destination, &acc)
	if e != nil {
		return nil, e
	}
	return acc.result(map[string]any{"source": entryPreview(src), "destination": entryPreview(dst)}, "")
}

// pathPreview: the stat of one path (possibly absent).
func (d *Deps) pathPreview(ctx context.Context, path, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	st, e := d.statPreview(ctx, target, path, &acc)
	if e != nil {
		return nil, e
	}
	return acc.result(map[string]any{"path": entryPreview(st)}, "")
}

// controlPreview: the unit's current load, active, sub and unit-file
// states, main PID and last result.
func (d *Deps) controlPreview(ctx context.Context, in controlIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	st, _, pol, e := previewFetch[ServiceStatus](ctx, d, target, protocol.OpServiceStatus, unitWire{Unit: in.Unit}, false)
	acc.add(pol)
	if e != nil {
		return nil, e
	}
	return acc.result(map[string]any{
		"unit": st.Unit, "load_state": st.LoadState, "active_state": st.ActiveState, "sub_state": st.SubState,
		"unit_file_state": st.UnitFileState, "main_pid": st.MainPID, "result": st.Result,
	}, "")
}

// maxPreviewEntries bounds the git status entries a preview lists.
const maxPreviewEntries = 50

// gitPullPreview: the repository's branch, HEAD, upstream, ahead and
// behind counts and its status entries (the first 50).
func (d *Deps) gitPullPreview(ctx context.Context, in repoIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	st, _, pol, e := previewFetch[GitStatus](ctx, d, target, protocol.OpGitStatus, repoWire{Repo: in.Repo}, false)
	acc.add(pol)
	if e != nil {
		return nil, e
	}
	entries := st.Entries
	if entries == nil {
		entries = []GitStatusEntry{}
	}
	return acc.result(map[string]any{
		"repo": st.Repo, "branch": st.Branch, "head": st.Head, "upstream": st.Upstream, "ahead": st.Ahead, "behind": st.Behind,
		"entries": entries[:min(len(entries), maxPreviewEntries)], "entries_total": len(entries),
		"truncated": st.Truncated || len(entries) > maxPreviewEntries,
	}, "")
}

// previewResolver matches templates on the server for the preview only:
// path placeholders are shown as given and unit placeholders are not
// checked; the gate resolves and checks both when the command runs.
type previewResolver struct{}

func (previewResolver) ResolvePath(v string, _ bool) (string, error) { return v, nil }
func (previewResolver) MatchUnit(string) bool                        { return true }

var tierRank = map[string]int{"read": 1, "operator": 2, "destructive": 3}

// runCommandPreview, from the policy op only until S4b-2's exec_preview:
// the command id, its tier, description and root_equivalent flag, the
// template the arguments match and the arguments as given. An undeclared
// command, one above the tool's ceiling or arguments matching no template
// are refused here, as the gate would refuse them.
func (d *Deps) runCommandPreview(ctx context.Context, in runCommandIn, target string) (*preview, *envelope.Error) {
	var acc policyAcc
	pol, _, h, e := previewFetch[summaryWire](ctx, d, target, protocol.OpPolicy, nil, false)
	acc.add(h)
	if e != nil {
		return nil, e
	}
	i := slices.IndexFunc(pol.Commands, func(c Command) bool { return c.ID == in.CommandID })
	if i < 0 {
		return nil, envelope.Errorf(protocol.CodePolicyDenied, "command %q is not declared in the target policy", in.CommandID)
	}
	cmd := pol.Commands[i]
	ceiling, _ := ctx.Value(ceilingKey{}).(Tier)
	if tierRank[cmd.Tier] == 0 || tierRank[cmd.Tier] > int(ceiling) {
		return nil, envelope.Errorf(protocol.CodeTierDenied, "command tier %s exceeds the request's ceiling %s", cmd.Tier, ceiling)
	}
	args := in.Args
	if args == nil {
		args = []string{}
	}
	var matched []string
	for _, raw := range cmd.Templates {
		t, err := template.Parse(raw)
		if err != nil {
			continue
		}
		if _, err := template.Match([]template.Template{t}, args, previewResolver{}); err == nil {
			matched = raw
			break
		}
	}
	if matched == nil {
		return nil, envelope.Errorf(protocol.CodeTemplateMismatch, "the arguments match none of the command's templates")
	}
	return acc.result(map[string]any{
		"command_id": cmd.ID, "tier": cmd.Tier, "description": cmd.Description, "root_equivalent": cmd.RootEquivalent,
		"template": matched, "args": args,
	}, "")
}
