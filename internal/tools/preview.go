package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Approval previews of the operator tools (docs/TOOLS.md, "Approval
// previews"). Each is built from the gate's existing read operations and
// holds only what does not change by itself between the request and the
// re-call (no memory figures, timestamps of the unit's state or durations),
// so that a fresh preview hashes the same unless the target changed.

// previewFetch sends one preview read and decodes its data strictly. With
// absentOK a not_found answer is no error: data is nil. The policy hash is
// returned in every case the gate answered: the gate block's, or for a
// privileged op (priv_*) the hash of the gate's and the helper's
// (privPolicy), so that an approval is bound to both policies. A
// privileged answer a preview uses (a success, or not_found under
// absentOK) must carry both; any other refusal is the preview's result
// as it is, whoever answered it.
func previewFetch[T any](ctx context.Context, d *Deps, target, op string, args any, absentOK bool) (data *T, warnings []string, policy string, e *envelope.Error) {
	resp, e := d.call(ctx, target, op, args, d.budget())
	if e != nil {
		return nil, nil, "", e
	}
	if resp.Gate != nil {
		policy = resp.Gate.PolicySHA256
	}
	absent := !resp.OK && absentOK && resp.Error != nil && resp.Error.Code == protocol.CodeNotFound
	if strings.HasPrefix(op, privOpPrefix) && (resp.OK || absent) {
		if policy, e = privPolicy(resp); e != nil {
			return nil, nil, "", e
		}
	}
	if absent {
		return nil, nil, policy, nil
	}
	env := envelope.FromGate[T](target, resp)
	if !env.OK {
		return nil, nil, policy, env.Error
	}
	redactStrings(d.redactor(), reflect.ValueOf(env.Data))
	return env.Data, env.Warnings, policy, nil
}

// privOpPrefix starts every privileged (helper) operation's name.
const privOpPrefix = "priv_"

// privPolicy is the policy hash a privileged preview binds (handoff D1):
// the SHA-256 of "gate:<gate policy hash>\nhelper:<privileged policy
// hash>", so that an edit of either policy between the approval and the
// re-call changes it (approval_invalid). A forwarded answer without the
// helper block, or without either hash, cannot bind the privileged policy
// and is refused: no approval is requested on it.
func privPolicy(resp *protocol.Response) (string, *envelope.Error) {
	if resp.Gate == nil || resp.Gate.PolicySHA256 == "" || resp.Helper == nil || resp.Helper.PolicySHA256 == "" {
		return "", envelope.Errorf("internal",
			"the gate's answer to a privileged operation carries no privileged policy hash (a gate older than this server?); nothing was requested")
	}
	return sha256Hex([]byte("gate:" + resp.Gate.PolicySHA256 + "\nhelper:" + resp.Helper.PolicySHA256)), nil
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
func (d *Deps) writePreview(ctx context.Context, in *writeIn, target string) (*preview, *envelope.Error) {
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
		return acc.absentResult(value)
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
		return acc.absentResult(value)
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

// execPreviewWire is the gate's exec_preview data and its arguments.
type execPreviewWire struct {
	CommandID      string   `json:"command_id"`
	Tier           string   `json:"tier"`
	Description    string   `json:"description"`
	RootEquivalent bool     `json:"root_equivalent"`
	Template       []string `json:"template"`
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

type execPreviewArgsWire struct {
	CommandID string   `json:"command_id"`
	Args      []string `json:"args"`
	Cwd       string   `json:"cwd"`
}

// runCommandPreview is shell_run_command's approval preview: the gate's
// exec_preview, which resolves the command exactly as exec will (the
// command's tier against the tool's ceiling, the template the arguments
// match, path placeholders and the cwd resolved on the target) and runs
// nothing: the command id, tier, description, root_equivalent flag, the
// matched template, the resolved argv and cwd, and preview_sha256, which
// the re-call sends to exec as expected_preview_sha256. The hash is taken
// from the gate's answer before the server's redaction.
func (d *Deps) runCommandPreview(ctx context.Context, in *runCommandIn, target string) (*preview, *envelope.Error) {
	args := in.Args
	if args == nil {
		args = []string{}
	}
	resp, e := d.call(ctx, target, protocol.OpExecPreview, execPreviewArgsWire{CommandID: in.CommandID, Args: args, Cwd: in.Cwd}, d.budget())
	if e != nil {
		return nil, e
	}
	policy := ""
	if resp.Gate != nil {
		policy = resp.Gate.PolicySHA256
	}
	env := envelope.FromGate[execPreviewWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	hash := env.Data.PreviewSHA256
	if !sha256RE.MatchString(hash) {
		return nil, envelope.Errorf("internal", "the gate's preview has no valid preview_sha256")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	for _, l := range []*[]string{&x.Template, &x.Argv} {
		if *l == nil {
			*l = []string{}
		}
	}
	value := map[string]any{"command_id": x.CommandID, "tier": x.Tier, "description": x.Description, "root_equivalent": x.RootEquivalent,
		"template": x.Template, "argv": x.Argv, "cwd": x.Cwd, "preview_sha256": hash}
	tier, ok := map[string]Tier{"read": TierRead, "operator": TierOperator, "destructive": TierDestructive}[env.Data.Tier]
	if !ok {
		return nil, envelope.Errorf("internal", "the gate's preview names no known tier")
	}
	return &preview{value: value, policy: policy, contentSHA256: hash, tier: tier}, nil
}
