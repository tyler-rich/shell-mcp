package tools

import (
	"context"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Git discard tools (docs/TOOLS.md): shell_preview_git_discard (read tier)
// sends git_discard_preview; shell_discard_git_changes (destructive, admin
// profile, always approval-gated) uses git_discard_preview's result as its
// approval preview, and its re-call sends git_discard with the fresh
// preview's preview_sha256 as expected_preview_sha256, so the gate discards
// exactly what that preview listed or stops.

type discardIn struct {
	targetArg
	Repo             string `json:"repo" jsonschema:"Absolute, clean path of a repository listed in the target policy's git repos; to discard, inside a write root."`
	IncludeUntracked bool   `json:"include_untracked,omitzero" jsonschema:"Also remove untracked files and directories (never ignored ones). Default false: untracked files are left alone."`
	// expectedPreview is set only by an approved call: the preview_sha256
	// of its fresh preview (never an input).
	expectedPreview string
}

func (in *discardIn) validate() *envelope.Error { return checkPath("repo", in.Repo) }

// GitDiscardEntry is one path a discard changes.
type GitDiscardEntry struct {
	Path   string `json:"path" jsonschema:"Path in the repository."`
	Status string `json:"status" jsonschema:"git status letters (index, work tree), or ?? for an untracked path."`
	Action string `json:"action" jsonschema:"restore (to HEAD) or remove."`
}

// GitDiscardPreview is shell_preview_git_discard's data.
type GitDiscardPreview struct {
	Repo             string            `json:"repo" jsonschema:"The repository."`
	Head             string            `json:"head" jsonschema:"HEAD commit the tracked files are restored to."`
	IncludeUntracked bool              `json:"include_untracked" jsonschema:"Whether untracked paths are removed."`
	Restore          int               `json:"restore" jsonschema:"Tracked paths restored to HEAD (staged and unstaged changes)."`
	Remove           int               `json:"remove" jsonschema:"Paths staged as new (not in HEAD) that are removed."`
	Untracked        int               `json:"untracked" jsonschema:"Untracked files and directories removed (0 without include_untracked)."`
	UntrackedEntries int               `json:"untracked_entries" jsonschema:"Entries under those untracked paths, the paths included."`
	Entries          int               `json:"entries" jsonschema:"restore + remove + untracked."`
	First            []GitDiscardEntry `json:"first" jsonschema:"The first entries (at most 50), in byte order of paths."`
	Skipped          []string          `json:"skipped" jsonschema:"Nested repositories inside the work tree, which are never touched."`
	Truncated        bool              `json:"truncated" jsonschema:"True when first lists fewer entries than entries."`
	PreviewSHA256    string            `json:"preview_sha256" jsonschema:"SHA-256 over HEAD, the index entries and the identity and content of everything discarded; a discard runs only while it is unchanged."`
}

// GitDiscard is shell_discard_git_changes' data.
type GitDiscard struct {
	Repo       string `json:"repo" jsonschema:"The repository."`
	Head       string `json:"head" jsonschema:"HEAD commit the tracked files were restored to."`
	Restore    int    `json:"restore" jsonschema:"Tracked paths restored to HEAD."`
	Remove     int    `json:"remove" jsonschema:"Paths staged as new that were removed."`
	Untracked  int    `json:"untracked" jsonschema:"Untracked files and directories removed."`
	Entries    int    `json:"entries" jsonschema:"restore + remove + untracked."`
	Discarded  bool   `json:"discarded" jsonschema:"True: everything the approved preview listed was discarded and the index is HEAD's."`
	CleanAfter bool   `json:"clean_after" jsonschema:"True when git status shows nothing afterwards in the superproject (untracked files left without include_untracked, or nested repositories, make it false); submodule work trees are never inspected, so true does not mean a submodule's work tree is clean."`
}

// gitDiscardWire is the gate's git_discard_preview and git_discard data.
type gitDiscardWire struct {
	Repo             string            `json:"repo"`
	Head             string            `json:"head"`
	IncludeUntracked bool              `json:"include_untracked"`
	Restore          int               `json:"restore"`
	Remove           int               `json:"remove"`
	Untracked        int               `json:"untracked"`
	UntrackedEntries int               `json:"untracked_entries"`
	Entries          int               `json:"entries"`
	First            []GitDiscardEntry `json:"first"`
	Skipped          []string          `json:"skipped"`
	Truncated        bool              `json:"truncated"`
	PreviewSHA256    string            `json:"preview_sha256"`
	Applied          bool              `json:"applied"`
	CleanAfter       *bool             `json:"clean_after,omitempty"`
}

type discardPreviewWire struct {
	Repo             string `json:"repo"`
	IncludeUntracked bool   `json:"include_untracked"`
}

type discardWire struct {
	Repo                  string `json:"repo"`
	IncludeUntracked      bool   `json:"include_untracked"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

func boundDiscard(s *jsonschema.Schema) {
	boundCommon(s)
	strIn(s, "repo", pathPattern, 4096)
	p := prop(s, "include_untracked")
	p.Type, p.Types = "boolean", nil
}

func discardAudit(in discardIn) map[string]any {
	return map[string]any{"target": in.Target, "repo": in.Repo, "include_untracked": in.IncludeUntracked}
}

func previewGitDiscard(d *Deps) Tool {
	return define(d, spec[discardIn, GitDiscardPreview]{
		name:        "shell_preview_git_discard",
		title:       "Preview git discard",
		description: "Reports what discarding a repository's uncommitted changes would restore and remove, without changing anything: counts, the first 50 paths and a hash of the complete list.",
		tier:        TierRead,
		schema:      boundDiscard,
		audit:       discardAudit,
		summary:     func(p *GitDiscardPreview) string { return discardSummary(p.Restore, p.Remove, p.Untracked) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in discardIn) envelope.Envelope[GitDiscardPreview] {
			r := fetch[gitDiscardWire](ctx, d, in.Target, protocol.OpGitDiscardPreview, discardPreviewWire{Repo: in.Repo, IncludeUntracked: in.IncludeUntracked}, d.budget())
			if !r.OK {
				return envelope.Failure[GitDiscardPreview](r.Target, r.Error)
			}
			x := r.Data
			out := GitDiscardPreview{Repo: x.Repo, Head: x.Head, IncludeUntracked: x.IncludeUntracked, Restore: x.Restore, Remove: x.Remove,
				Untracked: x.Untracked, UntrackedEntries: x.UntrackedEntries, Entries: x.Entries, First: x.First, Skipped: x.Skipped,
				Truncated: x.Truncated, PreviewSHA256: x.PreviewSHA256}
			if out.First == nil {
				out.First = []GitDiscardEntry{}
			}
			if out.Skipped == nil {
				out.Skipped = []string{}
			}
			out.Truncated = fitList(&out, &out.First, d.maxOutput()) || out.Truncated || len(out.First) < out.Entries
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
	})
}

func discardGitChanges(d *Deps) Tool {
	return define(d, spec[discardIn, GitDiscard]{
		name:        "shell_discard_git_changes",
		title:       "Discard git changes",
		description: "Restores a repository's tracked files and index to HEAD and, with include_untracked, removes untracked files, exactly as its approved preview listed them. Superproject only: submodule work trees are never inspected (not their changes or checked-out commit); staged gitlink changes are seen.",
		tier:        TierDestructive,
		schema:      boundDiscard,
		audit:       discardAudit,
		summary:     func(p *GitDiscard) string { return "discarded " + discardSummary(p.Restore, p.Remove, p.Untracked) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in discardIn) envelope.Envelope[GitDiscard] {
			// Only an approved call reaches this, with its fresh preview's
			// hash; the gate refuses a discard without one anyway.
			if in.expectedPreview == "" {
				return envelope.Failure[GitDiscard](in.Target, envelope.Errorf("internal", "a discard needs the hash of an approved preview; nothing was sent"))
			}
			w := discardWire{Repo: in.Repo, IncludeUntracked: in.IncludeUntracked, ExpectedPreviewSHA256: in.expectedPreview}
			r := fetch[gitDiscardWire](ctx, d, in.Target, protocol.OpGitDiscard, w, d.budget())
			if !r.OK {
				return envelope.Failure[GitDiscard](r.Target, r.Error)
			}
			x := r.Data
			if !x.Applied || x.CleanAfter == nil {
				return envelope.Failure[GitDiscard](r.Target, envelope.Errorf("internal", "the gate answered without confirming the discard; preview the repository to see what remains"))
			}
			env := envelope.Success(r.Target, GitDiscard{Repo: x.Repo, Head: x.Head, Restore: x.Restore, Remove: x.Remove, Untracked: x.Untracked,
				Entries: x.Entries, Discarded: true, CleanAfter: *x.CleanAfter})
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in discardIn) any {
			return struct {
				Repo             string `json:"repo"`
				IncludeUntracked bool   `json:"include_untracked"`
			}{in.Repo, in.IncludeUntracked}
		},
		describe: func(in discardIn, target string) string {
			what := "Discard the uncommitted changes in " + plain(in.Repo, "a repository shown in the arguments")
			if in.IncludeUntracked {
				what += ", untracked files included,"
			}
			return what + " on " + target
		},
		preview:      d.discardPreview,
		precondition: func(in *discardIn, p *preview) { in.expectedPreview = p.contentSHA256 },
	})
}

func discardSummary(restore, remove, untracked int) string {
	return plural(restore, "path", "paths") + " restored, " + plural(remove+untracked, "path", "paths") + " removed"
}

// discardPreview is shell_discard_git_changes' approval preview: the gate's
// git_discard_preview result. The hash the re-call sends back as the
// precondition is taken from the gate's answer before the server's
// redaction, which could otherwise rewrite it.
func (d *Deps) discardPreview(ctx context.Context, in discardIn, target string) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, protocol.OpGitDiscardPreview, discardPreviewWire{Repo: in.Repo, IncludeUntracked: in.IncludeUntracked}, d.budget())
	if e != nil {
		return nil, e
	}
	policy := ""
	if resp.Gate != nil {
		policy = resp.Gate.PolicySHA256
	}
	env := envelope.FromGate[gitDiscardWire](target, resp)
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
		x.First = []GitDiscardEntry{}
	}
	if x.Skipped == nil {
		x.Skipped = []string{}
	}
	value := map[string]any{"repo": x.Repo, "include_untracked": in.IncludeUntracked, "head": x.Head, "restore": x.Restore, "remove": x.Remove,
		"untracked": x.Untracked, "untracked_entries": x.UntrackedEntries, "entries": x.Entries, "first": x.First, "skipped": x.Skipped,
		"truncated": x.Truncated, "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash}, nil
}
