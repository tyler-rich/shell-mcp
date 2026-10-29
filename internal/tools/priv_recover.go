package tools

import (
	"context"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// shell_priv_recover_packages (handoff N-14, S7-4; docs/TOOLS.md,
// privileged tier: packages): finishes what an interrupted dpkg left
// unfinished. Its preview is the helper's priv_pkg_recover_preview: the
// unfinished packages from dpkg's status with its journal folded in, and a
// hash of them with the privileged policy. With nothing unfinished it
// answers at once, at tier read: no approval is requested and nothing is
// run (tierFromPreview). Otherwise it is approval-gated at tier operator,
// and the approved re-call sends priv_pkg_recover with the fresh
// preview's hash (taken before the server's redaction). The client sends
// no package names and no dpkg options.

type privRecoverIn struct {
	targetArg
	timeoutArg
	// expectedPreview and nothing are set only from the preview (never
	// inputs): its preview_sha256, and that nothing was unfinished.
	expectedPreview string
	nothing         bool
}

// RecoveredPackage is a package a recovery configured.
type RecoveredPackage struct {
	Name      string `json:"name" jsonschema:"Package name (with :arch for a foreign architecture)."`
	Version   string `json:"version" jsonschema:"Its version, unchanged by the recovery."`
	FromState string `json:"from_state" jsonschema:"dpkg's state for it before: unpacked, half-configured, triggers-awaited or triggers-pending."`
}

// RecoverResult is shell_priv_recover_packages' data.
type RecoverResult struct {
	Ran             bool               `json:"ran" jsonschema:"False when nothing was unfinished: nothing was run and no approval was needed."`
	Configured      []RecoveredPackage `json:"configured" jsonschema:"What dpkg's state shows the recovery configured: every unfinished package of the approved preview."`
	ExitCode        *int               `json:"exit_code" jsonschema:"dpkg's exit code (informational: the result is decided by dpkg's state)."`
	Stdout          string             `json:"stdout" jsonschema:"dpkg's output, redacted and capped."`
	Stderr          string             `json:"stderr" jsonschema:"dpkg's error output, redacted and capped."`
	StdoutTruncated bool               `json:"stdout_truncated" jsonschema:"True when stdout was cut."`
	StderrTruncated bool               `json:"stderr_truncated" jsonschema:"True when stderr was cut."`
	Attempts        int                `json:"attempts" jsonschema:"dpkg runs, more than one after another process held the lock."`
	LockWaitMS      int64              `json:"lock_wait_ms" jsonschema:"How long a held dpkg lock was waited for."`
	DurationMS      int64              `json:"duration_ms" jsonschema:"Duration of the last run."`
}

type recoverEntryWire struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	State          string   `json:"state"`
	Flag           string   `json:"flag"`
	MissingDepends []string `json:"missing_depends"`
}

type recoverPreviewWire struct {
	Op             string             `json:"op"`
	Unfinished     []recoverEntryWire `json:"unfinished"`
	NeedsReinstall []recoverEntryWire `json:"needs_reinstall"`
	JournalEntries int                `json:"journal_entries"`
	Argv           []string           `json:"argv"`
	PolicySHA256   string             `json:"policy_sha256"`
	PreviewSHA256  string             `json:"preview_sha256"`
}

type recoverResultWire struct {
	Op         string             `json:"op"`
	Ran        bool               `json:"ran"`
	Configured []RecoveredPackage `json:"configured"`
	Signal     *string            `json:"signal"`
	TimedOut   bool               `json:"timed_out"`
	PackageRun
}

func recoverEntries(l []recoverEntryWire) []map[string]any {
	out := make([]map[string]any, 0, len(l))
	for _, e := range l {
		missing := e.MissingDepends
		if missing == nil {
			missing = []string{}
		}
		out = append(out, map[string]any{"name": e.Name, "version": e.Version, "state": e.State, "flag": e.Flag, "missing_depends": missing})
	}
	return out
}

func privRecoverPackages(d *Deps) Tool {
	return define(d, spec[privRecoverIn, RecoverResult]{
		name: "shell_priv_recover_packages", title: "Recover unfinished packages as root",
		description: "Finishes, as root, what an interrupted dpkg left unfinished, exactly as its approved preview listed it, without installing or removing packages; returns what dpkg shows was configured.",
		tier:        TierOperator, privileged: true, idempotent: false, tierFromPreview: true,
		schema: boundCommon,
		audit:  func(in privRecoverIn) map[string]any { return pkgAudit(in.Target, nil) },
		summary: func(r *RecoverResult) string {
			if !r.Ran {
				return "nothing to recover; nothing ran"
			}
			return "as root: configured " + plural(len(r.Configured), "package", "packages")
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privRecoverIn) envelope.Envelope[RecoverResult] {
			if in.nothing {
				tg, e := d.resolve(in.Target)
				if e != nil {
					return envelope.Failure[RecoverResult](in.Target, e)
				}
				return envelope.Success(tg.Name, RecoverResult{Configured: []RecoveredPackage{}})
			}
			if in.expectedPreview == "" {
				return envelope.Failure[RecoverResult](in.Target, envelope.Errorf("internal", "a recovery needs the hash of an approved preview; nothing was sent"))
			}
			budget, e := d.timeoutFor(in.timeoutArg)
			if e != nil {
				return envelope.Failure[RecoverResult](in.Target, e)
			}
			r := fetch[recoverResultWire](ctx, d, in.Target, protocol.OpPrivPkgRecover, pkgBoundWire{ExpectedPreviewSHA256: in.expectedPreview}, budget)
			if !r.OK {
				return envelope.Failure[RecoverResult](r.Target, r.Error)
			}
			x := r.Data
			run := d.capRun(x.PackageRun)
			out := RecoverResult{Ran: x.Ran, Configured: x.Configured, ExitCode: run.ExitCode, Stdout: run.Stdout, Stderr: run.Stderr,
				StdoutTruncated: run.StdoutTruncated, StderrTruncated: run.StderrTruncated, Attempts: run.Attempts, LockWaitMS: run.LockWaitMS, DurationMS: run.DurationMS}
			if out.Configured == nil {
				out.Configured = []RecoveredPackage{}
			}
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privRecoverIn) any {
			return struct {
				TimeoutSeconds int `json:"timeout_seconds"`
			}{d.timeoutDefault(in.timeoutArg)}
		},
		describe: func(_ privRecoverIn, target string) string { return "As root, finish unfinished packages on " + target },
		describePreview: func(_ privRecoverIn, target string, p *preview) string {
			return "As root, finish " + plural(p.count, "unfinished package", "unfinished packages") + " on " + target
		},
		preview: func(ctx context.Context, _ privRecoverIn, target string) (*preview, *envelope.Error) {
			return d.privRecoverPreview(ctx, target)
		},
		precondition: func(in *privRecoverIn, p *preview) {
			in.expectedPreview, in.nothing = p.contentSHA256, p.tier == TierRead
		},
		precheck: func(in *privRecoverIn) *envelope.Error {
			_, e := d.timeoutFor(in.timeoutArg)
			return e
		},
	})
}

// privRecoverPreview is the recovery's approval preview: the helper's
// report of the unfinished packages, the argv and preview_sha256, bound
// with both policies' hashes. Its tier is read when nothing is unfinished
// (no approval, nothing run) and operator otherwise.
func (d *Deps) privRecoverPreview(ctx context.Context, target string) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, protocol.OpPrivPkgRecoverPreview, noArgsWire{}, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[recoverPreviewWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	policy, e := privPolicy(resp)
	if e != nil {
		return nil, e
	}
	hash := env.Data.PreviewSHA256
	if !sha256RE.MatchString(hash) || env.Data.Op != "recover" {
		return nil, envelope.Errorf("internal", "the helper's recovery preview has no valid preview_sha256")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	argv := x.Argv
	if argv == nil {
		argv = []string{}
	}
	value := map[string]any{"op": "recover", "unfinished": recoverEntries(x.Unfinished), "needs_reinstall": recoverEntries(x.NeedsReinstall),
		"journal_entries": x.JournalEntries, "argv": argv, "preview_sha256": hash}
	tier := TierOperator
	if len(x.Unfinished)+len(x.NeedsReinstall)+x.JournalEntries == 0 {
		tier = TierRead
	}
	return &preview{value: value, policy: policy, contentSHA256: hash, count: len(x.Unfinished), tier: tier}, nil
}
