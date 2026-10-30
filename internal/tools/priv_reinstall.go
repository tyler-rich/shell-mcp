package tools

import (
	"context"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// shell_priv_reinstall_packages (handoff N-36, S7-7; docs/TOOLS.md,
// privileged tier: packages): reinstalls the packages dpkg left needing a
// reinstall (half-installed, or flagged reinstreq), which the recovery
// cannot finish and dpkg refuses to remove. Its preview is the helper's
// priv_pkg_reinstall_preview: apt-get install --reinstall simulated with
// every name pinned to the version dpkg's status names, hashed with the
// unfinished state and the privileged policy. It is approval-gated at
// tier operator, and the approved re-call sends priv_pkg_reinstall with
// the names and the fresh preview's hash (taken before the server's
// redaction). The client sends package names only.

// UnfinishedPackage is a package dpkg left unfinished.
type UnfinishedPackage struct {
	Name           string   `json:"name" jsonschema:"Package name (with :arch for a foreign architecture)."`
	Version        string   `json:"version" jsonschema:"The version dpkg's status names for it."`
	State          string   `json:"state" jsonschema:"dpkg's state for it: unpacked, half-configured, half-installed, triggers-awaited or triggers-pending."`
	Flag           string   `json:"flag" jsonschema:"dpkg's flag for it: ok, or reinstreq when it needs a reinstall."`
	MissingDepends []string `json:"missing_depends" jsonschema:"Its dependencies that no package on the host provides."`
}

// ReinstallResult is shell_priv_reinstall_packages' data.
type ReinstallResult struct {
	Op          string             `json:"op" jsonschema:"reinstall."`
	Packages    []string           `json:"packages" jsonschema:"The requested names."`
	Reinstalled []RecoveredPackage `json:"reinstalled" jsonschema:"What dpkg's state shows was reinstalled: every requested package, installed at the same version."`
	PackageRun
}

type reinstallPreviewWire struct {
	Op              string             `json:"op"`
	Packages        []string           `json:"packages"`
	Reinstall       []recoverEntryWire `json:"reinstall"`
	Argv            []string           `json:"argv"`
	ExitCode        *int               `json:"exit_code"`
	Signal          *string            `json:"signal"`
	Stderr          string             `json:"stderr"`
	StderrTruncated bool               `json:"stderr_truncated"`
	DurationMS      int64              `json:"duration_ms"`
	PolicySHA256    string             `json:"policy_sha256"`
	PreviewSHA256   string             `json:"preview_sha256"`
}

type reinstallResultWire struct {
	Op          string             `json:"op"`
	Packages    []string           `json:"packages"`
	Reinstalled []RecoveredPackage `json:"reinstalled"`
	Signal      *string            `json:"signal"`
	TimedOut    bool               `json:"timed_out"`
	PackageRun
}

func orNone(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func unfinishedOf(l []recoverEntryWire) []UnfinishedPackage {
	out := make([]UnfinishedPackage, 0, len(l))
	for _, e := range l {
		out = append(out, UnfinishedPackage{Name: e.Name, Version: e.Version, State: e.State, Flag: e.Flag, MissingDepends: orNone(e.MissingDepends)})
	}
	return out
}

type privReinstallIn struct{ privPkgNamesIn }

func (in *privReinstallIn) validate() *envelope.Error { return checkPkgNames("reinstall", in.Packages) }

func privReinstallPackages(d *Deps) Tool {
	return define(d, spec[privReinstallIn, ReinstallResult]{
		name: "shell_priv_reinstall_packages", title: "Reinstall unfinished packages as root",
		description: "Reinstalls, as root, exactly the packages an interrupted dpkg left needing a reinstall, each at the version dpkg names, as its approved preview listed them; returns what dpkg shows was reinstalled.",
		tier:        TierOperator, privileged: true, idempotent: false,
		schema: boundPkgNames,
		audit:  func(in privReinstallIn) map[string]any { return pkgAudit(in.Target, in.Packages) },
		summary: func(r *ReinstallResult) string {
			return "as root: reinstalled " + plural(len(r.Reinstalled), "package", "packages")
		},
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privReinstallIn) envelope.Envelope[ReinstallResult] {
			if in.expectedPreview == "" {
				return envelope.Failure[ReinstallResult](in.Target, envelope.Errorf("internal", "a reinstall needs the hash of an approved preview; nothing was sent"))
			}
			budget, e := d.timeoutFor(in.timeoutArg)
			if e != nil {
				return envelope.Failure[ReinstallResult](in.Target, e)
			}
			r := fetch[reinstallResultWire](ctx, d, in.Target, protocol.OpPrivPkgReinstall, pkgBoundWire{Packages: in.Packages, ExpectedPreviewSHA256: in.expectedPreview}, budget)
			if !r.OK {
				return envelope.Failure[ReinstallResult](r.Target, r.Error)
			}
			x := r.Data
			out := ReinstallResult{Op: x.Op, Packages: orNone(x.Packages), Reinstalled: x.Reinstalled, PackageRun: d.capRun(x.PackageRun)}
			if out.Reinstalled == nil {
				out.Reinstalled = []RecoveredPackage{}
			}
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privReinstallIn) any {
			return struct {
				Packages       []string `json:"packages"`
				TimeoutSeconds int      `json:"timeout_seconds"`
			}{in.Packages, d.timeoutDefault(in.timeoutArg)}
		},
		describe: func(in privReinstallIn, target string) string {
			return "As root, reinstall " + plural(len(in.Packages), "package", "packages") + " on " + target
		},
		preview: func(ctx context.Context, in privReinstallIn, target string) (*preview, *envelope.Error) {
			return d.privReinstallPreview(ctx, target, in.Packages)
		},
		precondition: func(in *privReinstallIn, p *preview) { in.expectedPreview = p.contentSHA256 },
		precheck: func(in *privReinstallIn) *envelope.Error {
			_, e := d.timeoutFor(in.timeoutArg)
			return e
		},
	})
}

// privReinstallPreview is the reinstall's approval preview: each package
// with its version, state and flag, the pinned argv and preview_sha256,
// bound with both policies' hashes.
func (d *Deps) privReinstallPreview(ctx context.Context, target string, names []string) (*preview, *envelope.Error) {
	resp, e := d.call(ctx, target, protocol.OpPrivPkgReinstallPreview, pkgNamesWire{Packages: names}, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[reinstallPreviewWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	policy, e := privPolicy(resp)
	if e != nil {
		return nil, e
	}
	hash := env.Data.PreviewSHA256
	if !sha256RE.MatchString(hash) || env.Data.Op != "reinstall" {
		return nil, envelope.Errorf("internal", "the helper's reinstall preview has no valid preview_sha256")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	value := map[string]any{"op": "reinstall", "packages": orNone(names), "reinstall": recoverEntries(x.Reinstall), "argv": orNone(x.Argv), "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash, count: len(x.Reinstall)}, nil
}
