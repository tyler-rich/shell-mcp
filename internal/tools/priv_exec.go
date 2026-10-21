package tools

import (
	"context"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// shell_priv_run_command (docs/TOOLS.md, privileged tier: commands; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-6: D6, D9, P-2d, P-3, Q5, Q11, Q14): a
// command declared in the host's privileged policy, run as root by the
// helper. Every call first sends the helper's priv_exec_preview (through
// the core socket, for commands of either unit), which resolves the
// command, its tier and its unit without running anything. Gating follows
// that tier: a read command runs at once at ceiling read, an operator or
// destructive command only after approval, at its own tier. priv_exec goes
// to the unit the (fresh) preview reported, with its preview_sha256, which
// the helper there recomputes; a helper_wrong_unit answer is the result,
// never retried in the other unit. There is no stdin (Q11).

type privRunCommandIn struct {
	targetArg
	CommandID string   `json:"command_id" jsonschema:"Id of a command declared in the host's privileged policy."`
	Args      []string `json:"args,omitzero" jsonschema:"Arguments; they must match one of the command's templates exactly (at most 64, each at most 1024 bytes, no NUL or line breaks)."`
	Cwd       string   `json:"cwd,omitzero" jsonschema:"Working directory: an absolute, clean path under a root of the host's privileged policy. Default /."`
	timeoutArg
	outputArg
	// expectedPreview and unit are set from a preview only (never inputs):
	// the preview's preview_sha256 and the unit it reported.
	expectedPreview string
	unit            string
}

func (in *privRunCommandIn) validate() *envelope.Error {
	return checkCommand(in.CommandID, in.Args, in.Cwd)
}

// privExecWire is priv_exec's arguments (handoff P-3): the routing label
// unit and the preview's hash always go with it.
type privExecWire struct {
	CommandID             string   `json:"command_id"`
	Args                  []string `json:"args"`
	Cwd                   string   `json:"cwd"`
	MaxOutputBytes        int      `json:"max_output_bytes"`
	Unit                  string   `json:"unit"`
	ExpectedPreviewSHA256 string   `json:"expected_preview_sha256"`
}

func (w *privExecWire) normalize() {
	if w.Args == nil {
		w.Args = []string{}
	}
}

// privExecPreviewWire is the helper's priv_exec_preview data (P-2d).
type privExecPreviewWire struct {
	CommandID      string   `json:"command_id"`
	Tier           string   `json:"tier"`
	Unit           string   `json:"unit"`
	Description    string   `json:"description"`
	RootEquivalent bool     `json:"root_equivalent"`
	Capabilities   []string `json:"capabilities"`
	Template       []string `json:"template"`
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

func privRunCommand(d *Deps) Tool {
	return define(d, spec[privRunCommandIn, CommandOutput]{
		name:  "shell_priv_run_command",
		title: "Run command as root",
		description: "Runs, as root, a command declared in the host's privileged policy with arguments matching one of its templates, exactly as its preview " +
			"resolved it and in the unit it named, and returns its exit status and redacted, size-capped output.",
		tier:       TierDestructive,
		privileged: true,
		idempotent: false,
		schema:     boundCommand,
		audit: func(in privRunCommandIn) map[string]any {
			return commandAudit(in.Target, in.CommandID, in.Args, in.Cwd)
		},
		summary: commandSummary,
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privRunCommandIn) envelope.Envelope[CommandOutput] {
			// Only a call that previewed reaches this, with the preview's hash
			// and unit; the helper refuses an unbound operator command anyway.
			if in.expectedPreview == "" || in.unit == "" {
				return envelope.Failure[CommandOutput](in.Target, envelope.Errorf("internal", "a privileged command needs the hash and unit of its preview; nothing was sent"))
			}
			w := privExecWire{CommandID: in.CommandID, Args: in.Args, Cwd: in.Cwd, Unit: in.unit, ExpectedPreviewSHA256: in.expectedPreview}
			if in.MaxOutputBytes != nil {
				w.MaxOutputBytes = *in.MaxOutputBytes
			}
			env := d.runExec(ctx, protocol.OpPrivExec, in.Target, &w, in.timeoutArg, in.outputArg)
			if ceiling, _ := ctx.Value(ceilingKey{}).(Tier); env.OK && env.Exec != nil && env.Exec.TimedOut && ceiling > TierRead {
				env.Warnings = append(env.Warnings, "the command was stopped at its timeout after it had started; what it changed before then is unknown: check on the host before running it again")
			}
			return env
		},
		approvalArgs: func(in privRunCommandIn) any {
			args := in.Args
			if args == nil {
				args = []string{}
			}
			cwd := in.Cwd
			if cwd == "" {
				cwd = "/"
			}
			return struct {
				CommandID      string   `json:"command_id"`
				Args           []string `json:"args"`
				Cwd            string   `json:"cwd"`
				TimeoutSeconds int      `json:"timeout_seconds"`
				MaxOutputBytes int      `json:"max_output_bytes"`
			}{in.CommandID, args, cwd, d.timeoutDefault(in.timeoutArg), d.outputDefault(in.outputArg)}
		},
		describe: func(in privRunCommandIn, target string) string {
			return "As root, run command " + in.CommandID + " with " + plural(len(in.Args), "argument", "arguments") + " on " + target
		},
		describePreview: func(in privRunCommandIn, target string, p *preview) string {
			return "As root, run command " + in.CommandID + " with " + plural(len(in.Args), "argument", "arguments") + " in the " + p.unit + " unit on " + target
		},
		preview: func(ctx context.Context, in privRunCommandIn, target string) (*preview, *envelope.Error) {
			return d.privRunCommandPreview(ctx, &in, target)
		},
		precondition: func(in *privRunCommandIn, p *preview) {
			in.expectedPreview, in.unit = p.contentSHA256, p.unit
		},
		tierFromPreview: true,
		precheck: func(in *privRunCommandIn) *envelope.Error {
			if _, e := d.timeoutFor(in.timeoutArg); e != nil {
				return e
			}
			_, e := d.outputLimit(in.outputArg)
			return e
		},
	})
}

// privRunCommandPreview is shell_priv_run_command's preview: the helper's
// priv_exec_preview, which resolves the command exactly as priv_exec will
// (its tier against the tool's ceiling and the privileged policy's
// max_tier, the template the arguments match, path placeholders and the
// cwd resolved on the host) and runs nothing: the command id, tier, unit,
// description, root_equivalent flag, capabilities, the matched template,
// the resolved argv and cwd, and preview_sha256, bound with both policies'
// hashes. The hash and the unit the call then sends are taken from the
// helper's answer before the server's redaction.
func (d *Deps) privRunCommandPreview(ctx context.Context, in *privRunCommandIn, target string) (*preview, *envelope.Error) {
	args := in.Args
	if args == nil {
		args = []string{}
	}
	resp, e := d.call(ctx, target, protocol.OpPrivExecPreview, execPreviewArgsWire{CommandID: in.CommandID, Args: args, Cwd: in.Cwd}, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[privExecPreviewWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	policy, e := privPolicy(resp)
	if e != nil {
		return nil, e
	}
	hash, unit := env.Data.PreviewSHA256, env.Data.Unit
	if !sha256RE.MatchString(hash) {
		return nil, envelope.Errorf("internal", "the helper's preview has no valid preview_sha256")
	}
	if unit != "core" && unit != "broad" {
		return nil, envelope.Errorf("internal", "the helper's preview names no known unit")
	}
	tier, ok := map[string]Tier{"read": TierRead, "operator": TierOperator, "destructive": TierDestructive}[env.Data.Tier]
	if !ok {
		return nil, envelope.Errorf("internal", "the helper's preview names no known tier")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	for _, l := range []*[]string{&x.Capabilities, &x.Template, &x.Argv} {
		if *l == nil {
			*l = []string{}
		}
	}
	value := map[string]any{"command_id": x.CommandID, "tier": x.Tier, "unit": unit, "description": x.Description, "root_equivalent": x.RootEquivalent,
		"capabilities": x.Capabilities, "template": x.Template, "argv": x.Argv, "cwd": x.Cwd, "preview_sha256": hash}
	return &preview{value: value, policy: policy, contentSHA256: hash, tier: tier, unit: unit}, nil
}
