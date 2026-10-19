package tools

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/tyler-rich/shell-mcp/internal/approval"
	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// Deps are what tools need at call time. A zero Deps is enough to build the
// catalogue (definitions and schemas) without serving it.
type Deps struct {
	Targets       []config.Target
	DefaultTarget string
	// Opener returns the SSH client of a configured target.
	Opener         func(target string) (gateclient.Opener, bool)
	Gate           *gateclient.Client
	Principal      auth.Principal
	Logger         *slog.Logger
	DefaultTimeout time.Duration
	// MaxTimeout bounds a tool's timeout_seconds (SHELL_MCP_MAX_TIMEOUT).
	MaxTimeout time.Duration
	// MaxOutputBytes caps what a tool returns per output stream
	// (SHELL_MCP_MAX_OUTPUT_BYTES).
	MaxOutputBytes int
	// Redactor holds the built-in rules and SHELL_MCP_REDACT_PATTERNS.
	Redactor *redact.Redactor
	// ApprovalTiers is SHELL_MCP_APPROVAL_TIERS: the tiers whose tools need
	// a human approval (D-006); destructive tools always do.
	ApprovalTiers []string
	// ApprovalMethod is SHELL_MCP_APPROVAL_METHOD (empty: none).
	ApprovalMethod approval.Method
	// Approvals is the approval store (web and confirm-argument).
	Approvals *approval.Store
	// ApprovalPublicURL is SHELL_MCP_APPROVAL_PUBLIC_URL's origin (web).
	ApprovalPublicURL string
	// Notify, when set, is called for each new approval record.
	Notify func(*approval.Record, string)
}

// Catalogue returns the registry of every tool this binary knows, each with
// its tier. The server installs the profile's subset (ToolsForProfile).
func Catalogue(d *Deps) (*Registry, error) {
	r := NewRegistry()
	for _, reg := range []struct {
		tool Tool
		tier Tier
	}{
		{listTargets(d), TierRead},
		{getPolicy(d), TierRead},
		{getSystemInfo(d), TierRead},
		{getDiskUsage(d), TierRead},
		{listProcesses(d), TierRead},
		{getServiceStatus(d), TierRead},
		{listServices(d), TierRead},
		{getJournal(d), TierRead},
		{listDirectory(d), TierRead},
		{statPath(d), TierRead},
		{readFile(d), TierRead},
		{findFiles(d), TierRead},
		{inspectCertificate(d), TierRead},
		{getGitStatus(d), TierRead},
		{getGitLog(d), TierRead},
		{getGitDiff(d), TierRead},
		{runReadCommand(d), TierRead},
		{previewDelete(d), TierRead},
		{previewGitDiscard(d), TierRead},
		{controlService(d), TierOperator},
		{writeFile(d), TierOperator},
		{makeDirectory(d), TierOperator},
		{copyPath(d), TierOperator},
		{movePath(d), TierOperator},
		{setPermissions(d), TierOperator},
		{gitPull(d), TierOperator},
		{deletePath(d), TierDestructive},
		{discardGitChanges(d), TierDestructive},
	} {
		if err := r.Register(reg.tool, reg.tier, false); err != nil {
			return nil, err
		}
	}
	// Privileged tools: admin only, each at the tier it is defined with.
	for _, tool := range privilegedTools(d) {
		if err := r.Register(tool, tool.Tier, true); err != nil {
			return nil, err
		}
	}
	// shell_run_command: at operator in the operator profile, at destructive
	// (every call approval-gated) in admin.
	if err := r.RegisterFor(runCommand(d, TierOperator), TierOperator, []Profile{ProfileOperator}); err != nil {
		return nil, err
	}
	if err := r.RegisterFor(runCommand(d, TierDestructive), TierDestructive, []Profile{ProfileAdmin}); err != nil {
		return nil, err
	}
	if err := registerDiag(r, d); err != nil {
		return nil, err
	}
	return r, nil
}

// targetArg is the common optional `target` input.
type targetArg struct {
	Target string `json:"target,omitzero" jsonschema:"Name of the configured target (1-63 characters: lowercase letters, digits, - and _). Optional when exactly one target is configured or a default target is set."`
}

const targetPattern = `^[a-z0-9][a-z0-9_-]{0,62}$`

var targetRE = regexp.MustCompile(targetPattern)

func boundTarget(s *jsonschema.Schema) {
	if p := s.Properties["target"]; p != nil {
		p.Pattern = targetPattern
		p.MaxLength = new(63)
	}
}

// resolve picks the target a call names, or the only or default one.
func (d *Deps) resolve(name string) (config.Target, *envelope.Error) {
	if name == "" {
		switch {
		case len(d.Targets) == 1:
			return d.Targets[0], nil
		case d.DefaultTarget != "":
			name = d.DefaultTarget
		default:
			return config.Target{}, envelope.Errorf(envelope.CodeValidationError, "target is required: several targets are configured and none is the default")
		}
	}
	if !targetRE.MatchString(name) {
		return config.Target{}, envelope.Errorf(envelope.CodeValidationError, "target must match %s", targetPattern)
	}
	i := slices.IndexFunc(d.Targets, func(t config.Target) bool { return t.Name == name })
	if i < 0 {
		return config.Target{}, envelope.Errorf(envelope.CodeUnknownTarget, "no target named %q is configured", name)
	}
	return d.Targets[i], nil
}

// ceilingKey carries the calling tool's tier in a handler's context.
type ceilingKey struct{}

// withCeiling marks ctx with the tier of the tool handling the call (define
// does this for every tool). Every gate request made under ctx carries
// that tier as its ceiling, so the gate and the helper refuse anything
// above the tool's tier in the same check as their max_tier.
func withCeiling(ctx context.Context, t Tier) context.Context {
	return context.WithValue(ctx, ceilingKey{}, t)
}

// call sends one gate request to target at the ceiling ctx carries; a
// context without one sends nothing. A transport or protocol failure is
// the returned error; a gate failure is a response with ok false.
func (d *Deps) call(ctx context.Context, target, op string, args any, budget time.Duration) (*protocol.Response, *envelope.Error) {
	ceiling, _ := ctx.Value(ceilingKey{}).(Tier)
	if !ceiling.valid() {
		return nil, envelope.Errorf("internal", "the gate request has no tier ceiling")
	}
	var o gateclient.Opener
	ok := false
	if d.Opener != nil {
		o, ok = d.Opener(target)
	}
	if !ok || d.Gate == nil {
		return nil, envelope.Errorf(envelope.CodeTargetUnreachable, "no SSH client for the target")
	}
	resp, err := d.Gate.Call(ctx, o, op, ceiling.String(), args, budget)
	if err != nil {
		return nil, envelope.AsError(err)
	}
	return resp, nil
}

func (d *Deps) budget() time.Duration {
	if d.DefaultTimeout > 0 {
		return d.DefaultTimeout
	}
	return 30 * time.Second
}

// ProbeResult is what a target's gate says in its hello.
type ProbeResult struct {
	Gate       GateHello     `json:"gate"`
	Sandbox    SandboxStatus `json:"sandbox"`
	Privileged Privileged    `json:"privileged"`
}

// Probe calls the target's gate hello (shell-mcp check), a read request.
func Probe(ctx context.Context, d *Deps, target string) (*ProbeResult, *envelope.Error) {
	resp, e := d.call(withCeiling(ctx, TierRead), target, protocol.OpHello, nil, d.budget())
	if e != nil {
		return nil, e
	}
	h := envelope.FromGate[helloWire](target, resp)
	if !h.OK {
		return nil, h.Error
	}
	return &ProbeResult{
		Gate: GateHello{Version: h.Data.GateVersion, Protocol: h.Data.Protocol, Principal: h.Data.Principal,
			PolicySHA256: h.Data.PolicySHA256, MaxTier: h.Data.MaxTier, Ops: h.Data.Ops},
		Sandbox: h.Data.Sandbox, Privileged: h.Data.Privileged,
	}, nil
}

// EffectiveTools are the names among regs (a profile's tools) that a target
// whose gate allows maxTier, with privileged forwarding on or off, can
// serve.
func EffectiveTools(regs []Registration, maxTier string, privileged bool) []string {
	limit := map[string]Tier{"read": TierRead, "operator": TierOperator, "destructive": TierDestructive}[maxTier]
	out := []string{}
	for _, r := range regs {
		if r.Tier <= limit && (!r.Privileged || privileged) {
			out = append(out, r.Tool.Def.Name)
		}
	}
	return out
}
