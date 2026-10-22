package tools

import (
	"context"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Wire forms of the gate's hello and policy data (internal/gate/ops,
// summary.go), decoded strictly: a field this server does not know is a
// protocol mismatch, so it never forwards what its output schema does not
// describe. The policy's limits carry the gate's Go field names.

type helloWire struct {
	GateVersion  string        `json:"gate_version"`
	Protocol     int           `json:"protocol"`
	Principal    string        `json:"principal"`
	PolicySHA256 string        `json:"policy_sha256"`
	MaxTier      string        `json:"max_tier"`
	Ops          []string      `json:"ops"`
	Sandbox      SandboxStatus `json:"sandbox"`
	Privileged   Privileged    `json:"privileged"`
}

type summaryWire struct {
	Version    int           `json:"version"`
	MaxTier    string        `json:"max_tier"`
	SHA256     string        `json:"sha256"`
	Sandbox    PolicySandbox `json:"sandbox"`
	Limits     limitsWire    `json:"limits"`
	Paths      Paths         `json:"paths"`
	Services   Services      `json:"services"`
	Journal    Journal       `json:"journal"`
	Git        Git           `json:"git"`
	Privileged Privileged    `json:"privileged"`
	Redact     int           `json:"redact_patterns"`
	Commands   []Command     `json:"commands"`
}

type limitsWire struct {
	DefaultTimeoutS  int `json:"DefaultTimeoutS"`
	MaxTimeoutS      int `json:"MaxTimeoutS"`
	MaxOutputBytes   int `json:"MaxOutputBytes"`
	MaxStdinBytes    int `json:"MaxStdinBytes"`
	MaxReadBytes     int `json:"MaxReadBytes"`
	MaxWriteBytes    int `json:"MaxWriteBytes"`
	MaxFindResults   int `json:"MaxFindResults"`
	MaxFindDepth     int `json:"MaxFindDepth"`
	MaxDeleteEntries int `json:"MaxDeleteEntries"`
	MaxProcesses     int `json:"MaxProcesses"`
}

// PolicyData is shell_get_policy's data.
type PolicyData struct {
	Gate       GateHello        `json:"gate" jsonschema:"The gate that answered."`
	Sandbox    SandboxStatus    `json:"sandbox" jsonschema:"The gate's kernel sandbox for this request: Landlock ABI and what is enforced."`
	Privileged PrivilegedStatus `json:"privileged" jsonschema:"Whether privileged operations are forwarded to the host's privileged helper, their highest tier, and the helper's policy."`
	Policy     Policy           `json:"policy" jsonschema:"The target's effective gate policy (never the file's bytes)."`
}

// PrivilegedStatus is the forwarding status with, in the admin profile, the
// privileged helper's policy summary.
type PrivilegedStatus struct {
	Enabled bool        `json:"enabled" jsonschema:"Whether privileged operations are forwarded."`
	MaxTier string      `json:"max_tier" jsonschema:"Highest privileged tier the gate forwards."`
	Policy  *PrivPolicy `json:"policy,omitempty" jsonschema:"The privileged helper's effective policy, from the policy it enforces (admin profile, forwarding enabled). Absent otherwise, or when the helper did not answer (a warning says why)."`
}

// PrivPolicy is the privileged policy summary (priv_policy, handoff P-8):
// never the policy's deny patterns (only their count) or acknowledge text.
type PrivPolicy struct {
	PolicySHA256         string        `json:"policy_sha256" jsonschema:"SHA-256 of the privileged policy file (the helper's; the gate policy's is gate.policy_sha256)."`
	MaxTier              string        `json:"max_tier" jsonschema:"Highest tier the privileged policy allows: read, operator or destructive."`
	Limits               PrivLimits    `json:"limits" jsonschema:"The privileged policy's size, count and time limits."`
	Roots                PrivRoots     `json:"roots" jsonschema:"Roots root may read and write."`
	DenyPatterns         int           `json:"deny_patterns" jsonschema:"Number of the privileged policy's own deny patterns (their values are never shown; the built-in deny list always applies)."`
	Owners               PrivOwners    `json:"owners" jsonschema:"The only users and groups chown may set."`
	ModesMax             string        `json:"modes_max" jsonschema:"Octal mask no mode set as root may exceed."`
	BackupsKeep          int           `json:"backups_keep" jsonschema:"Backups kept per file (0: none are written)."`
	BackupsMaxStoreBytes int64         `json:"backups_max_store_bytes" jsonschema:"Size cap of the whole backup store in bytes."`
	Commands             []PrivCommand `json:"commands" jsonschema:"Declared root commands with their unit, tier and argument templates."`
	Packages             PrivPackages  `json:"packages" jsonschema:"The package operations' allow-lists and switches."`
	Power                PrivPower     `json:"power" jsonschema:"The power actions the policy allows."`
	Ops                  []PrivOp      `json:"ops" jsonschema:"Privileged operations this policy allows, with the tier and unit each runs at."`
	Findings             []PrivFinding `json:"findings" jsonschema:"Declared commands whose program bypasses a bound operation (a package tool, a power binary, find with an action), each acknowledged by the host owner."`
}

// PrivLimits are the privileged policy's limits.
type PrivLimits struct {
	MaxReadBytes     int `json:"max_read_bytes" jsonschema:"File read cap in bytes."`
	MaxWriteBytes    int `json:"max_write_bytes" jsonschema:"File write cap in bytes."`
	MaxOutputBytes   int `json:"max_output_bytes" jsonschema:"Command output cap per stream in bytes."`
	DefaultTimeoutS  int `json:"default_timeout_s" jsonschema:"Default operation timeout in seconds."`
	MaxTimeoutS      int `json:"max_timeout_s" jsonschema:"Longest operation timeout in seconds."`
	MaxDeleteEntries int `json:"max_delete_entries" jsonschema:"Most entries of a recursive delete, chown or chmod."`
}

// PrivRoots are the privileged roots.
type PrivRoots struct {
	Read        []string `json:"read" jsonschema:"Read roots."`
	Write       []string `json:"write" jsonschema:"Write roots (also readable)."`
	Persistence []string `json:"persistence" jsonschema:"Write roots inside normally protected persistence areas."`
}

// PrivOwners are the owner allow-lists.
type PrivOwners struct {
	Users  []string `json:"users" jsonschema:"Users chown may set."`
	Groups []string `json:"groups" jsonschema:"Groups chown may set."`
}

// PrivCommand is one declared root command.
type PrivCommand struct {
	ID             string     `json:"id" jsonschema:"Command id."`
	Tier           string     `json:"tier" jsonschema:"read, operator or destructive."`
	Unit           string     `json:"unit" jsonschema:"The unit it runs in: core or broad."`
	Description    string     `json:"description" jsonschema:"The host owner's description."`
	Templates      [][]string `json:"templates" jsonschema:"Argument templates; placeholders are typed."`
	RootEquivalent bool       `json:"root_equivalent" jsonschema:"Whether the owner acknowledged the command as root-equivalent."`
	Capabilities   []string   `json:"capabilities" jsonschema:"Capabilities the command adds."`
	Approval       bool       `json:"approval" jsonschema:"Whether running it needs a human approval (operator and destructive commands always do)."`
}

// PrivPackages is the packages section.
type PrivPackages struct {
	Enabled          bool     `json:"enabled" jsonschema:"Whether package operations are enabled."`
	Install          []string `json:"install" jsonschema:"Packages that may be installed."`
	Remove           []string `json:"remove" jsonschema:"Packages that may be removed."`
	AllowUpdateIndex bool     `json:"allow_update_index" jsonschema:"Whether the package index may be updated."`
	AllowUpgrade     bool     `json:"allow_upgrade" jsonschema:"Whether installed packages may be upgraded."`
}

// PrivPower is the power section.
type PrivPower struct {
	Allowed []string `json:"allowed" jsonschema:"Allowed actions: reboot, poweroff."`
}

// PrivOp is one privileged operation the policy allows.
type PrivOp struct {
	Op       string `json:"op" jsonschema:"Helper operation."`
	Tier     string `json:"tier" jsonschema:"read, operator or destructive; command for priv_exec, whose tier is each command's."`
	Unit     string `json:"unit" jsonschema:"core or broad; command for priv_exec, which runs in each command's unit."`
	Approval bool   `json:"approval" jsonschema:"Whether it needs a human approval (privileged operator and destructive operations always do; for priv_exec see each command)."`
}

// PrivFinding is a command whose program bypasses a bound operation.
type PrivFinding struct {
	CommandID string `json:"command_id" jsonschema:"Command id."`
	Category  string `json:"category" jsonschema:"package (a package tool), power (a power binary) or exec (find with an action that runs, deletes or writes)."`
	Program   string `json:"program" jsonschema:"The program recognised."`
	Match     string `json:"match" jsonschema:"How it was recognised: written (the path's name), resolved (the name it resolves to), identity (a copy of that program) or template (find's action in a template)."`
}

// GateHello identifies the gate.
type GateHello struct {
	Version      string   `json:"version" jsonschema:"Gate version."`
	Protocol     int      `json:"protocol" jsonschema:"Wire protocol version."`
	Principal    string   `json:"principal" jsonschema:"The principal label the SSH key's forced command selects."`
	PolicySHA256 string   `json:"policy_sha256" jsonschema:"SHA-256 of the gate policy file."`
	MaxTier      string   `json:"max_tier" jsonschema:"Highest tier the policy allows: read, operator or destructive."`
	Ops          []string `json:"ops" jsonschema:"Gate operations available under max_tier."`
}

// SandboxStatus is the gate's sandbox report.
type SandboxStatus struct {
	Mode              string      `json:"mode" jsonschema:"Policy sandbox mode: required or best-effort."`
	KernelABI         int         `json:"kernel_abi" jsonschema:"Landlock ABI the kernel offers (0: none)."`
	EffectiveABI      int         `json:"effective_abi" jsonschema:"Landlock ABI applied."`
	RequiredMinABI    int         `json:"required_min_abi" jsonschema:"Lowest ABI the required mode accepts."`
	Applied           bool        `json:"applied" jsonschema:"Whether the sandbox was applied."`
	NoNewPrivs        bool        `json:"no_new_privs" jsonschema:"Whether no_new_privs is set on every thread."`
	Enforced          Enforcement `json:"enforced" jsonschema:"Which rule classes the kernel enforces."`
	NotEnforced       []string    `json:"not_enforced" jsonschema:"Rule classes not enforced on this kernel."`
	UnixSocketControl string      `json:"unix_socket_control" jsonschema:"What controls Unix-socket access."`
	TCPConnectPorts   []uint16    `json:"tcp_connect_ports" jsonschema:"TCP ports commands may connect to."`
	ExtraFiles        []string    `json:"extra_files" jsonschema:"Device files granted to commands."`
	MPTCP             string      `json:"mptcp" jsonschema:"How Multipath TCP sockets are handled."`
}

// Enforcement lists the Landlock rule classes.
type Enforcement struct {
	FS         bool `json:"fs" jsonschema:"Filesystem rules."`
	Net        bool `json:"net" jsonschema:"TCP bind and connect rules."`
	UnixSocket bool `json:"unix_socket" jsonschema:"Pathname Unix-socket rules."`
	Scope      bool `json:"scope" jsonschema:"Signal and abstract-socket scoping."`
}

// Privileged is the forwarding status.
type Privileged struct {
	Enabled bool   `json:"enabled" jsonschema:"Whether privileged operations are forwarded."`
	MaxTier string `json:"max_tier" jsonschema:"Highest privileged tier the gate forwards."`
}

// Policy is the effective gate policy.
type Policy struct {
	Version        int           `json:"version" jsonschema:"Policy schema version."`
	MaxTier        string        `json:"max_tier" jsonschema:"Highest tier the policy allows."`
	SHA256         string        `json:"sha256" jsonschema:"SHA-256 of the policy file."`
	Sandbox        PolicySandbox `json:"sandbox" jsonschema:"The policy's sandbox section."`
	Limits         Limits        `json:"limits" jsonschema:"Size, count and time limits."`
	Paths          Paths         `json:"paths" jsonschema:"Read and write roots and the policy's deny patterns (the built-in deny list always applies)."`
	Services       Services      `json:"services" jsonschema:"Unit patterns for status, and the exact units and verbs for control."`
	Journal        Journal       `json:"journal" jsonschema:"Units whose journal may be read."`
	Git            Git           `json:"git" jsonschema:"Allow-listed repositories."`
	RedactPatterns int           `json:"redact_patterns" jsonschema:"Number of the policy's own redaction patterns."`
	Commands       []Command     `json:"commands" jsonschema:"Declared commands with their argv templates and tiers."`
}

// PolicySandbox is the policy's sandbox section.
type PolicySandbox struct {
	Landlock        string   `json:"landlock" jsonschema:"required or best-effort."`
	SystemReadExec  []string `json:"system_read_exec" jsonschema:"Extra read+execute directories."`
	TCPConnectPorts []uint16 `json:"tcp_connect_ports" jsonschema:"TCP ports commands may connect to."`
}

// Limits are the policy's limits.
type Limits struct {
	DefaultTimeoutS  int `json:"default_timeout_s" jsonschema:"Default operation timeout in seconds."`
	MaxTimeoutS      int `json:"max_timeout_s" jsonschema:"Longest operation timeout in seconds."`
	MaxOutputBytes   int `json:"max_output_bytes" jsonschema:"Output cap per stream in bytes."`
	MaxStdinBytes    int `json:"max_stdin_bytes" jsonschema:"Stdin cap in bytes."`
	MaxReadBytes     int `json:"max_read_bytes" jsonschema:"File read cap in bytes."`
	MaxWriteBytes    int `json:"max_write_bytes" jsonschema:"File write cap in bytes."`
	MaxFindResults   int `json:"max_find_results" jsonschema:"Most results of a find."`
	MaxFindDepth     int `json:"max_find_depth" jsonschema:"Deepest find walk."`
	MaxDeleteEntries int `json:"max_delete_entries" jsonschema:"Most entries of a recursive delete."`
	MaxProcesses     int `json:"max_processes" jsonschema:"Most processes listed."`
}

// Paths are the policy's roots.
type Paths struct {
	Read  []string `json:"read" jsonschema:"Read roots."`
	Write []string `json:"write" jsonschema:"Write roots (also readable)."`
	Deny  []string `json:"deny" jsonschema:"The policy's own deny patterns."`
}

// Services is the policy's services section.
type Services struct {
	Status       []string `json:"status" jsonschema:"Unit patterns whose status may be read."`
	ControlUnits []string `json:"control_units" jsonschema:"Exact units that may be controlled."`
	ControlVerbs []string `json:"control_verbs" jsonschema:"Allowed control verbs."`
}

// Journal is the policy's journal section.
type Journal struct {
	Units    []string `json:"units" jsonschema:"Units whose journal may be read."`
	MaxLines int      `json:"max_lines" jsonschema:"Most journal lines per read."`
}

// Git is the policy's git section.
type Git struct {
	Repos []Repo `json:"repos" jsonschema:"Allow-listed repositories."`
}

// Repo is one repository.
type Repo struct {
	Path   string `json:"path" jsonschema:"Repository path on the target."`
	Remote string `json:"remote" jsonschema:"The https remote pulls must use (credentials removed)."`
}

// Command is one declared command.
type Command struct {
	ID             string     `json:"id" jsonschema:"Command id."`
	Description    string     `json:"description" jsonschema:"The host owner's description."`
	Tier           string     `json:"tier" jsonschema:"read, operator or destructive."`
	RootEquivalent bool       `json:"root_equivalent" jsonschema:"Whether the owner acknowledged the command as root-equivalent."`
	Templates      [][]string `json:"templates" jsonschema:"Argument templates; placeholders are typed."`
}

func getPolicy(d *Deps) Tool {
	return define(d, spec[targetArg, PolicyData]{
		name:        "shell_get_policy",
		title:       "Get target policy",
		description: "Returns a target gate's version, principal, sandbox status and effective policy: roots, limits, services, repositories, commands with their templates, and privileged forwarding.",
		tier:        TierRead,
		schema:      boundTarget,
		audit:       func(in targetArg) map[string]any { return map[string]any{"target": in.Target} },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in targetArg) envelope.Envelope[PolicyData] {
			t, e := d.resolve(in.Target)
			if e != nil {
				return envelope.Failure[PolicyData](in.Target, e)
			}
			resp, e := d.call(ctx, t.Name, protocol.OpHello, nil, d.budget())
			if e != nil {
				return envelope.Failure[PolicyData](t.Name, e)
			}
			hello := envelope.FromGate[helloWire](t.Name, resp)
			if !hello.OK {
				return envelope.Failure[PolicyData](t.Name, hello.Error)
			}
			if resp, e = d.call(ctx, t.Name, protocol.OpPolicy, nil, d.budget()); e != nil {
				return envelope.Failure[PolicyData](t.Name, e)
			}
			sum := envelope.FromGate[summaryWire](t.Name, resp)
			if !sum.OK {
				return envelope.Failure[PolicyData](t.Name, sum.Error)
			}
			h, s := hello.Data, sum.Data
			// The privileged helper's summary, in the admin profile only (the
			// profile that registers privileged tools) and only when this gate
			// forwards privileged operations; a failure leaves the gate policy
			// reported, with a warning.
			var priv *PrivPolicy
			var privWarn []string
			if d.Principal.Profile == string(ProfileAdmin) && h.Privileged.Enabled {
				priv, privWarn = d.privPolicy(ctx, t.Name)
			}
			out := envelope.Success(t.Name, PolicyData{
				Gate: GateHello{Version: h.GateVersion, Protocol: h.Protocol, Principal: h.Principal,
					PolicySHA256: h.PolicySHA256, MaxTier: h.MaxTier, Ops: h.Ops},
				Sandbox:    h.Sandbox,
				Privileged: PrivilegedStatus{Enabled: h.Privileged.Enabled, MaxTier: h.Privileged.MaxTier, Policy: priv},
				Policy: Policy{Version: s.Version, MaxTier: s.MaxTier, SHA256: s.SHA256, Sandbox: s.Sandbox,
					Limits: Limits(s.Limits), Paths: s.Paths, Services: s.Services, Journal: s.Journal,
					Git: s.Git, RedactPatterns: s.Redact, Commands: s.Commands},
			})
			out.Gate = sum.Gate
			out.Warnings = slices.Concat(hello.Warnings, sum.Warnings, privWarn)
			if h.PolicySHA256 != s.SHA256 {
				out.Warnings = append(out.Warnings, "the policy changed between the hello and policy requests")
			}
			return out
		},
	})
}

// privPolicyWire is the helper's priv_policy data (handoff P-8), decoded
// strictly: a field this server does not know is a protocol mismatch.
type privPolicyWire struct {
	PolicySHA256         string        `json:"policy_sha256"`
	MaxTier              string        `json:"max_tier"`
	Limits               PrivLimits    `json:"limits"`
	Roots                PrivRoots     `json:"roots"`
	DenyPatterns         int           `json:"deny_patterns"`
	Owners               PrivOwners    `json:"owners"`
	ModesMax             string        `json:"modes_max"`
	BackupsKeep          int           `json:"backups_keep"`
	BackupsMaxStoreBytes int64         `json:"backups_max_store_bytes"`
	Commands             []privCmdWire `json:"commands"`
	Packages             PrivPackages  `json:"packages"`
	Power                PrivPower     `json:"power"`
	Ops                  []privOpWire  `json:"ops"`
	Findings             []PrivFinding `json:"findings"`
}

type privCmdWire struct {
	ID             string     `json:"id"`
	Tier           string     `json:"tier"`
	Unit           string     `json:"unit"`
	Description    string     `json:"description"`
	Templates      [][]string `json:"templates"`
	RootEquivalent bool       `json:"root_equivalent"`
	Capabilities   []string   `json:"capabilities"`
}

type privOpWire struct {
	Op   string `json:"op"`
	Tier string `json:"tier"`
	Unit string `json:"unit"`
}

// privApproval is D-006's rule for a privileged tier: operator and
// destructive always need a human approval, read never.
func privApproval(tier string) bool {
	return tier == TierOperator.String() || tier == TierDestructive.String()
}

// privPolicy asks the helper for its policy summary (priv_policy, at the
// tool's read ceiling) and returns it, or nil and a warning saying why not:
// a refusal, an answer without the helper's block, or a summary whose hash
// is not that block's.
func (d *Deps) privPolicy(ctx context.Context, target string) (*PrivPolicy, []string) {
	const what = "the privileged policy summary is not shown: "
	resp, e := d.call(ctx, target, protocol.OpPrivPolicy, nil, d.budget())
	if e != nil {
		return nil, []string{what + e.Code + ": " + e.Message}
	}
	env := envelope.FromGate[privPolicyWire](target, resp)
	if !env.OK {
		return nil, []string{what + env.Error.Code + ": " + env.Error.Message}
	}
	if resp.Helper == nil || resp.Helper.PolicySHA256 == "" {
		return nil, []string{what + "the answer carries no helper block"}
	}
	w := env.Data
	if w.PolicySHA256 != resp.Helper.PolicySHA256 {
		return nil, []string{what + "its policy hash is not the helper block's"}
	}
	p := &PrivPolicy{
		PolicySHA256: w.PolicySHA256, MaxTier: w.MaxTier, Limits: w.Limits, Roots: w.Roots, DenyPatterns: w.DenyPatterns,
		Owners: w.Owners, ModesMax: w.ModesMax, BackupsKeep: w.BackupsKeep, BackupsMaxStoreBytes: w.BackupsMaxStoreBytes,
		Commands: []PrivCommand{}, Packages: w.Packages, Power: w.Power, Ops: []PrivOp{}, Findings: w.Findings,
	}
	for _, c := range w.Commands {
		p.Commands = append(p.Commands, PrivCommand{ID: c.ID, Tier: c.Tier, Unit: c.Unit, Description: c.Description, Templates: c.Templates,
			RootEquivalent: c.RootEquivalent, Capabilities: c.Capabilities, Approval: privApproval(c.Tier)})
	}
	for _, o := range w.Ops {
		p.Ops = append(p.Ops, PrivOp{Op: o.Op, Tier: o.Tier, Unit: o.Unit, Approval: privApproval(o.Tier)})
	}
	if p.Findings == nil {
		p.Findings = []PrivFinding{}
	}
	return p, env.Warnings
}
