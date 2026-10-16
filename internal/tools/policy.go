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
	Gate       GateHello     `json:"gate" jsonschema:"The gate that answered."`
	Sandbox    SandboxStatus `json:"sandbox" jsonschema:"The gate's kernel sandbox for this request: Landlock ABI and what is enforced."`
	Privileged Privileged    `json:"privileged" jsonschema:"Whether privileged operations are forwarded to the host's privileged helper, and their highest tier."`
	Policy     Policy        `json:"policy" jsonschema:"The target's effective gate policy (never the file's bytes)."`
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
			out := envelope.Success(t.Name, PolicyData{
				Gate: GateHello{Version: h.GateVersion, Protocol: h.Protocol, Principal: h.Principal,
					PolicySHA256: h.PolicySHA256, MaxTier: h.MaxTier, Ops: h.Ops},
				Sandbox:    h.Sandbox,
				Privileged: h.Privileged,
				Policy: Policy{Version: s.Version, MaxTier: s.MaxTier, SHA256: s.SHA256, Sandbox: s.Sandbox,
					Limits: Limits(s.Limits), Paths: s.Paths, Services: s.Services, Journal: s.Journal,
					Git: s.Git, RedactPatterns: s.Redact, Commands: s.Commands},
			})
			out.Gate = sum.Gate
			out.Warnings = slices.Concat(hello.Warnings, sum.Warnings)
			if h.PolicySHA256 != s.SHA256 {
				out.Warnings = append(out.Warnings, "the policy changed between the hello and policy requests")
			}
			return out
		},
	})
}
