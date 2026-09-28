//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"net/url"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

type helloData struct {
	GateVersion  string         `json:"gate_version"`
	Protocol     int            `json:"protocol"`
	Principal    string         `json:"principal"`
	PolicySHA256 string         `json:"policy_sha256"`
	MaxTier      string         `json:"max_tier"`
	Ops          []string       `json:"ops"`
	Sandbox      sandbox.Report `json:"sandbox"`
	Privileged   privSummary    `json:"privileged"`
}

type privSummary struct {
	Enabled bool   `json:"enabled"`
	MaxTier string `json:"max_tier"`
}

func (s *server) hello(raw jsontext.Value) (any, []string, error) {
	var a noArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	table := opTable()
	ops := []string{}
	for _, op := range opOrder {
		if table[op].tier <= s.p.MaxTier {
			ops = append(ops, op)
		}
	}
	for _, c := range s.p.Commands {
		if c.Tier <= s.p.MaxTier {
			ops = append(ops, protocol.OpExec)
			break
		}
	}
	return helloData{
		GateVersion: s.o.Version, Protocol: protocol.Version, Principal: s.o.Principal,
		PolicySHA256: s.p.SHA256, MaxTier: s.p.MaxTier.String(), Ops: ops, Sandbox: s.report,
		Privileged: privSummary{Enabled: s.p.Privileged.Enabled, MaxTier: s.p.Privileged.MaxTier.String()},
	}, nil, nil
}

// Summary is the effective policy as the policy op and check-policy show
// it. It is built from the validated policy, never from the file bytes, and
// leaves out command paths, redaction patterns and remote credentials.
type Summary struct {
	Version    int             `json:"version"`
	MaxTier    string          `json:"max_tier"`
	SHA256     string          `json:"sha256"`
	Sandbox    sandboxSummary  `json:"sandbox"`
	Limits     policy.Limits   `json:"limits"`
	Paths      pathsSummary    `json:"paths"`
	Services   servicesSummary `json:"services"`
	Journal    journalSummary  `json:"journal"`
	Git        gitSummary      `json:"git"`
	Privileged privSummary     `json:"privileged"`
	Redact     int             `json:"redact_patterns"`
	Commands   []cmdSummary    `json:"commands"`
}

type sandboxSummary struct {
	Landlock        string   `json:"landlock"`
	SystemReadExec  []string `json:"system_read_exec"`
	TCPConnectPorts []uint16 `json:"tcp_connect_ports"`
}

type pathsSummary struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
	// Deny is the policy's own patterns; the built-in list always applies.
	Deny []string `json:"deny"`
}

type servicesSummary struct {
	Status       []string `json:"status"`
	ControlUnits []string `json:"control_units"`
	ControlVerbs []string `json:"control_verbs"`
}

type journalSummary struct {
	Units    []string `json:"units"`
	MaxLines int      `json:"max_lines"`
}

type gitSummary struct {
	Repos []repoSummary `json:"repos"`
}

type repoSummary struct {
	Path   string `json:"path"`
	Remote string `json:"remote"`
}

type cmdSummary struct {
	ID             string     `json:"id"`
	Description    string     `json:"description"`
	Tier           string     `json:"tier"`
	RootEquivalent bool       `json:"root_equivalent"`
	Templates      [][]string `json:"templates"`
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// redactRemote removes userinfo (credentials) from a remote URL.
func redactRemote(r string) string {
	u, err := url.Parse(r)
	if err != nil || u.User == nil {
		return r
	}
	u.User = url.User("REDACTED")
	return u.String()
}

// PolicySummary builds the Summary for a validated policy.
func PolicySummary(p *policy.Policy) Summary {
	s := Summary{
		Version: policy.SchemaVersion, MaxTier: p.MaxTier.String(), SHA256: p.SHA256,
		Sandbox: sandboxSummary{Landlock: string(p.Sandbox.Landlock), SystemReadExec: orEmpty(p.Sandbox.SystemReadExec),
			TCPConnectPorts: orEmpty(p.Sandbox.TCPConnectPorts)},
		Limits:     p.Limits,
		Paths:      pathsSummary{Read: orEmpty(p.Paths.Read), Write: orEmpty(p.Paths.Write), Deny: orEmpty(p.Paths.DenyUser)},
		Services:   servicesSummary{Status: orEmpty(p.Services.Status), ControlUnits: orEmpty(p.Services.ControlUnits), ControlVerbs: orEmpty(p.Services.ControlVerbs)},
		Journal:    journalSummary{Units: orEmpty(p.Journal.Units), MaxLines: p.Journal.MaxLines},
		Git:        gitSummary{Repos: []repoSummary{}},
		Privileged: privSummary{Enabled: p.Privileged.Enabled, MaxTier: p.Privileged.MaxTier.String()},
		Redact:     len(p.Redact),
		Commands:   []cmdSummary{},
	}
	for _, r := range p.Git.Repos {
		s.Git.Repos = append(s.Git.Repos, repoSummary{Path: r.Path, Remote: redactRemote(r.Remote)})
	}
	for _, c := range p.Commands {
		cs := cmdSummary{ID: c.ID, Description: c.Description, Tier: c.Tier.String(), RootEquivalent: c.RootEquivalent, Templates: [][]string{}}
		for _, t := range c.Templates {
			cs.Templates = append(cs.Templates, t.String())
		}
		s.Commands = append(s.Commands, cs)
	}
	return s
}

func (s *server) policySummary(raw jsontext.Value) (any, []string, error) {
	var a noArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	return PolicySummary(s.p), nil, nil
}
