// Package tools holds the tool registry. Tools are registered once at startup
// for the server's profile; tools outside the profile are never added to the
// MCP server (D-005). Domain tool files arrive in Sessions 2–4.
package tools

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tier is a property of an operation (plan "Definitions").
type Tier int

// Tiers, in increasing order of consequence.
const (
	TierRead Tier = iota + 1
	TierOperator
	TierDestructive
)

func (t Tier) String() string {
	switch t {
	case TierRead:
		return "read"
	case TierOperator:
		return "operator"
	case TierDestructive:
		return "destructive"
	}
	return fmt.Sprintf("tier(%d)", int(t))
}

func (t Tier) valid() bool { return t >= TierRead && t <= TierDestructive }

// Profile is a property of a running server; it selects which tiers are
// registered.
type Profile string

// Profiles.
const (
	ProfileReadOnly Profile = "read-only"
	ProfileOperator Profile = "operator"
	ProfileAdmin    Profile = "admin"
)

// ParseProfile returns the Profile named s.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(s); p {
	case ProfileReadOnly, ProfileOperator, ProfileAdmin:
		return p, nil
	}
	return "", fmt.Errorf("unknown profile %q", s)
}

// maxTier is the highest unprivileged tier a profile registers.
func (p Profile) maxTier() Tier {
	switch p {
	case ProfileReadOnly:
		return TierRead
	case ProfileOperator:
		return TierOperator
	case ProfileAdmin:
		return TierDestructive
	}
	return 0
}

// Tool is one registrable tool: its definition and a function that adds it,
// with its handler, to an MCP server.
type Tool struct {
	Def     *mcp.Tool
	Install func(*mcp.Server)
}

// Registration is a tool with its tier and privileged flag.
type Registration struct {
	Tool       Tool
	Tier       Tier
	Privileged bool
}

// Registry is the set of all tools the binary knows. It is built at startup
// and not modified afterwards.
type Registry struct {
	regs []Registration
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

var toolNameRE = regexp.MustCompile(`^shell_[a-z0-9]+(_[a-z0-9]+)+$`)

const privPrefix = "shell_priv_"

// Register adds a tool with an explicit tier. Privileged tools (shell_priv_*)
// are forwarded to the host's privileged helper and are only registered in
// the admin profile.
func (r *Registry) Register(tool Tool, tier Tier, privileged bool) error {
	if tool.Def == nil || tool.Install == nil {
		return errors.New("tools: registration needs a definition and an installer")
	}
	name := tool.Def.Name
	if !toolNameRE.MatchString(name) {
		return fmt.Errorf("tools: %q is not a shell_<verb>_<noun> name", name)
	}
	if !tier.valid() {
		return fmt.Errorf("tools: %s: invalid tier %s", name, tier)
	}
	if privileged != strings.HasPrefix(name, privPrefix) {
		return fmt.Errorf("tools: %s: privileged tools, and only they, are named %s*", name, privPrefix)
	}
	if slices.ContainsFunc(r.regs, func(g Registration) bool { return g.Tool.Def.Name == name }) {
		return fmt.Errorf("tools: %s registered twice", name)
	}
	r.regs = append(r.regs, Registration{Tool: tool, Tier: tier, Privileged: privileged})
	return nil
}

// ToolsForProfile returns, sorted by name, the registrations profile p may
// expose, minus the names in disabled: read-only → read; operator → read and
// operator; admin → everything, including every privileged tool. An unknown
// profile gets nothing.
func (r *Registry) ToolsForProfile(p Profile, disabled []string) []Registration {
	limit := p.maxTier()
	out := []Registration{}
	for _, g := range r.regs {
		if limit == 0 || g.Tier > limit || slices.Contains(disabled, g.Tool.Def.Name) {
			continue
		}
		if g.Privileged && p != ProfileAdmin {
			continue
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b Registration) int { return strings.Compare(a.Tool.Def.Name, b.Tool.Def.Name) })
	return out
}
