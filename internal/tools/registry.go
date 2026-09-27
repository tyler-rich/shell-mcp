package tools

import (
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tier is an operation's tier.
type Tier int

// Tiers.
const (
	TierRead Tier = iota + 1
	TierOperator
	TierDestructive
)

// Profile is a server profile.
type Profile string

// Profiles.
const (
	ProfileReadOnly Profile = "read-only"
	ProfileOperator Profile = "operator"
	ProfileAdmin    Profile = "admin"
)

// Tool is one registrable tool.
type Tool struct {
	Def     *mcp.Tool
	Install func(*mcp.Server)
}

// Registration is a registered tool.
type Registration struct {
	Tool       Tool
	Tier       Tier
	Privileged bool
}

// Registry holds tools.
type Registry struct{}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a tool.
func (r *Registry) Register(_ Tool, _ Tier, _ bool) error { return errors.New("not implemented") }

// ToolsForProfile returns the tools for a profile.
func (r *Registry) ToolsForProfile(_ Profile, _ []string) []Registration { return nil }

// ParseProfile parses a profile.
func ParseProfile(_ string) (Profile, error) { return "", errors.New("not implemented") }
