// Package policy loads the gate policy strictly (docs/POLICY.md §1–§5):
// unknown keys, wrong types and duplicate keys are errors; roots, globs,
// services, repos, privileged forwarding and commands are validated; command
// binaries are resolved and ownership-checked; the hard-deny list and the
// protected-path set are applied.
package policy

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// SchemaVersion is the policy schema version this gate implements.
const SchemaVersion = 1

// MaxPolicyBytes bounds the policy file.
const MaxPolicyBytes = 1 << 20

// Tier is a property of an operation or command.
type Tier int

// Tiers, ordered.
const (
	TierRead Tier = iota + 1
	TierOperator
	TierDestructive
)

// ParseTier parses read | operator | destructive.
func ParseTier(s string) (Tier, error) {
	switch s {
	case "read":
		return TierRead, nil
	case "operator":
		return TierOperator, nil
	case "destructive":
		return TierDestructive, nil
	}
	return 0, fmt.Errorf("tier %q is not read, operator or destructive", s)
}

func (t Tier) String() string {
	switch t {
	case TierRead:
		return "read"
	case TierOperator:
		return "operator"
	case TierDestructive:
		return "destructive"
	}
	return "invalid"
}

// LandlockMode is sandbox.landlock.
type LandlockMode string

// Landlock modes.
const (
	LandlockRequired   LandlockMode = "required"
	LandlockBestEffort LandlockMode = "best-effort"
)

// Policy is a validated gate policy.
type Policy struct {
	MaxTier    Tier
	Sandbox    Sandbox
	Limits     Limits
	Paths      Paths
	Services   Services
	Journal    Journal
	Git        Git
	Privileged Privileged
	Redact     []*regexp.Regexp
	Commands   []Command
	// SHA256 is the lowercase hex SHA-256 of the policy file bytes.
	SHA256 string
	// ServiceHome is the service account's home directory (HOME for
	// commands; part of the protected set).
	ServiceHome string
	// Warnings are non-fatal findings for check-policy.
	Warnings []string
}

// Sandbox is the sandbox section.
type Sandbox struct {
	Landlock        LandlockMode
	SystemReadExec  []string
	TCPConnectPorts []uint16
}

// Limits is the limits section, with defaults applied.
type Limits struct {
	DefaultTimeoutS  int
	MaxTimeoutS      int
	MaxOutputBytes   int
	MaxStdinBytes    int
	MaxReadBytes     int
	MaxWriteBytes    int
	MaxFindResults   int
	MaxFindDepth     int
	MaxDeleteEntries int
	MaxProcesses     int
}

// Paths holds the roots, the deny matcher (built-ins plus policy
// patterns) and the protected matcher.
type Paths struct {
	Read      []string
	Write     []string
	DenyUser  []string
	Deny      *pathx.Matcher
	Protected *pathx.Matcher
}

// Services is the services section.
type Services struct {
	Status        []string
	ControlUnits  []string
	ControlVerbs  []string
}

// Journal is the journal section.
type Journal struct {
	Units    []string
	MaxLines int
}

// Git is the git section.
type Git struct {
	Repos []Repo
}

// Repo is one allow-listed repository.
type Repo struct {
	Path   string
	Remote string
}

// Privileged is the privileged forwarding section.
type Privileged struct {
	Enabled     bool
	Socket      string
	BroadSocket string
	MaxTier     Tier
}

// Command is one declared command.
type Command struct {
	ID             string
	Path           string // as written
	Resolved       string // after EvalSymlinks; argv[0] and the execve path
	Tier           Tier
	Description    string
	RootEquivalent bool
	Templates      []template.Template
}

// Command returns the command with the given id.
func (p *Policy) Command(id string) (*Command, bool) {
	for i := range p.Commands {
		if p.Commands[i].ID == id {
			return &p.Commands[i], true
		}
	}
	return nil, false
}

// Error is a policy validation failure. Field names the offending key; the
// message may name host paths and is for local display (check-policy), not
// for the wire.
type Error struct {
	Field string
	Msg   string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return "policy: " + e.Msg
	}
	return "policy: " + e.Field + ": " + e.Msg
}

// LoadOptions carries the facts about this host that validation needs.
type LoadOptions struct {
	// Trust decides who may own the policy, its directories and command
	// binaries. Production uses RootTrust().
	Trust Trust
	// GateExecutable is the resolved path of the running gate binary; it
	// joins the protected set.
	GateExecutable string
	// ServiceHome is the service account's home directory; it joins the
	// protected set and is HOME for commands.
	ServiceHome string
}

// Load checks the ownership of the policy file and every parent directory,
// reads it (bounded), and parses and validates it.
func Load(file string, opts LoadOptions) (*Policy, error) {
	return nil, errors.New("not implemented")
}

// Parse validates policy bytes. file is the policy's path (it joins the
// protected set).
func Parse(data []byte, file string, opts LoadOptions) (*Policy, error) {
	return nil, errors.New("not implemented")
}
