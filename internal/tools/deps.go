package tools

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/tyler-rich/shell-mcp/internal/auth"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
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
	} {
		if err := r.Register(reg.tool, reg.tier, false); err != nil {
			return nil, err
		}
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

// call sends one gate request to target. A transport or protocol failure is
// the returned error; a gate failure is a response with ok false.
func (d *Deps) call(ctx context.Context, target, op string, args any, budget time.Duration) (*protocol.Response, *envelope.Error) {
	var o gateclient.Opener
	ok := false
	if d.Opener != nil {
		o, ok = d.Opener(target)
	}
	if !ok || d.Gate == nil {
		return nil, envelope.Errorf(envelope.CodeTargetUnreachable, "no SSH client for the target")
	}
	resp, err := d.Gate.Call(ctx, o, op, args, budget)
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
