//go:build linux

package ops

import (
	"context"
	"encoding/json/jsontext"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// execArgs has no stdin: the privileged policy declares no stdin limit, so
// root commands always read /dev/null.
type execArgs struct {
	CommandID      string   `json:"command_id"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	// Unit is the routing label the server supplies so that the gate can
	// pick the socket (the gate cannot read the privileged policy): "",
	// "core" or "broad". The helper decides by the command's declared unit;
	// a label that disagrees with this instance is refused.
	Unit string `json:"unit"`
}

type execData struct {
	CommandID       string   `json:"command_id"`
	Argv            []string `json:"argv"`
	ExitCode        *int     `json:"exit_code"`
	Signal          *string  `json:"signal"`
	TimedOut        bool     `json:"timed_out"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
	DurationMS      int64    `json:"duration_ms"`
}

// resolver resolves {path:read} and {path:write} against the privileged
// roots; the privileged policy declares no units.
type resolver struct{ s *server }

func (r resolver) ResolvePath(v string, write bool) (string, error) {
	if write {
		return r.s.fs.ResolveWrite(v)
	}
	return r.s.fs.ResolveRead(v)
}

func (resolver) MatchUnit(string) bool { return false }

// responseBudget leaves room for the envelope inside MaxResponseBytes.
const responseBudget = protocol.MaxResponseBytes - 256<<10

// execHome is HOME for root commands: ProtectHome=read-only leaves /root
// read-only, and the helper has no home of its own.
const execHome = "/root"

func (s *server) exec(raw jsontext.Value) (data any, warns []string, failure error) {
	var a execArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	switch policy.Unit(a.Unit) {
	case "", policy.UnitCore, policy.UnitBroad:
	default:
		return nil, nil, errf(protocol.CodeBadRequest, "unit must be core or broad")
	}
	c, ok := s.p.Command(a.CommandID)
	if !ok {
		return nil, nil, errf(protocol.CodePolicyDenied, "command_id is not declared in the privileged policy")
	}
	// The unit before anything else about the command: a command declared for
	// the other unit, or a request labelled for it, never runs here.
	if c.Unit != s.unit {
		return nil, nil, s.wrongUnit(c.Unit)
	}
	if a.Unit != "" && policy.Unit(a.Unit) != s.unit {
		return nil, nil, s.wrongUnit(policy.Unit(a.Unit))
	}
	// The command's tier is checked before anything else about the request.
	if c.Tier > s.p.MaxTier {
		return nil, nil, errf(protocol.CodeTierDenied, "command tier %s exceeds the privileged policy's max_tier %s", c.Tier, s.p.MaxTier)
	}
	if len(a.Args) > template.MaxTokens {
		return nil, nil, errf(protocol.CodeBadRequest, "at most %d arguments", template.MaxTokens)
	}
	args, err := template.Match(c.Templates, a.Args, resolver{s})
	if err != nil {
		return nil, nil, err
	}
	dir := "/"
	if a.Cwd != "" {
		if dir, err = s.fs.ResolveDir(a.Cwd); err != nil {
			return nil, nil, err
		}
	}
	maxOut := s.p.Limits.MaxOutputBytes
	if a.MaxOutputBytes != 0 {
		if a.MaxOutputBytes < 1 || a.MaxOutputBytes > maxOut {
			return nil, nil, errf(protocol.CodeBadRequest, "max_output_bytes must be 1..%d", maxOut)
		}
		maxOut = a.MaxOutputBytes
	}
	res, err := execx.Run(context.Background(), &execx.Spec{
		Path:      c.Resolved,
		Args:      args,
		Env:       execx.Environment(execHome),
		Dir:       dir,
		Timeout:   s.timeout(),
		MaxOutput: maxOut,
	})
	if err != nil {
		return nil, nil, err
	}
	stdout, cutOut := s.red.Truncate(res.Stdout, maxOut)
	stderr, cutErr := s.red.Truncate(res.Stderr, maxOut)
	d := execData{
		CommandID:       c.ID,
		Argv:            append([]string{c.Resolved}, args...),
		ExitCode:        res.ExitCode,
		TimedOut:        res.TimedOut,
		Stdout:          string(stdout),
		Stderr:          string(stderr),
		StdoutTruncated: res.StdoutTruncated || cutOut,
		StderrTruncated: res.StderrTruncated || cutErr,
		DurationMS:      res.Duration.Milliseconds(),
	}
	if res.Signal != "" {
		sig := res.Signal
		d.Signal = &sig
	}
	var warnings []string
	if res.OutputCeilingHit {
		warnings = append(warnings, "output exceeded the hard ceiling; the process group was killed")
	}
	for i := 0; i < 24; i++ {
		b, err := protocol.Marshal(d)
		if err != nil || len(b) <= responseBudget {
			break
		}
		if i == 0 {
			warnings = append(warnings, "output was cut further to fit the 4 MiB response limit")
		}
		if len(d.Stdout) >= len(d.Stderr) {
			out, _ := s.red.Truncate([]byte(d.Stdout), len(d.Stdout)/2)
			d.Stdout, d.StdoutTruncated = string(out), true
		} else {
			out, _ := s.red.Truncate([]byte(d.Stderr), len(d.Stderr)/2)
			d.Stderr, d.StderrTruncated = string(out), true
		}
	}
	return d, warnings, nil
}
