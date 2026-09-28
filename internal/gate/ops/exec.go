//go:build linux

package ops

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"path"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

type execArgs struct {
	CommandID      string   `json:"command_id"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	StdinB64       string   `json:"stdin_b64"`
	MaxOutputBytes int      `json:"max_output_bytes"`
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

// resolver resolves template placeholders against this gate's roots and
// services.status patterns.
type resolver struct{ s *server }

func (r resolver) ResolvePath(v string, write bool) (string, error) {
	if write {
		return r.s.fs.ResolveWrite(v)
	}
	return r.s.fs.ResolveRead(v)
}

func (r resolver) MatchUnit(v string) bool {
	for _, pat := range r.s.p.Services.Status {
		if ok, _ := path.Match(pat, v); ok {
			return true
		}
	}
	return false
}

// responseBudget leaves room for the envelope inside MaxResponseBytes.
const responseBudget = protocol.MaxResponseBytes - 256<<10

func (s *server) exec(raw jsontext.Value) (any, []string, error) {
	var a execArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	c, ok := s.p.Command(a.CommandID)
	if !ok {
		return nil, nil, errf(protocol.CodePolicyDenied, "command_id is not declared in the policy")
	}
	// The command's tier is checked before anything else about the request.
	if c.Tier > s.p.MaxTier {
		return nil, nil, errf(protocol.CodeTierDenied, "command tier %s exceeds the policy's max_tier %s", c.Tier, s.p.MaxTier)
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
	var stdin []byte
	if a.StdinB64 != "" {
		maxIn := s.p.Limits.MaxStdinBytes
		if len(a.StdinB64) > base64.StdEncoding.EncodedLen(maxIn) {
			return nil, nil, errf(protocol.CodeTooLarge, "stdin exceeds max_stdin_bytes (%d)", maxIn)
		}
		if stdin, err = base64.StdEncoding.Strict().DecodeString(a.StdinB64); err != nil {
			return nil, nil, errf(protocol.CodeBadRequest, "stdin_b64 is not standard base64")
		}
		if len(stdin) > maxIn {
			return nil, nil, errf(protocol.CodeTooLarge, "stdin exceeds max_stdin_bytes (%d)", maxIn)
		}
	}
	maxOut := s.p.Limits.MaxOutputBytes
	if a.MaxOutputBytes != 0 {
		if a.MaxOutputBytes < 1 || a.MaxOutputBytes > maxOut {
			return nil, nil, errf(protocol.CodeBadRequest, "max_output_bytes must be 1..%d", maxOut)
		}
		maxOut = a.MaxOutputBytes
	}

	res, err := execx.Run(context.Background(), execx.Spec{
		Path:      c.Resolved,
		Args:      args,
		Env:       execx.Environment(s.p.ServiceHome),
		Dir:       dir,
		Stdin:     stdin,
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
	// Both streams at their caps (plus JSON escaping) can exceed the
	// response limit: halve the larger until the result fits.
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
