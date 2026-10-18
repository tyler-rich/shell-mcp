//go:build linux

package ops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"path"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

type execArgs struct {
	CommandID      string   `json:"command_id"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	StdinB64       string   `json:"stdin_b64"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	// ExpectedPreviewSHA256, when given, is the preview_sha256 exec_preview
	// returned for the same command, arguments and cwd.
	ExpectedPreviewSHA256 *string `json:"expected_preview_sha256"`
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

func (s *server) exec(raw jsontext.Value) (data any, warns []string, failure error) {
	var a execArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	rx, err := s.resolveExec(a.CommandID, a.Args, a.Cwd)
	if err != nil {
		return nil, nil, err
	}
	if a.ExpectedPreviewSHA256 != nil {
		if !fsx.ValidPreviewSHA256(*a.ExpectedPreviewSHA256) {
			return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that exec_preview returned")
		}
		if rx.preview(s.p.SHA256).PreviewSHA256 != *a.ExpectedPreviewSHA256 {
			return nil, nil, errf(protocol.CodeExists, "the command resolves differently than its preview (its preview_sha256 differs: "+
				"the policy, the command's binary, a path placeholder or the cwd changed); nothing was run")
		}
	}
	c, args, dir := rx.c, rx.args, rx.dir
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

	res, err := execx.Run(context.Background(), &execx.Spec{
		Trampoline: s.o.Executable,
		Path:       c.Resolved,
		Args:       args,
		Env:        execx.Environment(s.p.ServiceHome),
		Dir:        dir,
		Stdin:      stdin,
		Timeout:    s.timeout(),
		MaxOutput:  maxOut,
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

// resolvedExec is a policy command resolved for one request: the command,
// the template its arguments matched, the arguments as they are passed
// (path placeholders resolved) and the working directory. exec and
// exec_preview both get it from resolveExec, so what a preview shows is
// what exec runs.
type resolvedExec struct {
	c        *policy.Command
	template int
	args     []string
	dir      string
}

// resolveExec looks the command up, checks its tier first (against
// max_tier and the request's ceiling), matches the arguments against its
// templates and resolves the working directory.
func (s *server) resolveExec(id string, args []string, cwd string) (*resolvedExec, error) {
	c, ok := s.p.Command(id)
	if !ok {
		return nil, errf(protocol.CodePolicyDenied, "command_id is not declared in the policy")
	}
	// The command's tier is checked before anything else about the request,
	// against max_tier and the request's ceiling.
	if err := s.within("command", c.Tier, s.p.MaxTier, "max_tier"); err != nil {
		return nil, err
	}
	if len(args) > template.MaxTokens {
		return nil, errf(protocol.CodeBadRequest, "at most %d arguments", template.MaxTokens)
	}
	i, out, err := template.MatchIndex(c.Templates, args, resolver{s})
	if err != nil {
		return nil, err
	}
	dir := "/"
	if cwd != "" {
		if dir, err = s.fs.ResolveDir(cwd); err != nil {
			return nil, err
		}
	}
	return &resolvedExec{c: c, template: i, args: out, dir: dir}, nil
}

type execPreviewArgs struct {
	CommandID string   `json:"command_id"`
	Args      []string `json:"args"`
	Cwd       string   `json:"cwd"`
}

// execPreviewData is exec_preview's result.
type execPreviewData struct {
	CommandID      string   `json:"command_id"`
	Tier           string   `json:"tier"`
	Description    string   `json:"description"`
	RootEquivalent bool     `json:"root_equivalent"`
	Template       []string `json:"template"`
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

const execPreviewDomain = "shell-mcp exec preview v1\x00"

// preview describes the resolved command; preview_sha256 covers every
// field, the policy's SHA-256 included, each length-prefixed and counted.
func (rx *resolvedExec) preview(policySHA string) execPreviewData {
	d := execPreviewData{
		CommandID: rx.c.ID, Tier: rx.c.Tier.String(), Description: rx.c.Description, RootEquivalent: rx.c.RootEquivalent,
		Template: rx.c.Templates[rx.template].String(), Argv: append([]string{rx.c.Resolved}, rx.args...), Cwd: rx.dir,
		PolicySHA256: policySHA,
	}
	b := []byte(execPreviewDomain)
	for _, f := range []string{d.PolicySHA256, d.CommandID, d.Tier, d.Description, d.Cwd} {
		b = appendStr(b, f)
	}
	if d.RootEquivalent {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	for _, list := range [][]string{d.Template, d.Argv} {
		b = binary.AppendUvarint(b, uint64(len(list)))
		for _, f := range list {
			b = appendStr(b, f)
		}
	}
	h := sha256.Sum256(b)
	d.PreviewSHA256 = hex.EncodeToString(h[:])
	return d
}

// execPreview resolves a command exactly as exec would and runs nothing.
func (s *server) execPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a execPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	rx, err := s.resolveExec(a.CommandID, a.Args, a.Cwd)
	if err != nil {
		return nil, nil, err
	}
	return rx.preview(s.p.SHA256), nil, nil
}
