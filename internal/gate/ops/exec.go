//go:build linux

package ops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"os"
	"path"
	"syscall"

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
	Fds             []execFD `json:"fds"`
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
// services.status patterns. Paths go through execFS, under the chain rule
// (handoff N-11): the command looks the resolved string up again itself.
type resolver struct{ s *server }

func (r resolver) ResolvePath(v string, write bool) (string, error) {
	if write {
		return r.s.execFS.ResolveWrite(v)
	}
	return r.s.execFS.ResolveRead(v)
}

func (r resolver) ResolveReadFD(v string) (*os.File, string, error) {
	return r.s.execFS.ResolveReadFD(v)
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
	defer rx.close()
	if a.ExpectedPreviewSHA256 != nil {
		if !fsx.ValidPreviewSHA256(*a.ExpectedPreviewSHA256) {
			return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that exec_preview returned")
		}
		if rx.preview(s.p.SHA256).PreviewSHA256 != *a.ExpectedPreviewSHA256 {
			return nil, nil, errf(protocol.CodeExists, "the command resolves differently than its preview (its preview_sha256 differs: "+
				"the policy, the command's binary, a path placeholder, a file passed as a descriptor or the cwd changed); nothing was run")
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

	if s.o.InjectBeforeExec != nil {
		s.o.InjectBeforeExec()
	}
	// The command gets the descriptors the hash above covered.
	res, err := execx.Run(context.Background(), &execx.Spec{
		Trampoline:  s.o.Executable,
		Path:        c.Resolved,
		Args:        args,
		Env:         execx.Environment(s.p.ServiceHome),
		Dir:         dir,
		Stdin:       stdin,
		Timeout:     s.timeout(),
		MaxOutput:   maxOut,
		MaxMemoryMB: s.p.Limits.MaxMemoryMB,
		Files:       rx.files(),
	})
	if err != nil {
		return nil, nil, err
	}

	stdout, cutOut := s.red.Truncate(res.Stdout, maxOut)
	stderr, cutErr := s.red.Truncate(res.Stderr, maxOut)
	d := execData{
		CommandID:       c.ID,
		Argv:            append([]string{c.Resolved}, args...),
		Fds:             rx.fdList(),
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
// (path placeholders resolved, a {path:read:fd} as /dev/fd/N), the
// descriptors opened for the {path:read:fd} placeholders with each file's
// identity, and the working directory. exec and exec_preview both get it
// from resolveExec, so what a preview shows is what exec runs; the caller
// closes it.
type resolvedExec struct {
	c        *policy.Command
	template int
	args     []string
	fds      []template.Descriptor
	ids      []fileID
	dir      string
}

// fileID is a passed file's identity, read from its descriptor: the values
// another gate instance reads for the same file, so that exec's recomputed
// preview hash equals the preview's exactly when it passes the same file.
// The mount id is left out (it is not stable across mount namespaces).
type fileID struct{ dev, ino uint64 }

// execFD is one passed descriptor, as exec_preview and exec report it.
type execFD struct {
	FD   int    `json:"fd"`
	Path string `json:"path"`
}

func (rx *resolvedExec) close() {
	for _, d := range rx.fds {
		_ = d.File.Close()
	}
	rx.fds = nil
}

// files are the descriptors to pass, in order (execx passes the first as
// template.FirstFD).
func (rx *resolvedExec) files() []*os.File {
	out := make([]*os.File, 0, len(rx.fds))
	for _, d := range rx.fds {
		out = append(out, d.File)
	}
	return out
}

// fdList is the descriptors as reported: never nil.
func (rx *resolvedExec) fdList() []execFD {
	out := make([]execFD, 0, len(rx.fds))
	for _, d := range rx.fds {
		out = append(out, execFD{FD: d.FD, Path: d.Path})
	}
	return out
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
	m, err := template.MatchFD(c.Templates, args, resolver{s})
	if err != nil {
		return nil, err
	}
	rx := &resolvedExec{c: c, template: m.Index, args: m.Args, fds: m.Descriptors}
	for _, d := range rx.fds {
		fi, serr := d.File.Stat()
		st, ok := fileStat(fi)
		if serr != nil || !ok {
			rx.close()
			return nil, errf(protocol.CodeInternal, "a file passed as a descriptor could not be read (fstat); nothing was run")
		}
		rx.ids = append(rx.ids, fileID{dev: st.Dev, ino: st.Ino})
	}
	rx.dir = "/"
	if cwd != "" {
		if rx.dir, err = s.execFS.ResolveDir(cwd); err != nil {
			rx.close()
			return nil, err
		}
	}
	return rx, nil
}

// fileStat is fi's stat(2) record.
func fileStat(fi os.FileInfo) (*syscall.Stat_t, bool) {
	if fi == nil {
		return nil, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return st, ok
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
	Fds            []execFD `json:"fds"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

// execPreviewDomain is v2 since protocol version 2 (handoff N-22): the hash
// also covers the passed descriptors.
const execPreviewDomain = "shell-mcp exec preview v2\x00"

// preview describes the resolved command; preview_sha256 covers every
// field, the policy's SHA-256 included, each length-prefixed and counted,
// and for each passed descriptor its number, path, device and inode, so
// that another file under the same name is another preview.
func (rx *resolvedExec) preview(policySHA string) execPreviewData {
	d := execPreviewData{
		CommandID: rx.c.ID, Tier: rx.c.Tier.String(), Description: rx.c.Description, RootEquivalent: rx.c.RootEquivalent,
		Template: rx.c.Templates[rx.template].String(), Argv: append([]string{rx.c.Resolved}, rx.args...), Cwd: rx.dir,
		Fds: rx.fdList(), PolicySHA256: policySHA,
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
	b = binary.AppendUvarint(b, uint64(len(d.Fds)))
	for i, fd := range d.Fds {
		b = binary.AppendUvarint(b, uint64(fd.FD)) //nolint:gosec // G115: a descriptor number from template.FirstFD
		b = appendStr(b, fd.Path)
		b = binary.AppendUvarint(b, rx.ids[i].dev)
		b = binary.AppendUvarint(b, rx.ids[i].ino)
	}
	h := sha256.Sum256(b)
	d.PreviewSHA256 = hex.EncodeToString(h[:])
	return d
}

// execPreview resolves a command exactly as exec would and runs nothing.
func (s *server) execPreview(raw jsontext.Value) (data any, failure error) {
	var a execPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	rx, err := s.resolveExec(a.CommandID, a.Args, a.Cwd)
	if err != nil {
		return nil, err
	}
	defer rx.close()
	return rx.preview(s.p.SHA256), nil
}
