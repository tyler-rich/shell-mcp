//go:build linux

package gen

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// Dir is the only directory policy new writes into (POLICY §9.4).
const Dir = "/etc/shell-mcp"

// outRE is --out's file name under Dir.
var outRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.yaml$`)

// Options are policy new's flags.
type Options struct {
	Answers string // absolute
	Out     string // "-" or Dir/<name>.yaml
	DryRun  bool
}

// UsageError is a usage problem (exit 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// ParseFlags parses `policy new` flags; a relative --answers is taken
// from cwd. The --out rule is a refusal (exit 1), checked by Run.
func ParseFlags(args []string, cwd string) (*Options, error) {
	fset := flag.NewFlagSet("policy new", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	o := &Options{}
	fset.StringVar(&o.Answers, "answers", "", "")
	fset.StringVar(&o.Out, "out", "", "")
	fset.BoolVar(&o.DryRun, "dry-run", false, "")
	if err := fset.Parse(args); err != nil {
		return nil, &UsageError{err.Error()}
	}
	switch {
	case fset.NArg() != 0:
		return nil, &UsageError{fmt.Sprintf("unexpected argument %q", fset.Arg(0))}
	case o.Answers == "":
		return nil, &UsageError{"--answers is required"}
	case o.Out == "":
		return nil, &UsageError{"--out is required (a file under /etc/shell-mcp, or - to print)"}
	case o.Out == "-" && o.DryRun:
		return nil, &UsageError{"--dry-run and --out - together: --out - already writes nothing"}
	}
	if !filepath.IsAbs(o.Answers) {
		o.Answers = filepath.Join(cwd, o.Answers)
	}
	o.Answers = filepath.Clean(o.Answers)
	return o, nil
}

// Spec is what differs between the gate's command and the helper's.
type Spec struct {
	// Command is the command's name in messages ("shell-mcp-gate policy new").
	Command string
	// Kind names the policy in messages ("gate policy").
	Kind string
	// Mode is the written file's mode (0644 or 0600).
	Mode fs.FileMode
	// DefaultOut is the path the policy is loaded as under --out -.
	DefaultOut func(*Answers) string
	// Prepare checks what the policy needs from this host before it is
	// rendered; it reports through r and returns false to refuse.
	Prepare func(a *Answers, r *setupx.Report) bool
	// Render renders the policy.
	Render func(*Answers) ([]byte, error)
	// Load loads the rendered bytes as the policy file path, strictly, with
	// the binary's own loader. It returns the loader's warnings.
	Load func(data []byte, path string, a *Answers) ([]string, error)
	// Field maps one line of a loader error to the answers key it came from
	// (preset names the preset, for a field the answers do not decide).
	Field func(line, preset string) string
	// CheckPolicy runs the binary's check-policy on path, printing to w,
	// and returns its exit code.
	CheckPolicy func(path string, w io.Writer) int
	// Notes are printed after check-policy passes.
	Notes []string
}

// Result classes (TARGET-SETUP §12.4).
const (
	classCreate    = "create"
	classUnchanged = "unchanged"
)

// maxPolicyFile bounds reading an existing policy for the comparison.
const maxPolicyFile = 1 << 20

type runner struct {
	o      *Options
	s      *Spec
	h      setupx.Host
	r      *setupx.Report
	a      *setupx.Auditor
	stdout io.Writer
	ans    *Answers
}

// Run is `policy new` (POLICY §9.4). It returns the exit code.
// Run is a stub: it prints nothing and exits 0.
func Run(o *Options, s *Spec, h setupx.Host, stdout, stderr io.Writer, a *setupx.Auditor) int { return 0 }

func runImpl(o *Options, s *Spec, h setupx.Host, stdout, stderr io.Writer, a *setupx.Auditor) int {
	report := stdout
	if o.Out == "-" {
		report = stderr // stdout carries the policy
	}
	run := &runner{o: o, s: s, h: h, r: &setupx.Report{W: report}, a: a, stdout: stdout}
	return run.run()
}

func (run *runner) refuse(reason, format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	run.r.Fail("%s", msg)
	run.a.Log(&setupx.Record{Action: setupx.ActionRefuse, Object: "policy", Path: run.outPath(), Reason: reason, Detail: msg, Preset: run.preset()})
	return 1
}

func (run *runner) outPath() string {
	if run.o.Out == "-" {
		return ""
	}
	return run.o.Out
}

func (run *runner) preset() string {
	if run.ans == nil {
		return ""
	}
	return run.ans.Preset
}

func (run *runner) run() int {
	o, r, s := run.o, run.r, run.s
	mode := ""
	switch {
	case o.DryRun:
		mode = " (dry run: nothing is written)"
	case o.Out == "-":
		mode = " (printing to stdout: nothing is written)"
	}
	r.Info("%s%s: answers %s, out %s", s.Command, mode, o.Answers, o.Out)
	if _, ok := run.h.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		return run.refuse("forced_command", "SSH_ORIGINAL_COMMAND is set: policy new never runs as an SSH forced command")
	}
	if o.Out != "-" {
		if path.Dir(o.Out) != Dir || !outRE.MatchString(path.Base(o.Out)) {
			return run.refuse("out_path", "--out %s: must be - or %s/<name>.yaml, <name> of A-Z a-z 0-9 . _ - (the forced command and the units point there; another path is possible by hand)", o.Out, Dir)
		}
		if run.h.Euid() != 0 {
			return run.refuse("not_root", "policy new writes as root only (effective uid %d); --out - prints without writing", run.h.Euid())
		}
	}
	ans, ok := run.readAnswers()
	if !ok {
		return 1
	}
	run.ans = ans
	r.OK("answers: preset %s, account %s (uid %d)", ans.Preset, ans.Account.User, ans.Account.UID)
	if ans.Landlock == LandlockBestEffort {
		r.Warn("landlock: best-effort: serve then runs with reduced enforcement where the kernel lacks the ABI, and says so in hello and check-policy (POLICY §4a)")
	}
	if s.Prepare != nil && !s.Prepare(ans, r) {
		run.a.Log(&setupx.Record{Action: setupx.ActionRefuse, Object: "policy", Path: run.outPath(), Reason: "host", Detail: "the host is not ready for this policy", Preset: ans.Preset})
		return 1
	}
	data, err := s.Render(ans)
	if err != nil {
		return run.refuse("render", "%v", err)
	}
	loadAs := o.Out
	if o.Out == "-" {
		loadAs = s.DefaultOut(ans)
	}
	warnings, err := s.Load(data, loadAs, ans)
	if err != nil {
		var lines []string
		for _, l := range strings.Split(err.Error(), "\n") {
			lines = append(lines, s.Field(l, ans.Preset))
		}
		for _, l := range lines {
			r.Fail("%s", l)
		}
		run.a.Log(&setupx.Record{Action: setupx.ActionRefuse, Object: "policy", Path: run.outPath(), Reason: "policy_load",
			Detail: strings.Join(lines, "; "), Preset: ans.Preset})
		r.Info("the %s does not load, so nothing was written", s.Kind)
		return 1
	}
	r.OK("%s: loads strictly (sha256 %s)", s.Kind, setupx.Hash(data))
	for _, w := range warnings {
		r.Warn("%s", w)
	}
	if o.Out == "-" {
		_, _ = run.stdout.Write(data)
		return 0
	}
	return run.write(data)
}

// readAnswers reads and decodes the answers file.
func (run *runner) readAnswers() (*Answers, bool) {
	st, err := run.h.State(run.o.Answers, MaxAnswersBytes)
	switch {
	case err != nil:
		run.refuse("answers", "--answers %s: %v", run.o.Answers, err)
		return nil, false
	case !st.Exists:
		run.refuse("answers", "--answers %s: does not exist", run.o.Answers)
		return nil, false
	case !st.IsRegular():
		run.refuse("answers", "--answers %s: is not a regular file (give the file itself, not a link)", run.o.Answers)
		return nil, false
	}
	if st.Owner.UID != 0 || st.Perm()&0o022 != 0 {
		run.r.Warn("--answers %s is %s %04o: whoever can write it chooses what root writes into %s; keep it root's and not group- or world-writable", run.o.Answers, st.Owner, st.Perm(), Dir)
	}
	ans, err := Decode(st.Data)
	if err != nil {
		run.refuse("answers", "%v", err)
		return nil, false
	}
	return ans, true
}

// write is steps 6 of POLICY §9.4: the directory and the owned file, then
// check-policy, rolled back on a FAIL.
func (run *runner) write(data []byte) int {
	o, r, h, s := run.o, run.r, run.h, run.s
	if err := h.CheckChain(path.Dir(Dir)); err != nil {
		return run.refuse("directory_insecure", "%s: %v (it and every directory above it must be root's and not group- or world-writable)", path.Dir(Dir), err)
	}
	dir, err := h.State(Dir, 0)
	if err != nil {
		return run.refuse("file_unreadable", "%s: %v", Dir, err)
	}
	dirClass := classUnchanged
	switch {
	case !dir.Exists:
		dirClass = classCreate
	case dir.IsDir() && dir.Owner == setupx.Root && dir.Perm() == 0o755:
	default:
		return run.refuse("directory_differs", "%s exists but is not a root:root directory of mode 0755 (%s %s); fix it and run again", Dir, dir.Owner, dir.Mode)
	}
	prev, err := h.State(o.Out, maxPolicyFile)
	if err != nil {
		return run.refuse("file_unreadable", "%s: %v", o.Out, err)
	}
	class := classCreate
	switch {
	case !prev.Exists:
	case prev.Same(data, s.Mode, setupx.Root):
		class = classUnchanged
	case !prev.IsRegular():
		return run.refuse("file_differs", "%s exists and is not a regular file; remove it and run again", o.Out)
	case prev.Perm() != s.Mode || prev.Owner != setupx.Root:
		return run.refuse("file_differs", "%s is %s %04o, not root:root %04o; remove it (or fix it) and run again", o.Out, prev.Owner, prev.Perm(), s.Mode)
	default:
		n := run.refuse("file_differs", "%s exists with other content; policy new never overwrites it: edit it by hand, or remove it and run again", o.Out)
		r.Block(setupx.UnifiedDiff(o.Out+" (on the host)", o.Out+" (policy new)", prev.Data, data))
		return n
	}
	if o.DryRun {
		r.Info("directory %s root:root 0755: %s", Dir, dirClass)
		r.Info("file %s root:root %04o: %s", o.Out, s.Mode, class)
		if class == classCreate {
			r.Block(string(data))
		}
		r.Info("would run %s check-policy --policy %s", strings.Fields(s.Command)[0], o.Out)
		r.OK("dry run: every check passed; the run above would be made")
		return 0
	}
	if names, err := h.ReadDir(Dir); err == nil {
		for _, n := range names {
			if setupx.IsTempFor(n, path.Base(o.Out)) {
				left, err := h.RemoveLeftovers(o.Out)
				for _, l := range left {
					r.Warn("removed %s, a temp file a killed run left", l)
				}
				if err != nil {
					return run.refuse("temp_file", "%v", err)
				}
				break
			}
		}
	}
	j := setupx.NewJournal(h, run.a)
	if dirClass == classCreate {
		if err := j.Mkdir(Dir, 0o755, setupx.Root, &setupx.Record{Object: "directory", Owner: "root:root"}); err != nil {
			return run.refuse("write_failed", "%v", err)
		}
		r.OK("%s: create (root:root 0755)", Dir)
	}
	if class == classUnchanged {
		r.OK("%s: unchanged", o.Out)
	} else {
		rec := &setupx.Record{Object: "policy", Owner: "root:root", Preset: run.ans.Preset}
		if err := j.Write(o.Out, prev, data, s.Mode, setupx.Root, rec); err != nil {
			run.rollback(j)
			return run.refuse("write_failed", "%v", err)
		}
		r.OK("%s: %s (root:root %04o, sha256 %s)", o.Out, rec.Action, s.Mode, setupx.Hash(data))
	}
	r.Info("")
	code := s.CheckPolicy(o.Out, r.W)
	r.Info("")
	if code != 0 {
		n := run.refuse("check_policy", "check-policy reports a FAIL for %s (above)", o.Out)
		run.rollback(j)
		return n
	}
	for _, note := range s.Notes {
		r.Note("%s", note)
	}
	if j.Changed() {
		r.OK("written: %s", o.Out)
	} else {
		r.OK("nothing to do: %s unchanged", o.Out)
	}
	return 0
}

func (run *runner) rollback(j *setupx.Journal) {
	if !j.Changed() {
		return
	}
	undone, failed := j.Rollback()
	for _, err := range failed {
		run.r.Fail("rollback: %v", err)
	}
	if len(undone) > 0 {
		run.r.Info("rolled back: %s", strings.Join(undone, ", "))
	}
}

// LoaderField rewrites one line of a loader error ("<prefix>: <field>:
// <msg>") to name the answers key the field came from, through table
// (policy field prefix → answers key prefix; the first match wins). A field
// no entry matches is the preset's.
// LoaderField is a stub.
func LoaderField(line, prefix string, table [][2]string, preset string) string { return line }

func loaderFieldImpl(line, prefix string, table [][2]string, preset string) string {
	rest, ok := strings.CutPrefix(line, prefix+": ")
	if !ok {
		return line
	}
	field, msg, ok := strings.Cut(rest, ": ")
	if !ok || strings.ContainsAny(field, " ") {
		return "answers: " + rest
	}
	for _, e := range table {
		if strings.HasPrefix(field, e[0]) {
			return "answers " + e[1] + strings.TrimPrefix(field, e[0]) + ": " + msg
		}
	}
	return fmt.Sprintf("the %s preset's %s: %s", preset, field, msg)
}
