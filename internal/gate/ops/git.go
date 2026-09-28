//go:build linux

package ops

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Built-in git operations (POLICY §7). Every invocation is
//
//	git -C <repo> --no-pager --no-optional-locks -c core.fsmonitor=false
//	    -c core.hooksPath=/dev/null -c core.pager=cat -c core.sshCommand=/bin/false
//	    -c credential.helper= -c protocol.file.allow=never -c protocol.ext.allow=never
//	    -c safe.directory=<repo> <subcommand> …
//
// with GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null, GIT_DIR=<repo>/.git
// and GIT_WORK_TREE=<repo> added to the gate's fixed environment (nothing
// else reaches git: execx inherits no variable). <repo>/.git must be a real
// directory inside the root (no gitfile, no symlink, no commondir), and
// before anything else the repository-local configuration is read with
// `git config --local --no-includes --list -z` and refused unless every key
// is on gitx's allowlist: repository-local configuration can otherwise make
// git run commands (filters, textconv, external diff, askPass) or talk to
// another host (url.*.insteadOf). fsx never writes under a .git component
// (POLICY §3), so a caller cannot plant such configuration either.

const (
	maxGitEntries   = 1000
	defaultGitLog   = 20
	maxGitLog       = 200
	gitHashMaxBytes = 128
)

// GitArgs returns the gate's git argv for the repository at repo (a real
// path) followed by sub. caFile adds http.sslCAInfo and is set only by
// tests (Options.TestGitCAFile).
func GitArgs(repo, caFile string, sub ...string) []string {
	a := []string{"-C", repo, "--no-pager", "--no-optional-locks",
		"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
		"-c", "core.sshCommand=/bin/false", "-c", "credential.helper=",
		"-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
		"-c", "safe.directory=" + repo}
	if caFile != "" {
		a = append(a, "-c", "http.sslCAInfo="+caFile)
	}
	return append(a, sub...)
}

// GitEnv returns git's exact environment for the repository at repo.
func GitEnv(home, repo string) []string {
	return append(execx.Environment(home), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_DIR="+repo+"/.git", "GIT_WORK_TREE="+repo)
}

// gitRepo is a validated repository and the request's deadline.
type gitRepo struct {
	path, real, remote string
	deadline           time.Time
	s                  *server
}

// gitRepo validates repo: listed in git.repos, inside a write root when
// write is set, confined by fsx, and with a real .git directory.
func (s *server) gitRepo(p string, write bool) (*gitRepo, error) {
	if p == "" {
		return nil, errf(protocol.CodeBadRequest, "repo is required")
	}
	if err := pathx.CheckClean(p); err != nil {
		return nil, errf(protocol.CodeBadRequest, "repo must be an absolute clean path")
	}
	i := slices.IndexFunc(s.p.Git.Repos, func(r policy.Repo) bool { return r.Path == p })
	if i < 0 {
		return nil, errf(protocol.CodePolicyDenied, "repo is not listed in git.repos")
	}
	if _, ok := pathx.Longest(s.p.Paths.Write, p); write && !ok {
		return nil, errf(protocol.CodePolicyDenied, "repo is not inside a write root")
	}
	realPath, err := s.fs.ResolveDir(p)
	if err != nil {
		return nil, err
	}
	if write {
		if _, err = s.fs.ResolveWrite(p); err != nil {
			return nil, err
		}
	}
	e, err := s.fs.Stat(p + "/.git")
	if err != nil {
		var fe *fsx.Error
		if errors.As(err, &fe) && fe.Code == protocol.CodeNotFound {
			return nil, errf(protocol.CodeNotFound, "repo has no .git directory")
		}
		return nil, err
	}
	if e.Type != "dir" {
		return nil, errf(protocol.CodePolicyDenied, "repo/.git must be a real directory (a gitfile or a symlink is refused)")
	}
	if gd, err := s.fs.ResolveDir(p + "/.git"); err != nil || gd != realPath+"/.git" {
		return nil, errf(protocol.CodePolicyDenied, "repo/.git must be a real directory inside the root")
	}
	if _, err := s.fs.Stat(p + "/.git/commondir"); err == nil {
		return nil, errf(protocol.CodePolicyDenied, "repo/.git has a commondir (a linked worktree); only plain repositories are allowed")
	}
	return &gitRepo{path: p, real: realPath, remote: s.p.Git.Repos[i].Remote, deadline: time.Now().Add(s.timeout()), s: s}, nil
}

// run runs one git subcommand within the request's remaining time.
func (r *gitRepo) run(maxOut int, sub ...string) (execx.Result, error) {
	s := r.s
	bin, err := s.builtin(s.o.Git, "git")
	if err != nil {
		return execx.Result{}, err
	}
	left := time.Until(r.deadline)
	if left <= 0 {
		return execx.Result{}, errf(protocol.CodeTimeout, "git did not finish within the request timeout")
	}
	res, err := execx.Run(context.Background(), &execx.Spec{
		Path: bin, Args: GitArgs(r.real, s.o.TestGitCAFile, sub...), Env: GitEnv(s.p.ServiceHome, r.real),
		Dir: r.real, Timeout: left, MaxOutput: maxOut,
	})
	if err != nil {
		return execx.Result{}, err
	}
	if res.TimedOut {
		return res, errf(protocol.CodeTimeout, "git did not finish within the request timeout")
	}
	return res, nil
}

// output runs a subcommand that must succeed and whose whole stdout is
// needed.
func (r *gitRepo) output(sub ...string) ([]byte, error) {
	res, err := r.run(r.s.p.Limits.MaxOutputBytes, sub...)
	if err != nil {
		return nil, err
	}
	if !exited(&res, 0) {
		return nil, errf(protocol.CodeExecFailed, "git %s failed (%s)", sub[0], exitStatus(&res))
	}
	if res.StdoutTruncated {
		return nil, errf(protocol.CodeTooLarge, "git %s output exceeds max_output_bytes", sub[0])
	}
	return res.Stdout, nil
}

// safeKey bounds a configuration key for a one-line message.
func safeKey(k string) string {
	k = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return '?'
		}
		return c
	}, k)
	if len(k) > 128 {
		k = k[:128] + "..."
	}
	return k
}

// checkConfig refuses repository-local configuration outside the allowlist.
func (r *gitRepo) checkConfig() ([]gitx.KV, error) {
	out, err := r.output("config", "--local", "--no-includes", "--list", "-z")
	if err != nil {
		return nil, err
	}
	kvs, err := gitx.ParseConfig(out)
	if err != nil {
		return nil, errf(protocol.CodeExecFailed, "git config output could not be parsed")
	}
	if key, ok := gitx.CheckConfig(kvs); !ok {
		return nil, errf(protocol.CodePolicyDenied, "the repository's .git/config sets %q, which the gate does not allow "+
			"(only core basics, remote.origin.url/fetch and branch.<name>.remote/merge); remove it on the host", safeKey(key))
	}
	return kvs, nil
}

// status parses porcelain v2 status; untracked selects --untracked-files.
func (r *gitRepo) status(untracked string, branch bool) (gitx.Status, bool, error) {
	args := []string{"status", "--porcelain=v2", "-z", "--untracked-files=" + untracked}
	if branch {
		args = append(args, "--branch")
	}
	out, err := r.output(args...)
	if err != nil {
		return gitx.Status{}, false, err
	}
	st, truncated, err := gitx.ParseStatus(out, maxGitEntries)
	if err != nil {
		return gitx.Status{}, false, errf(protocol.CodeExecFailed, "git status output could not be parsed")
	}
	return st, truncated, nil
}

// head returns HEAD's commit, or "" for a repository without commits.
func (r *gitRepo) head() (string, error) {
	res, err := r.run(gitHashMaxBytes, "rev-parse", "--verify", "-q", "HEAD")
	if err != nil {
		return "", err
	}
	if !exited(&res, 0) {
		return "", nil
	}
	h := strings.TrimSpace(string(res.Stdout))
	if (len(h) != 40 && len(h) != 64) || strings.Trim(h, "0123456789abcdef") != "" {
		return "", errf(protocol.CodeExecFailed, "git rev-parse output could not be parsed")
	}
	return h, nil
}

type repoArgs struct {
	Repo string `json:"repo"`
}

type gitStatusData struct {
	Repo      string       `json:"repo"`
	Branch    string       `json:"branch"`
	Head      string       `json:"head"`
	Upstream  string       `json:"upstream"`
	Ahead     int          `json:"ahead"`
	Behind    int          `json:"behind"`
	Entries   []gitx.Entry `json:"entries"`
	Truncated bool         `json:"truncated"`
}

func (s *server) gitStatus(raw jsontext.Value) (data any, warns []string, failure error) {
	var a repoArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.gitRepo(a.Repo, false)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	st, truncated, err := r.status("normal", true)
	if err != nil {
		return nil, nil, err
	}
	d := gitStatusData{Repo: a.Repo, Branch: st.Branch, Head: st.OID, Upstream: st.Upstream, Ahead: st.Ahead, Behind: st.Behind,
		Entries: orEmpty(st.Entries), Truncated: truncated}
	return d, nil, nil
}

type gitLogArgs struct {
	Repo  string `json:"repo"`
	Limit int    `json:"limit"`
}

type gitLogData struct {
	Repo    string        `json:"repo"`
	Commits []gitx.Commit `json:"commits"`
}

func (s *server) gitLog(raw jsontext.Value) (data any, warns []string, failure error) {
	var a gitLogArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	switch {
	case a.Limit == 0:
		a.Limit = defaultGitLog
	case a.Limit < 1 || a.Limit > maxGitLog:
		return nil, nil, errf(protocol.CodeBadRequest, "limit must be 1..%d", maxGitLog)
	}
	r, err := s.gitRepo(a.Repo, false)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	d := gitLogData{Repo: a.Repo, Commits: []gitx.Commit{}}
	if h, herr := r.head(); herr != nil || h == "" {
		return d, nil, herr
	}
	out, err := r.output("log", "--no-color", "--no-show-signature", "--no-ext-diff", "--no-textconv",
		"--format="+gitx.LogFormat, "-n", strconv.Itoa(a.Limit))
	if err != nil {
		return nil, nil, err
	}
	cs, err := gitx.ParseLog(out)
	if err != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "git log output could not be parsed")
	}
	for _, c := range cs {
		c.Author, c.Subject = s.red.String(c.Author), s.red.String(c.Subject)
		d.Commits = append(d.Commits, c)
	}
	return d, nil, nil
}

type gitDiffArgs struct {
	Repo           string `json:"repo"`
	Staged         bool   `json:"staged"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

type gitDiffData struct {
	Repo      string `json:"repo"`
	Staged    bool   `json:"staged"`
	Diff      string `json:"diff"`
	Truncated bool   `json:"truncated"`
}

func (s *server) gitDiff(raw jsontext.Value) (data any, warns []string, failure error) {
	var a gitDiffArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	maxOut := s.p.Limits.MaxOutputBytes
	if a.MaxOutputBytes != 0 {
		if a.MaxOutputBytes < 1 || a.MaxOutputBytes > maxOut {
			return nil, nil, errf(protocol.CodeBadRequest, "max_output_bytes must be 1..%d", maxOut)
		}
		maxOut = a.MaxOutputBytes
	}
	r, err := s.gitRepo(a.Repo, false)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	args := []string{"diff", "--no-color", "--no-ext-diff", "--no-textconv"}
	if a.Staged {
		args = append(args, "--cached")
	}
	res, err := r.run(maxOut, args...)
	if err != nil {
		return nil, nil, err
	}
	if !exited(&res, 0) {
		return nil, nil, errf(protocol.CodeExecFailed, "git diff failed (%s)", exitStatus(&res))
	}
	out, cut := s.red.Truncate(res.Stdout, maxOut)
	return gitDiffData{Repo: a.Repo, Staged: a.Staged, Diff: string(out), Truncated: cut || res.StdoutTruncated}, nil, nil
}

type gitPullData struct {
	Repo         string `json:"repo"`
	OldHead      string `json:"old_head"`
	NewHead      string `json:"new_head"`
	ChangedFiles int    `json:"changed_files"`
	Updated      bool   `json:"updated"`
}

// gitPull fast-forwards a repository inside a write root from the policy's
// remote: refused when origin differs from the policy (as configured or as
// git would resolve it), when tracked files have uncommitted changes, or
// when the pull is not a fast-forward.
func (s *server) gitPull(raw jsontext.Value) (data any, warns []string, failure error) {
	var a repoArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.gitRepo(a.Repo, true)
	if err != nil {
		return nil, nil, err
	}
	kvs, err := r.checkConfig()
	if err != nil {
		return nil, nil, err
	}
	if u, ok := gitx.Value(kvs, "remote.origin.url"); !ok || u != r.remote {
		return nil, nil, errf(protocol.CodePolicyDenied, "remote.origin.url is not the remote the policy lists for this repo")
	}
	got, err := r.output("ls-remote", "--get-url", "origin")
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(string(got)) != r.remote {
		return nil, nil, errf(protocol.CodePolicyDenied, "origin resolves to a URL other than the policy's remote")
	}
	st, _, err := r.status("no", false)
	if err != nil {
		return nil, nil, err
	}
	if len(st.Entries) > 0 {
		return nil, nil, errf(protocol.CodePolicyDenied, "the working tree has uncommitted changes to tracked files; commit or discard them first")
	}
	old, err := r.head()
	if err != nil {
		return nil, nil, err
	}
	res, err := r.run(s.p.Limits.MaxOutputBytes, "pull", "--ff-only", "--no-rebase", "--no-recurse-submodules")
	if err != nil {
		return nil, nil, err
	}
	if !exited(&res, 0) {
		if old != "" {
			// The pull's fetch updated FETCH_HEAD; exit 1 from --is-ancestor
			// means HEAD is not an ancestor of it: not a fast-forward.
			mb, mberr := r.run(gitHashMaxBytes, "merge-base", "--is-ancestor", "HEAD", "FETCH_HEAD")
			if mberr == nil && exited(&mb, 1) {
				return nil, nil, errf(protocol.CodePolicyDenied, "the pull is not a fast-forward (local and remote history diverge); nothing was changed")
			}
		}
		return nil, nil, errf(protocol.CodeExecFailed, "git pull failed (%s)", exitStatus(&res))
	}
	nw, err := r.head()
	if err != nil {
		return nil, nil, err
	}
	d := gitPullData{Repo: a.Repo, OldHead: old, NewHead: nw, Updated: old != nw}
	if d.Updated {
		var names []byte
		if old == "" {
			names, err = r.output("ls-tree", "-r", "-z", "--name-only", nw)
		} else {
			names, err = r.output("diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", old, nw)
		}
		if err != nil {
			return nil, nil, err
		}
		d.ChangedFiles = bytes.Count(names, []byte{0})
	}
	return d, nil, nil
}

type gitDiscardData struct {
	Repo      string   `json:"repo"`
	Reset     []string `json:"reset"`
	Remove    []string `json:"remove"`
	Skipped   []string `json:"skipped"`
	Truncated bool     `json:"truncated"`
	Applied   bool     `json:"applied"`
	CleanAt   *bool    `json:"clean_after,omitempty"`
}

// discardPreview lists exactly what `reset --hard` and `clean -f -d` would
// change: tracked entries that differ from HEAD (both paths of a rename),
// and the untracked files and directories clean would remove (ignored files
// are kept; nested repositories are skipped).
func (r *gitRepo) discardPreview() (gitDiscardData, error) {
	d := gitDiscardData{Repo: r.path}
	st, truncated, err := r.status("no", false)
	if err != nil {
		return d, err
	}
	d.Truncated = truncated
	reset := []string{}
	for _, e := range st.Entries {
		reset = append(reset, e.Path)
		if e.OrigPath != "" {
			reset = append(reset, e.OrigPath)
		}
	}
	slices.Sort(reset)
	d.Reset = slices.Compact(reset)
	out, err := r.output("clean", "-n", "-d")
	if err != nil {
		return d, err
	}
	rm, skip, err := gitx.ParseClean(out)
	if err != nil {
		return d, errf(protocol.CodeExecFailed, "git clean output could not be parsed")
	}
	slices.Sort(rm)
	slices.Sort(skip)
	d.Remove, d.Skipped = rm, skip
	return d, nil
}

func (s *server) gitDiscardPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a repoArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.gitRepo(a.Repo, false)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	d, err := r.discardPreview()
	if err != nil {
		return nil, nil, err
	}
	return d, nil, nil
}

// gitDiscard runs `reset --hard` and `clean -f -d` on a repository inside a
// write root and reports what it changed (the preview taken just before).
func (s *server) gitDiscard(raw jsontext.Value) (data any, warns []string, failure error) {
	var a repoArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.gitRepo(a.Repo, true)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	d, err := r.discardPreview()
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.output("reset", "--hard", "-q"); err != nil {
		return nil, nil, err
	}
	if _, err = r.output("clean", "-f", "-d", "-q"); err != nil {
		return nil, nil, err
	}
	d.Applied = true
	st, _, err := r.status("normal", false)
	if err != nil {
		return nil, nil, err
	}
	clean := len(st.Entries) == 0
	d.CleanAt = &clean
	var warnings []string
	if !clean {
		warnings = append(warnings, "the working tree still has changes after the discard (for example nested repositories, which are skipped)")
	}
	return d, warnings, nil
}
