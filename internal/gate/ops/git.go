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
//	    -c safe.directory=<repo> -c maintenance.auto=false -c gc.auto=0
//	    -c gc.autoDetach=false -c core.ignorecase=false
//	    -c <every program-running key with a fixed name>=/bin/false
//	    -c hook.<every event>.enabled=false <subcommand> …
//
// with GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null, GIT_DIR=<repo>/.git,
// GIT_WORK_TREE=<repo> and the program-naming variables (GitEnv) added to
// the gate's fixed environment (nothing else reaches git: execx inherits no
// variable). Before any git process the repository must be closed
// (fsx.CheckGitRepo, handoff N-20): every directory from / to it, it, .git
// and .git/config root's or the service account's and neither group- nor
// world-writable nor sticky, .git a real directory, no commondir or
// config.worktree. Then the repository-local configuration is read with
// `git config --local --no-includes --list -z` and refused unless every key
// is on gitx's allowlist: repository-local configuration can otherwise make
// git run commands (filters, textconv, external diff, askPass) or talk to
// another host (url.*.insteadOf). In a closed repository no other account can
// change it after that check, and the -c overrides and variables are a
// second layer for the keys whose names are fixed. fsx never writes under a
// .git component (POLICY §3), so a caller cannot plant such configuration
// either. git applies no safe.directory ownership check to a repository
// GIT_DIR names, so safe.directory=<repo> does nothing for it.

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
		"-c", "safe.directory=" + repo,
		// No automatic maintenance or gc: git would otherwise start
		// `git maintenance run --auto --detach` after a pull, which
		// daemonizes (setsid) out of the gate's process group and outlives
		// the request. Case sensitivity is pinned: a repo-local
		// core.ignorecase=true would hide untracked files from status and
		// clean on a case-sensitive filesystem.
		"-c", "maintenance.auto=false", "-c", "gc.auto=0", "-c", "gc.autoDetach=false", "-c", "core.ignorecase=false",
		// Every key with a fixed name that names a program git would run
		// (git 2.55 git-config(1)), so that none the repository sets after
		// the configuration check runs anything (handoff N-20). The
		// command line is read last and wins for each of them.
		"-c", "core.editor=/bin/false", "-c", "sequence.editor=/bin/false", "-c", "core.askPass=/bin/false",
		"-c", "core.alternateRefsCommand=/bin/false", "-c", "diff.external=/bin/false",
		"-c", "gpg.program=/bin/false", "-c", "gpg.openpgp.program=/bin/false", "-c", "gpg.x509.program=/bin/false",
		"-c", "gpg.ssh.program=/bin/false", "-c", "gpg.ssh.defaultKeyCommand=/bin/false"}
	// Hooks defined in configuration (hook.<name>.command and .event) run
	// whatever core.hooksPath says; hook.<event>.enabled=false turns every
	// hook of that event off.
	for _, e := range gitHookEvents {
		a = append(a, "-c", "hook."+e+".enabled=false")
	}
	if caFile != "" {
		a = append(a, "-c", "http.sslCAInfo="+caFile)
	}
	return append(a, sub...)
}

// gitHookEvents are the hook events of githooks(5) in git 2.55.
var gitHookEvents = []string{
	"applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg",
	"post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
	"post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
	"fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-index-change",
}

// GitEnv returns git's exact environment for the repository at repo. The
// variables that would name a program are set to ones that run nothing
// (they take precedence over the matching configuration keys, and
// GIT_PROXY_COMMAND, set even empty, over every core.gitProxy).
func GitEnv(home, repo string) []string {
	return append(execx.Environment(home), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_DIR="+repo+"/.git", "GIT_WORK_TREE="+repo,
		"GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false", "GIT_EDITOR=/bin/false", "GIT_SEQUENCE_EDITOR=/bin/false",
		"GIT_EXTERNAL_DIFF=/bin/false", "GIT_PAGER=cat", "GIT_PROXY_COMMAND=", "GIT_SSH=/bin/false", "GIT_SSH_COMMAND=/bin/false")
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
	// The repository is closed (handoff N-20): no account but root and the
	// service account can change any directory from / to it, it, .git or
	// .git/config, so none can change what git reads between checkConfig
	// and the operation's git processes; .git is a real directory, and
	// neither a commondir nor a config.worktree points git elsewhere. One
	// check, by descriptor, before any git process, for every operation.
	if err := s.gitFS.CheckGitRepo(p); err != nil {
		return nil, err
	}
	return &gitRepo{path: p, real: realPath, remote: s.p.Git.Repos[i].Remote, deadline: time.Now().Add(s.timeout()), s: s}, nil
}

func notFound(err error) bool {
	var fe *fsx.Error
	return errors.As(err, &fe) && fe.Code == protocol.CodeNotFound
}

// run runs one git subcommand within the request's remaining time.
func (r *gitRepo) run(maxOut int, sub ...string) (execx.Result, error) {
	return r.runWith(nil, nil, maxOut, sub...)
}

// runWith is run with variables added to git's environment (only
// GIT_INDEX_FILE, for git_discard's temporary index) and stdin.
func (r *gitRepo) runWith(env []string, stdin []byte, maxOut int, sub ...string) (execx.Result, error) {
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
		Path: bin, Trampoline: s.o.Executable, Args: GitArgs(r.real, s.o.TestGitCAFile, sub...), Env: append(GitEnv(s.p.ServiceHome, r.real), env...),
		Dir: r.real, Stdin: stdin, Timeout: left, MaxOutput: maxOut,
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
func (r *gitRepo) output(sub ...string) ([]byte, error) { return r.outputWith(nil, sub...) }

// outputWith is output with runWith's added environment.
func (r *gitRepo) outputWith(env []string, sub ...string) ([]byte, error) {
	res, err := r.runWith(env, nil, r.s.p.Limits.MaxOutputBytes, sub...)
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
			"(only the data-only keys listed in POLICY §7); remove it on the host with `%s` in the repository. "+
			"Git LFS repositories are not supported in v1: LFS works through filter programs", safeKey(key), safeKey(gitx.RemovalHint(key)))
	}
	r.s.o.afterGitConfigCheck(r.real)
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
