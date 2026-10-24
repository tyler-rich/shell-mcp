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
//	    -c maintenance.auto=false -c gc.auto=0
//	    -c gc.autoDetach=false -c core.ignorecase=false
//	    -c <every program-running key with a fixed name>=/bin/false
//	    -c hook.<every event>.enabled=false
//	    -c diff.ignoreSubmodules=all -c diff.submodule=short
//	    -c status.submoduleSummary=false -c submodule.recurse=false
//	    -c fetch.recurseSubmodules=false <subcommand> …
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
// either. There is no safe.directory: git applies its ownership check only
// to a repository it discovers (setup.c, git 2.55), never to one GIT_DIR
// names, as the gate's always is, and the git processes it starts in a
// submodule get GIT_DIR=.git explicitly too (prepare_other_repo_env,
// run-command.c), so safe.directory=<repo> did nothing (POLICY §7).
//
// No git process enters a submodule (handoff N-23): such a process would
// run under the submodule's own configuration, which nothing above covers.
// Every run that can read the work tree carries --ignore-submodules=all
// (status, the work-tree diff), --ignore-submodules (update-index
// --refresh) or --no-recurse-submodules (pull), or takes no such flag and
// starts no process in a submodule (clean, checkout-index); runs that
// compare only the index or commits pass =dirty or =none, so that gitlink
// commit changes still show; the submodule -c values above are a second
// layer (gitx.GitCommands, gitx.SubmoduleKeys).

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
		// No automatic maintenance or gc: git would otherwise start
		// `git maintenance run --auto --detach` after a pull, which
		// daemonizes (setsid) out of the gate's process group and outlives
		// the request. Case sensitivity is pinned: a repo-local
		// core.ignorecase=true would hide untracked files from status and
		// clean on a case-sensitive filesystem.
		"-c", "maintenance.auto=false", "-c", "gc.auto=0", "-c", "gc.autoDetach=false", "-c", "core.ignorecase=false"}
	// Every program-running key with a fixed name, and
	// hook.<event>.enabled=false for every hook event (hooks defined in
	// configuration run whatever core.hooksPath says), from gitx's table,
	// so that none the repository sets after the configuration check runs
	// anything (handoff N-20). The command line is read last and wins for
	// each of them. Those on the first lines above are not repeated.
	for _, o := range gitx.ProgramOverrides() {
		if !slices.Contains(a, o) {
			a = append(a, "-c", o)
		}
	}
	// The submodule keys (handoff N-23): a second layer under the
	// --ignore-submodules and --no-recurse-submodules flags of every
	// command that can read the work tree (gitx.GitCommands), and the only
	// one for pull's merge, which takes no such flag.
	for _, o := range gitx.SubmoduleOverrides() {
		a = append(a, "-c", o)
	}
	if caFile != "" {
		a = append(a, "-c", "http.sslCAInfo="+caFile)
	}
	return append(a, sub...)
}

// GitEnv returns git's exact environment for the repository at repo. The
// variables that would name a program (gitx.ProgramEnv) are set to ones
// that run nothing: they take precedence over the matching configuration
// keys, and GIT_PROXY_COMMAND, set even empty, over every core.gitProxy.
func GitEnv(home, repo string) []string {
	return append(append(execx.Environment(home), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_DIR="+repo+"/.git", "GIT_WORK_TREE="+repo), gitx.ProgramEnv()...)
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
// Status never enters a submodule (--ignore-submodules=all, handoff N-23),
// which also hides staged gitlink changes, so those, the repository's own
// index, are added from stagedGitlinks, in path order among the tracked
// entries. A submodule's own work tree (its commits, edits and untracked
// files) is never reported.
func (r *gitRepo) status(untracked string, branch bool) (gitx.Status, bool, error) {
	args := []string{"status", "--porcelain=v2", "-z", "--untracked-files=" + untracked, "--ignore-submodules=all"}
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
	links, cut, err := r.stagedGitlinks()
	if err != nil {
		return gitx.Status{}, false, err
	}
	st.Entries, truncated = mergeGitlinks(st.Entries, links, truncated || cut)
	return st, truncated, nil
}

// stagedGitlinks lists the gitlinks whose index entry differs from HEAD's
// (added, removed, moved to another commit or changed type), from a
// comparison of the index with HEAD (the empty tree in a repository without
// commits) that never looks at the work tree, so it enters no submodule;
// =dirty makes the command line, not a submodule.<name>.ignore, decide that
// gitlink commit changes are shown.
func (r *gitRepo) stagedGitlinks() ([]gitx.Entry, bool, error) {
	out, err := r.output("diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", "--no-ext-diff", "--no-textconv", "--ignore-submodules=dirty")
	if err != nil {
		return nil, false, err
	}
	links, truncated, err := gitx.ParseStagedGitlinks(out, maxGitEntries)
	if err != nil {
		return nil, false, errf(protocol.CodeExecFailed, "git diff output could not be parsed")
	}
	return links, truncated, nil
}

// mergeGitlinks adds the staged gitlink entries status did not report
// (status reports a type change from or to a gitlink itself) to its
// tracked entries, which stay in path order before the untracked and
// ignored ones, keeping at most maxGitEntries.
func mergeGitlinks(ents, links []gitx.Entry, truncated bool) ([]gitx.Entry, bool) {
	if len(links) == 0 {
		return ents, truncated
	}
	seen := map[string]bool{}
	var tracked, rest []gitx.Entry
	for _, e := range ents {
		seen[e.Path] = true
		if e.Kind == "untracked" || e.Kind == "ignored" {
			rest = append(rest, e)
		} else {
			tracked = append(tracked, e)
		}
	}
	for _, l := range links {
		if !seen[l.Path] {
			tracked = append(tracked, l)
		}
	}
	slices.SortStableFunc(tracked, func(a, b gitx.Entry) int { return strings.Compare(a.Path, b.Path) })
	tracked = append(tracked, rest...)
	if len(tracked) > maxGitEntries {
		return tracked[:maxGitEntries], true
	}
	return tracked, truncated
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
	// A gitlink shows as the two commit ids at most (--submodule=short),
	// never a submodule's history or diff. The work-tree diff never enters
	// a submodule (=all); the staged diff compares the index with HEAD only,
	// so it still shows staged gitlink changes (=dirty; handoff N-23).
	args := []string{"diff", "--no-color", "--no-ext-diff", "--no-textconv", "--submodule=short", "--ignore-submodules=all"}
	if a.Staged {
		args = append(args[:len(args)-1], "--cached", "--ignore-submodules=dirty")
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
			// Two commits, no work tree: a gitlink the pull moved counts
			// (=none, whatever diff.ignoreSubmodules says).
			names, err = r.output("diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", old, nw)
		}
		if err != nil {
			return nil, nil, err
		}
		d.ChangedFiles = bytes.Count(names, []byte{0})
	}
	return d, nil, nil
}
