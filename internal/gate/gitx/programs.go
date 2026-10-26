package gitx

import "strings"

// Configuration keys that make git run a program (POLICY §7, handoff N-20),
// and what keeps the gate's git from running one. This table is the one
// place the gate's command-line overrides and program-naming environment
// come from (ops.GitArgs, ops.GitEnv), and the one place
// TestGitProgramKeysCovered checks against the installed git's own list of
// keys (`git help --config`) and hook events (githooks(5)), so that a git
// that adds a hook event or a program-running key the gate does not cover
// fails the test. A key whose name holds a part the repository chooses can
// never be forced with -c; it is marked Chain: covered by the closed
// repository chain.
//
// Which keys run programs: a key is treated as naming a program or command
// to run when its last component (its variable name, lowercased) ends in
// cmd, command, program, editor, askpass, pager, helper, driver, external,
// textconv, clean, smudge, process, tunnel, browser, viewer, httpd or hook;
// or is gitproxy, fsmonitor, hookspath, vcs, uploadpack, receivepack or
// smtpserver; or is path in the difftool, mergetool, browser and man
// sections (a tool's program); or the key is in the alias, pager or hook
// section (ProgramKeyName). The rule errs towards too many: a key it
// matches that runs nothing (a boolean such as advice.waitingForEditor) is
// listed below as not a program. Written from git 2.55's
// Documentation/config, where each such key is described as a command, a
// program or a helper git runs. A key whose name the rule does not
// recognise is not caught: the rule is a check, not a proof.

// ProgramKey is one such key, as `git help --config` prints it, and how it
// is covered: forced with -c (Args), overridden by environment variables
// that take precedence over it (Env), forced for every hook event
// (PerEvent), covered by the closed repository chain (Chain), and why
// (Why) where no override applies.
type ProgramKey struct {
	Key      string
	Args     []string // "key=value", passed as -c on every git process
	Env      []string // "NAME=value", set on every git process
	PerEvent bool     // hook.<event>.enabled=false for every HookEvents entry
	// Chain: covered by the closed repository chain (fsx.CheckGitRepo):
	// the key's name holds a part the repository chooses (<driver>,
	// <name>, <url>, *), which no -c can target. Set for every such key.
	Chain bool
	Why   string
}

// Why a key needs no override.
const (
	// The repository chooses the name, so no -c can target it: covered by
	// the closed repository chain (Chain), which keeps any other account
	// from adding it between the configuration check and git's use of it;
	// the allowlist refuses it at the check.
	whyNamed = "named by the repository, so no -c can override it: covered by the closed repository chain, which keeps every other account from adding it after the configuration check, and refused by the allowlist at the check"
	// Read only by commands the gate never runs (the gate runs status,
	// log, diff, config, rev-parse, ls-remote, pull, merge-base, ls-tree,
	// read-tree, checkout-index, update-index and clean).
	whyNotRun = "read only by commands the gate never runs"
	// The rule matched, but the value names no program.
	whyNotProgram = "not a program"
)

// ProgramKeys is the table (git 2.55).
var ProgramKeys = []ProgramKey{
	// Forced on every git process.
	{Key: "core.editor", Args: []string{"core.editor=/bin/false"}, Env: []string{"GIT_EDITOR=/bin/false"}},
	{Key: "sequence.editor", Args: []string{"sequence.editor=/bin/false"}, Env: []string{"GIT_SEQUENCE_EDITOR=/bin/false"}},
	{Key: "core.askPass", Args: []string{"core.askPass=/bin/false"}, Env: []string{"GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false"}},
	{Key: "core.pager", Args: []string{"core.pager=cat"}, Env: []string{"GIT_PAGER=cat"}},
	{Key: "core.sshCommand", Args: []string{"core.sshCommand=/bin/false"}, Env: []string{"GIT_SSH_COMMAND=/bin/false", "GIT_SSH=/bin/false"}},
	{Key: "core.fsmonitor", Args: []string{"core.fsmonitor=false"}},
	{Key: "core.hooksPath", Args: []string{"core.hooksPath=/dev/null"}},
	{Key: "core.alternateRefsCommand", Args: []string{"core.alternateRefsCommand=/bin/false"}},
	{Key: "credential.helper", Args: []string{"credential.helper="}},
	{Key: "diff.external", Args: []string{"diff.external=/bin/false"}, Env: []string{"GIT_EXTERNAL_DIFF=/bin/false"}},
	{Key: "gpg.program", Args: []string{"gpg.program=/bin/false"}},
	{Key: "gpg.<format>.program", Args: []string{"gpg.openpgp.program=/bin/false", "gpg.x509.program=/bin/false", "gpg.ssh.program=/bin/false"}},
	{Key: "gpg.ssh.defaultKeyCommand", Args: []string{"gpg.ssh.defaultKeyCommand=/bin/false"}},
	// Its first match wins and the repository's configuration is read
	// before the command line, so no -c overrides it; the variable, set
	// (empty: no proxy), replaces every configured value.
	{Key: "core.gitProxy", Env: []string{"GIT_PROXY_COMMAND="}},
	// Hooks defined in configuration, whatever core.hooksPath says.
	{Key: "hook.<event>.enabled", PerEvent: true},
	{Key: "hook.<friendly-name>.command", PerEvent: true, Chain: true, Why: whyNamed},
	{Key: "pager.<cmd>", Chain: true, Why: "covered by --no-pager on every git command"},

	// Named by the repository.
	{Key: "alias.*", Chain: true, Why: whyNamed + "; an alias never replaces a built-in command"},
	{Key: "alias.*.command", Chain: true, Why: whyNamed + "; an alias never replaces a built-in command"},
	{Key: "diff.<driver>.command", Chain: true, Why: whyNamed},
	{Key: "diff.<driver>.textconv", Chain: true, Why: whyNamed},
	{Key: "filter.<driver>.clean", Chain: true, Why: whyNamed},
	{Key: "filter.<driver>.smudge", Chain: true, Why: whyNamed},
	{Key: "filter.<driver>.process", Chain: true, Why: whyNamed},
	{Key: "merge.<driver>.driver", Chain: true, Why: whyNamed},
	{Key: "credential.<url>.helper", Chain: true, Why: whyNamed},
	{Key: "remote.<name>.uploadpack", Chain: true, Why: whyNamed},
	{Key: "remote.<name>.receivepack", Chain: true, Why: whyNamed},
	{Key: "remote.<name>.vcs", Chain: true, Why: whyNamed},
	{Key: "hook.<friendly-name>.event", Chain: true, Why: whyNamed},
	{Key: "hook.<friendly-name>.enabled", Chain: true, Why: whyNamed},
	{Key: "hook.<friendly-name>.parallel", Chain: true, Why: whyNamed},
	{Key: "trailer.<key-alias>.cmd", Chain: true, Why: whyNamed},
	{Key: "trailer.<key-alias>.command", Chain: true, Why: whyNamed},

	// Never read by the gate's commands.
	{Key: "browser.<tool>.cmd", Chain: true, Why: whyNotRun},
	{Key: "browser.<tool>.path", Chain: true, Why: whyNotRun},
	{Key: "difftool.<tool>.cmd", Chain: true, Why: whyNotRun},
	{Key: "difftool.<tool>.path", Chain: true, Why: whyNotRun},
	{Key: "mergetool.<tool>.cmd", Chain: true, Why: whyNotRun},
	{Key: "mergetool.<tool>.path", Chain: true, Why: whyNotRun},
	{Key: "guitool.<name>.cmd", Chain: true, Why: whyNotRun},
	{Key: "man.<tool>.cmd", Chain: true, Why: whyNotRun},
	{Key: "man.<tool>.path", Chain: true, Why: whyNotRun},
	{Key: "man.viewer", Why: whyNotRun},
	{Key: "help.browser", Why: whyNotRun},
	{Key: "web.browser", Why: whyNotRun},
	{Key: "instaweb.browser", Why: whyNotRun},
	{Key: "instaweb.httpd", Why: whyNotRun},
	{Key: "imap.tunnel", Why: whyNotRun},
	{Key: "interactive.diffFilter", Why: whyNotRun},
	{Key: "sendemail.ccCmd", Why: whyNotRun},
	{Key: "sendemail.headerCmd", Why: whyNotRun},
	{Key: "sendemail.toCmd", Why: whyNotRun},
	{Key: "sendemail.smtpServer", Why: whyNotRun},
	{Key: "uploadpack.packObjectsHook", Why: whyNotRun + " (upload-pack, on a server; read only from protected configuration)"},
	{Key: "gc.recentObjectsHook", Why: whyNotRun + " (gc and repack; gc.auto=0 and maintenance.auto=false keep pull from starting either)"},

	// Matched by the rule, but no program.
	{Key: "advice.ignoredHook", Why: whyNotProgram},
	{Key: "advice.waitingForEditor", Why: whyNotProgram},
	{Key: "color.pager", Why: whyNotProgram},
	{Key: "column.clean", Why: whyNotProgram},
	{Key: "gitcvs.dbDriver", Why: whyNotProgram},
	{Key: "diff.<driver>.cachetextconv", Chain: true, Why: whyNotProgram},
	{Key: "hook.<event>.jobs", Chain: true, Why: whyNotProgram},
	{Key: "hook.jobs", Why: whyNotProgram},
}

// HookEvents are the hook events of githooks(5) in git 2.55; each gets
// hook.<event>.enabled=false, which turns off every hook of the event,
// configured ones included.
var HookEvents = []string{
	"applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg",
	"post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
	"post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
	"fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-index-change",
}

// ProgramOverrides returns every -c value of the table, in its order,
// followed by hook.<event>.enabled=false for each of HookEvents.
func ProgramOverrides() []string {
	var out []string
	for i := range ProgramKeys {
		out = append(out, ProgramKeys[i].Args...)
	}
	for _, e := range HookEvents {
		out = append(out, "hook."+e+".enabled=false")
	}
	return out
}

// ProgramEnv returns every environment setting of the table, each once.
func ProgramEnv() []string {
	var out []string
	seen := map[string]bool{}
	for i := range ProgramKeys {
		for _, e := range ProgramKeys[i].Env {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// ProgramKeyName reports whether key, as `git help --config` prints it,
// names a program or command to run under the rule above.
func ProgramKeyName(key string) bool {
	parts := strings.Split(key, ".")
	section, name := strings.ToLower(parts[0]), strings.ToLower(parts[len(parts)-1])
	switch section {
	case "alias", "pager", "hook":
		return true
	}
	switch name {
	case "gitproxy", "fsmonitor", "hookspath", "vcs", "uploadpack", "receivepack", "smtpserver":
		return true
	case "path":
		switch section {
		case "difftool", "mergetool", "browser", "man":
			return true
		}
	}
	for _, s := range []string{"cmd", "command", "program", "editor", "askpass", "pager", "helper", "driver", "external", "textconv",
		"clean", "smudge", "process", "tunnel", "browser", "viewer", "httpd", "hook"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// ThreadKey is a configuration key whose default makes git start threads
// or processes in proportion to the host's CPUs (online_cpus()), as
// `git help --config` prints it, and how the gate pins it: forced with -c
// on every git process (Args), or why it needs no override (Why). Each
// thread's stack counts against the child memory limit (RLIMIT_DATA), so
// pinning them keeps a git operation's memory need the same on every host
// (handoff N-30).
type ThreadKey struct {
	Key  string
	Args []string
	Why  string
}

// Why a thread key needs no override.
const (
	whyHooksOff = "hooks only, and every hook is disabled (hook.<event>.enabled=false, core.hooksPath=/dev/null)"
	whyWorkers  = "read only when checkout.workers is above 1, which is pinned to 1"
)

// ThreadKeys is the table (git 2.55). The values are fixed, so a git
// process starts the same threads on every host; each is a thread count
// git accepts (thread-utils, index-pack, read-cache, preload-index,
// parallel-checkout, fetch, submodule-config).
var ThreadKeys = []ThreadKey{
	// index-pack (a pull's fetch): online_cpus()/2, at most 20 threads,
	// without it.
	{Key: "pack.threads", Args: []string{"pack.threads=" + PackThreads}},
	// Reading and writing the index: one thread unless set (read-cache.c);
	// pinned so that no configuration turns on online_cpus() threads.
	{Key: "index.threads", Args: []string{"index.threads=1"}},
	// The lstat preload of status, diff and update-index: one thread per
	// 500 entries, at most 20, whatever the CPUs (preload-index.c).
	{Key: "core.preloadIndex", Args: []string{"core.preloadIndex=" + PreloadIndex}},
	{Key: "checkout.workers", Args: []string{"checkout.workers=1"}},
	{Key: "checkout.thresholdForParallelism", Why: whyWorkers},
	{Key: "grep.threads", Args: []string{"grep.threads=1"}},
	{Key: "fetch.parallel", Args: []string{"fetch.parallel=1"}},
	{Key: "submodule.fetchJobs", Args: []string{"submodule.fetchJobs=1"}},
	{Key: "repack.cruftThreads", Why: whyNotRun},
	{Key: "hook.jobs", Why: whyHooksOff},
	{Key: "hook.<event>.jobs", Why: whyHooksOff},
	{Key: "hook.<friendly-name>.parallel", Why: whyHooksOff},
}

// The pinned values of the two thread keys whose fixed value is a choice
// (handoff N-30, measured in S6-1 on git 2.47.3 with 32 CPUs): index-pack
// of git's own 222 MB pack took 8.6 s and 278 MiB with 4 threads, 9.1 s and
// 485 MiB with git's default (16 there), 14.0 s and 203 MiB with 1; the
// preload's lstat threads follow the index's size, not the CPUs, and make
// status on a 1,000,000-entry index take 0.7 s instead of 1.6 s.
const (
	PackThreads  = "4"
	PreloadIndex = "true"
)

// ThreadOverrides returns every -c value of ThreadKeys, in its order.
func ThreadOverrides() []string {
	var out []string
	for i := range ThreadKeys {
		out = append(out, ThreadKeys[i].Args...)
	}
	return out
}

// ThreadKeyName reports whether key, as `git help --config` prints it,
// sets how many threads, workers or parallel jobs git runs: its variable
// name (last component, lowercased) ends in threads, workers, jobs or
// parallel, or is preloadindex or thresholdforparallelism. Like
// ProgramKeyName, the rule errs towards too many and is a check, not a
// proof: git's own online_cpus() callers in 2.55 (index-pack, pack-objects,
// grep, read-cache, preload-index, parallel checkout, fetch, submodule
// fetches, hooks, name-hash) were read to write the table.
func ThreadKeyName(key string) bool {
	parts := strings.Split(key, ".")
	name := strings.ToLower(parts[len(parts)-1])
	switch name {
	case "preloadindex", "thresholdforparallelism":
		return true
	}
	for _, s := range []string{"threads", "workers", "jobs", "parallel"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}
