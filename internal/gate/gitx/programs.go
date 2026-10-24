package gitx

import "strings"

// Configuration keys that make git run a program (POLICY §7, handoff N-20),
// and what keeps the gate's git from running one. This table is the one
// place the gate's command-line overrides and program-naming environment
// come from (ops.GitArgs, ops.GitEnv), and the one place
// TestGitProgramKeysCovered checks against the installed git's own list of
// keys (`git help --config`) and hook events (githooks(5)), so that a git
// that adds a hook event or a program-running key the gate does not cover
// fails the test.
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
// (PerEvent), or neither, for the reason Why.
type ProgramKey struct {
	Key      string
	Args     []string // "key=value", passed as -c on every git process
	Env      []string // "NAME=value", set on every git process
	PerEvent bool     // hook.<event>.enabled=false for every HookEvents entry
	Why      string
}

// Why a key needs no override.
const (
	// The repository chooses the name, so no -c can target it: gitx's
	// allowlist refuses it, and the closed repository rule keeps it from
	// appearing after the check.
	whyNamed = "named by the repository: refused by the allowlist, and kept out after the check by the closed repository rule"
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
	{Key: "hook.<friendly-name>.command", PerEvent: true, Why: whyNamed},
	{Key: "pager.<cmd>", Why: "covered by --no-pager on every git command"},

	// Named by the repository.
	{Key: "alias.*", Why: whyNamed + "; an alias never replaces a built-in command"},
	{Key: "alias.*.command", Why: whyNamed + "; an alias never replaces a built-in command"},
	{Key: "diff.<driver>.command", Why: whyNamed},
	{Key: "diff.<driver>.textconv", Why: whyNamed},
	{Key: "filter.<driver>.clean", Why: whyNamed},
	{Key: "filter.<driver>.smudge", Why: whyNamed},
	{Key: "filter.<driver>.process", Why: whyNamed},
	{Key: "merge.<driver>.driver", Why: whyNamed},
	{Key: "credential.<url>.helper", Why: whyNamed},
	{Key: "remote.<name>.uploadpack", Why: whyNamed},
	{Key: "remote.<name>.receivepack", Why: whyNamed},
	{Key: "remote.<name>.vcs", Why: whyNamed},
	{Key: "hook.<friendly-name>.event", Why: whyNamed},
	{Key: "hook.<friendly-name>.enabled", Why: whyNamed},
	{Key: "hook.<friendly-name>.parallel", Why: whyNamed},
	{Key: "trailer.<key-alias>.cmd", Why: whyNamed},
	{Key: "trailer.<key-alias>.command", Why: whyNamed},

	// Never read by the gate's commands.
	{Key: "browser.<tool>.cmd", Why: whyNotRun},
	{Key: "browser.<tool>.path", Why: whyNotRun},
	{Key: "difftool.<tool>.cmd", Why: whyNotRun},
	{Key: "difftool.<tool>.path", Why: whyNotRun},
	{Key: "mergetool.<tool>.cmd", Why: whyNotRun},
	{Key: "mergetool.<tool>.path", Why: whyNotRun},
	{Key: "guitool.<name>.cmd", Why: whyNotRun},
	{Key: "man.<tool>.cmd", Why: whyNotRun},
	{Key: "man.<tool>.path", Why: whyNotRun},
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
	{Key: "diff.<driver>.cachetextconv", Why: whyNotProgram},
	{Key: "hook.<event>.jobs", Why: whyNotProgram},
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

// LookupProgramKey returns the table's entry for key (compared without
// case), or nil.
func LookupProgramKey(key string) *ProgramKey {
	for i := range ProgramKeys {
		if strings.EqualFold(ProgramKeys[i].Key, key) {
			return &ProgramKeys[i]
		}
	}
	return nil
}
