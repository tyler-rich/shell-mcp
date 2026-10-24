package gitx

import "strings"

// Submodules (POLICY §7, handoff N-23): no git process the gate starts
// ever enters a submodule. Git's status and diff check every populated
// gitlink for changes by starting `git status` inside it
// (is_submodule_modified, submodule.c, git 2.55), which runs under that
// repository's own configuration: the allowlist never sees it and the
// closed repository rule does not cover directories inside the work tree.
// This table is the one place the gate's submodule overrides come from
// (ops.GitArgs), and the one place TestGitSubmoduleKeysCovered checks
// against the installed git's own list of keys, and
// TestGitWorkTreeCommandsIgnoreSubmodules against every git process the
// gate's operations start.
//
// Which keys: a key is treated as able to make a command enter a submodule
// when its section is submodule or its name holds "submodule"
// (SubmoduleKeyName). As for ProgramKeyName, the rule is a check, not a
// proof.
//
// Which wins (git 2.55): --ignore-submodules=<when> on the command line
// sets override_submodule_config (diff.c, wt-status.c), so neither
// diff.ignoreSubmodules nor any submodule.<name>.ignore (from .gitmodules
// or the configuration) is consulted; diff.ignoreSubmodules alone only sets
// the default, which a submodule.<name>.ignore overrides
// (set_diffopt_flags_from_submodule_config, submodule.c). So every command
// that can read the work tree carries the flag, and the -c values are a
// second layer. pull's --no-recurse-submodules reaches its fetch as
// --recurse-submodules=no, which wins over fetch.recurseSubmodules and
// every submodule.<name>.fetchRecurseSubmodules (builtin/fetch.c); its
// merge takes no such flag and reads only submodule.recurse.

// SubmoduleKey is one such key, as `git help --config` prints it, and how
// it is covered: forced with -c (Args), beaten by a command-line flag on
// every gate command that reads it (Flag), and why (Why) where neither
// applies or as well.
type SubmoduleKey struct {
	Key  string
	Args []string // "key=value", passed as -c on every git process
	Flag string   // the command-line flag that takes precedence over it
	Why  string
}

// Why a key needs no override.
const (
	// Read only by commands the gate never runs (the gate runs status,
	// log, diff, config, rev-parse, ls-remote, pull, merge-base, ls-tree,
	// read-tree, checkout-index, update-index and clean).
	whySubNotRun = "read only by commands the gate never runs"
	// Read only when a command recurses into submodules, which
	// submodule.recurse=false, fetch.recurseSubmodules=false and
	// --no-recurse-submodules keep off.
	whySubNoRecurse = "read only when a command recurses into submodules, which submodule.recurse=false, fetch.recurseSubmodules=false and pull's --no-recurse-submodules keep off"
	// The repository names it, so no -c can target it.
	whySubNamed = "named by the repository, so no -c can override it"
)

// SubmoduleKeys is the table (git 2.55).
var SubmoduleKeys = []SubmoduleKey{
	{Key: "diff.ignoreSubmodules", Args: []string{"diff.ignoreSubmodules=all"}, Flag: "--ignore-submodules",
		Why: "the default of --ignore-submodules for status and diff; every gate status and diff passes the flag, which wins"},
	{Key: "diff.submodule", Args: []string{"diff.submodule=short"}, Flag: "--submodule=short",
		Why: "log walks a submodule's history, diff starts git diff in it; short only names the two commits"},
	{Key: "status.submoduleSummary", Args: []string{"status.submoduleSummary=false"},
		Why: "the long format's summary starts git submodule summary; the gate's porcelain status never prints it"},
	{Key: "submodule.recurse", Args: []string{"submodule.recurse=false"},
		Why: "the default of --recurse-submodules; pull's merge and read-tree read it"},
	{Key: "fetch.recurseSubmodules", Args: []string{"fetch.recurseSubmodules=false"}, Flag: "--no-recurse-submodules",
		Why: "pull's fetch; pull passes --recurse-submodules=no to it, which wins"},
	{Key: "submodule.<name>.ignore", Flag: "--ignore-submodules",
		Why: whySubNamed + "; --ignore-submodules on the command line means it is never consulted"},
	{Key: "submodule.<name>.fetchRecurseSubmodules", Flag: "--no-recurse-submodules",
		Why: whySubNamed + "; pull's --no-recurse-submodules reaches its fetch, which then never consults it"},
	{Key: "submodule.<name>.active", Why: whySubNamed + "; " + whySubNoRecurse},
	{Key: "submodule.active", Why: whySubNoRecurse},
	{Key: "submodule.fetchJobs", Why: whySubNoRecurse},
	{Key: "submodule.<name>.gitdir", Why: whySubNamed + "; where a submodule's repository is, read only with extensions.submodulePathConfig, which the allowlist refuses (extensions.*)"},
	{Key: "extensions.submodulePathConfig", Why: "refused by the allowlist (extensions.*); it only says where submodules' repositories are"},
	{Key: "submodule.<name>.url", Why: whySubNamed + "; " + whySubNotRun + " (git submodule)"},
	{Key: "submodule.<name>.update", Why: whySubNamed + "; " + whySubNotRun + " (git submodule update)"},
	{Key: "submodule.<name>.branch", Why: whySubNamed + "; " + whySubNotRun + " (git submodule update)"},
	{Key: "submodule.alternateLocation", Why: whySubNotRun + " (clone and git submodule update)"},
	{Key: "submodule.alternateErrorStrategy", Why: whySubNotRun + " (clone and git submodule update)"},
	{Key: "submodule.propagateBranches", Why: whySubNotRun + " (branch)"},
	{Key: "push.recurseSubmodules", Why: whySubNotRun + " (push)"},
	{Key: "clone.filterSubmodules", Why: whySubNotRun + " (clone)"},
	{Key: "init.defaultSubmodulePathConfig", Why: whySubNotRun + " (init and clone)"},
	{Key: "advice.submoduleAlternateErrorStrategyDie", Why: "a hint on stderr"},
	{Key: "advice.submoduleMergeConflict", Why: "a hint on stderr"},
	{Key: "advice.submodulesNotUpdated", Why: "a hint on stderr"},
}

// GitCommand is one git subcommand the gate runs: whether some run of it
// can read the work tree, the flag that keeps such a run out of every
// submodule, and why (Why) where it takes none or reads no work tree.
// TreeForms: a run with --cached, or comparing two commits, reads no work
// tree, and passes --ignore-submodules=dirty or =none so that gitlink
// commit changes still show.
type GitCommand struct {
	Name      string
	WorkTree  bool
	Flag      string
	TreeForms bool
	Why       string
}

// GitCommands is every subcommand the gate runs (git 2.55).
var GitCommands = []GitCommand{
	{Name: "status", WorkTree: true, Flag: "--ignore-submodules=all"},
	{Name: "diff", WorkTree: true, Flag: "--ignore-submodules=all", TreeForms: true},
	{Name: "update-index", WorkTree: true, Flag: "--ignore-submodules",
		Why: "only --refresh, which with the flag skips every gitlink"},
	{Name: "pull", WorkTree: true, Flag: "--no-recurse-submodules",
		Why: "its fetch gets --recurse-submodules=no; its merge, which updates the work tree, takes no flag and reads only submodule.recurse, forced false"},
	{Name: "clean", WorkTree: true,
		Why: "takes no such flag: -n lists untracked paths within the process, skips a nested repository without entering it (dir.c) and starts no process"},
	{Name: "checkout-index", WorkTree: true,
		Why: "takes no such flag: writes only the listed files and symlinks, never a gitlink (the discard refuses gitlink changes), and starts no process in a submodule while submodule.recurse is false"},
	{Name: "log", Why: "reads commits only"},
	{Name: "config", Why: "reads the repository's configuration file only"},
	{Name: "rev-parse", Why: "reads refs only"},
	{Name: "ls-remote", Why: "asks the remote only"},
	{Name: "merge-base", Why: "reads commits only"},
	{Name: "ls-tree", Why: "reads trees only"},
	{Name: "read-tree", Why: "without -u, writes only the index"},
}

// SubmoduleKeyName reports whether key, as `git help --config` prints it,
// can make a command enter a submodule under the rule above (a key in the
// submodule section holds the word too).
func SubmoduleKeyName(key string) bool {
	return strings.Contains(strings.ToLower(key), "submodule")
}

// ParseStagedGitlinks parses `git diff --cached --raw -z --no-renames`
// and returns the staged gitlink changes. Not implemented yet.
func ParseStagedGitlinks(b []byte, maxEntries int) (entries []Entry, truncated bool, err error) {
	_, _ = b, maxEntries
	return nil, false, bad("staged gitlinks: not implemented")
}
