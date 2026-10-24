//go:build linux && shellmcp_gitconfig_hook

package ops

// The shellmcp_gitconfig_hook test build, never released: a hook that runs
// after a git operation's configuration check (checkConfig) and before its
// next git process, so that tests can change the repository's
// configuration in between and show that git ignores what the check would
// have refused (handoff N-20). scripts/release-binary-check.sh refuses a
// binary built with the tag, by its build settings and by this text in the
// binary.
const gitConfigHookBuild = "shellmcp_gitconfig_hook test build"

// testHooks holds the test build's hooks; ProductionOptions sets none.
type testHooks struct {
	// AfterGitConfigCheck, when set, is called with gitConfigHookBuild and
	// the repository's real path once checkConfig accepted its
	// configuration.
	AfterGitConfigCheck func(build, repo string)
}

func (h testHooks) afterGitConfigCheck(repo string) {
	if h.AfterGitConfigCheck != nil {
		h.AfterGitConfigCheck(gitConfigHookBuild, repo)
	}
}
