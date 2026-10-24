//go:build linux && !shellmcp_gitconfig_hook

package ops

// testHooks holds hooks that exist only in a test build
// (testhooks_gitconfig.go). In a release build it is empty and its methods
// do nothing.
type testHooks struct{}

// afterGitConfigCheck runs after a git operation's configuration check.
func (testHooks) afterGitConfigCheck(string) {}
