// Package runner is the guard for the end-to-end tests. They change the
// machine they run on (accounts, units, policies, packages, a second sshd)
// as root, so they run only on a disposable GitHub-hosted Actions runner:
// Linux, GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted. The e2e
// test binary checks this before anything else; test/e2e/setup.sh does the
// same in its first lines.
package runner

import (
	"errors"
	"os"
	"runtime"
)

// ErrNotRunner is the refusal.
var ErrNotRunner = errors.New("refusing to run: the end-to-end tests change the machine and run only on a GitHub-hosted Actions runner (Linux, GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted)")

// CheckEnv returns ErrNotRunner unless goos is linux and getenv reports
// exactly GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted.
func CheckEnv(goos string, getenv func(string) string) error {
	if goos != "linux" || getenv("GITHUB_ACTIONS") != "true" || getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return ErrNotRunner
	}
	return nil
}

// Check checks this process.
func Check() error { return CheckEnv(runtime.GOOS, os.Getenv) }

// Env is the runner's own two variables, for a child of the test binary
// (which checks them again before anything else).
func Env() []string {
	return []string{"GITHUB_ACTIONS=" + os.Getenv("GITHUB_ACTIONS"), "RUNNER_ENVIRONMENT=" + os.Getenv("RUNNER_ENVIRONMENT")}
}
