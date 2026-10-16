// Package runner is the guard for the end-to-end tests: they change the
// machine (accounts, units, policies, packages) and run only on a
// GitHub-hosted Actions runner. (stub)
package runner

// CheckEnv (stub).
func CheckEnv(string, func(string) string) error { return nil }

// Check (stub).
func Check() error { return nil }
