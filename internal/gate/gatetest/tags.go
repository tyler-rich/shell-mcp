//go:build linux && !landlock_forcepsx

package gatetest

// tagArgs are the build tags Build and BuildTest pass on, so that the
// binaries a test builds take the same sandbox path as the test itself.
func tagArgs() []string { return nil }
