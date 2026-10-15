//go:build linux && shellmcp_e2e_bypass

package fsx

// The end-to-end test build skips the forbidden-root check (bypass.go). It
// must never be part of a release.
func init() { bypassForbiddenRoots = true }
