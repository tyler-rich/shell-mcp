//go:build linux

package fsx

// bypassForbiddenRoots is true only in the test build (build tag
// shellmcp_e2e_bypass, bypass_e2e.go), stub.
var bypassForbiddenRoots = false
