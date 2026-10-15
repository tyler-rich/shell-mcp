//go:build linux

package fsx

// bypassForbiddenRoots skips the check that a root never resolves to /, or
// into /proc, /sys, /dev or /run. It is true only in the end-to-end test
// build (build tag shellmcp_e2e_bypass, bypass_e2e.go), whose tests prove
// that the built-in read deny list refuses on its own with every root check
// out of the way. Release builds never set the tag: CI and ci-local fail if
// a built binary carries it, and TestNoForbiddenRootBypassInThisBuild
// checks the normal build.
var bypassForbiddenRoots = false
