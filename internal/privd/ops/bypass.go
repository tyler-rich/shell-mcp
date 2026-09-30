//go:build linux

package ops

// BypassBuild is true only in the e2e test build of the helper (build tag
// shellmcp_e2e_bypass, bypass_e2e.go), which skips Landlock and adds raw
// file operations so that the end-to-end tests can prove that the
// generated systemd unit alone confines the helper. Release builds never
// set the tag; TestNoBypassInThisBuild and the CI cross-build check that.
var BypassBuild = false

// extraOps are the bypass build's additional operations (none otherwise).
var extraOps = map[string]opSpec{}
