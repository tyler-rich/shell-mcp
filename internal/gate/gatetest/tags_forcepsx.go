//go:build linux && landlock_forcepsx

package gatetest

// tagArgs passes the landlock_forcepsx test build on to the binaries a test
// builds: the gate, the helper and the applier must take the psx path too.
func tagArgs() []string { return []string{"-tags", "landlock_forcepsx"} }
