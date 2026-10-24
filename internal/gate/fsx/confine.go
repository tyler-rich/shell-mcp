//go:build linux && !shellmcp_confine_hook

package fsx

// confineHooks holds hooks that exist only in a test build
// (confine_hook.go). In a release build it is empty, every
// read-confinement layer is on, and its methods do nothing.
type confineHooks struct{}

// layerOff reports whether the test build turned off one read-confinement
// layer; never in a release build.
func (confineHooks) layerOff(confineLayer) bool { return false }

// at runs the test build's hook at a named point of a lookup.
func (confineHooks) at(string) {}
