//go:build linux && shellmcp_confine_hook

package fsx

// The shellmcp_confine_hook test build, never released: hooks that turn off
// one read-confinement layer (confineLayer) and run code at named points of
// a lookup, so that tests can show which layer refuses a swapped path when
// another is gone (handoff N-12). scripts/release-binary-check.sh refuses a
// binary built with the tag, by its build settings and by this text in the
// binary.
const confineHookBuild = "shellmcp_confine_hook test build"

// confineHooks holds the test build's hooks; the gate and the helper set
// none.
type confineHooks struct {
	// confineOff, when set, turns off that one layer.
	confineOff confineLayer
	// confineAt, when set, is called with confineHookBuild and the point
	// reached: "parent" (locate, before it opens the parent), "target"
	// (openTarget and openDirRoot, before the target's lstat) and "open"
	// (after that lstat, before the target is opened).
	confineAt func(build, point string)
}

func (h confineHooks) layerOff(l confineLayer) bool { return l != layerNone && h.confineOff == l }

func (h confineHooks) at(point string) {
	if h.confineAt != nil {
		h.confineAt(confineHookBuild, point)
	}
}
