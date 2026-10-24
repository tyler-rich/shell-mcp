//go:build linux && shellmcp_confine_hook

package fsx

import "os"

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

// layerNone is confineOff's zero value: every layer on.
const layerNone confineLayer = 0

func (h confineHooks) layerOff(l confineLayer) bool { return l != layerNone && h.confineOff == l }

// rootByPath and fileByPath stand in for the descriptor layer when it is
// turned off: they open a path string from /, following every symlink, as
// a lookup without the parent's os.Root would. Only this build has them.
func (confineHooks) rootByPath(p string) (*os.Root, error) { return os.OpenRoot(p) }

func (confineHooks) fileByPath(p string, flags int) (*os.File, error) {
	return os.OpenFile(p, flags, 0) //nolint:gosec // G304: the test build's stand-in for the descriptor layer opens by path on purpose

}

func (h confineHooks) at(point string) {
	if h.confineAt != nil {
		h.confineAt(confineHookBuild, point)
	}
}
