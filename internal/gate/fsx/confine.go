//go:build linux && !shellmcp_confine_hook

package fsx

import (
	"errors"
	"os"
)

// confineHooks holds hooks that exist only in a test build
// (confine_hook.go). In a release build it is empty, every
// read-confinement layer is on, and its methods do nothing.
type confineHooks struct{}

// layerOff reports whether the test build turned off one read-confinement
// layer; never in a release build.
func (confineHooks) layerOff(confineLayer) bool { return false }

// at runs the test build's hook at a named point of a lookup.
func (confineHooks) at(string) {}

// errNoLookupByPath answers the lookups by path string that stand in for
// the descriptor layer in the test build. A release build has none: it
// never calls these, since layerOff is always false, and they open nothing.
// (Its text must not name the test build's tag, which
// scripts/release-binary-check.sh refuses in a release binary.)
var errNoLookupByPath = errors.New("fsx: no lookup by path in this build")

func (confineHooks) rootByPath(string) (*os.Root, error) { return nil, errNoLookupByPath }

func (confineHooks) fileByPath(string, int) (*os.File, error) { return nil, errNoLookupByPath }
