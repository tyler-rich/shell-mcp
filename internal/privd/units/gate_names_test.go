//go:build linux

package units_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// The gate's shared-account check reads the group of the helper's sockets
// under names of its own (the gate never links the helper's packages): they
// must be where these units listen.
func TestGateKnowsTheSocketPaths(t *testing.T) {
	var gate []string
	for _, s := range install.HelperSockets {
		gate = append(gate, filepath.Join(install.HelperRunDir, s))
	}
	if want := []string{units.SocketPath, units.BroadSocketPath}; !slices.Equal(gate, want) {
		t.Fatalf("the gate checks %v, the units listen on %v", gate, want)
	}
}
