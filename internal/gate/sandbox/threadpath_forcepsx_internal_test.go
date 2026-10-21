//go:build linux && landlock_forcepsx

package sandbox

import "testing"

// TestThreadPathDecision (landlock_forcepsx test build): on a kernel at ABI
// 8 or above the sandbox plans as at ABI 7 and takes the psx path; below 8
// it plans for the kernel's own ABI, as a release build does.
func TestThreadPathDecision(t *testing.T) {
	for abi, c := range map[int]struct {
		planned int
		path    string
	}{
		0: {0, "none"}, 1: {1, "psx"}, 6: {6, "psx"}, 7: {7, "psx"},
		8: {7, "psx"}, 9: {7, "psx"}, 10: {7, "psx"},
	} {
		if got := capABI(abi); got != c.planned {
			t.Errorf("ABI %d planned as %d, want %d", abi, got, c.planned)
		}
		if got := threadPath(capABI(abi)); got != c.path {
			t.Errorf("ABI %d: path %s, want %s", abi, got, c.path)
		}
	}
}
