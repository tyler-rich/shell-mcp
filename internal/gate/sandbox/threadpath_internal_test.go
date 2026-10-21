//go:build linux && !landlock_forcepsx

package sandbox

import "testing"

// TestThreadPathDecision: a release build plans for the kernel's own ABI
// and takes go-landlock's path for it, psx below ABI 8 and TSYNC from 8.
func TestThreadPathDecision(t *testing.T) {
	for abi, want := range map[int]string{0: "none", 1: "psx", 6: "psx", 7: "psx", 8: "tsync", 9: "tsync", 10: "tsync"} {
		if got := capABI(abi); got != abi {
			t.Errorf("ABI %d planned as %d", abi, got)
		}
		if got := threadPath(capABI(abi)); got != want {
			t.Errorf("ABI %d: path %s, want %s", abi, got, want)
		}
	}
}
