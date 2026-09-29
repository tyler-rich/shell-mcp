//go:build linux

package ops

import "testing"

// TestNoBypassInThisBuild: the bypass operations and the Landlock skip
// exist only under the e2e test build tag, never in a normal (or release)
// build.
func TestNoBypassInThisBuild(t *testing.T) {
	if BypassBuild || len(extraOps) != 0 {
		t.Fatalf("bypass build: %v, extra ops %d", BypassBuild, len(extraOps))
	}
	for op := range opTable() {
		if len(op) < 5 || op[:5] != "priv_" {
			t.Fatalf("op %q is not a priv_ op", op)
		}
	}
}
