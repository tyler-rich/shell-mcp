//go:build linux

package ops

import (
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

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

// TestRulesUnscopeSignalsOnlyForCAPKILL: the helper's Landlock ruleset
// leaves signals unscoped exactly when a core-unit command declares
// CAP_KILL (maintainer decision, PRIVILEGED §5.1); otherwise signals stay
// scoped to the helper's domain from ABI 8.
func TestRulesUnscopeSignalsOnlyForCAPKILL(t *testing.T) {
	p := &policy.Policy{Capabilities: append([]string(nil), policy.BaseCapabilities...)}
	if Rules(p, "/var/lib/shell-mcp/backups").UnscopedSignals {
		t.Fatal("signals unscoped without CAP_KILL")
	}
	p.Capabilities = append(p.Capabilities, "CAP_SYS_BOOT")
	if Rules(p, "/var/lib/shell-mcp/backups").UnscopedSignals {
		t.Fatal("signals unscoped for CAP_SYS_BOOT")
	}
	p.Capabilities = append(p.Capabilities, "CAP_KILL")
	if !Rules(p, "/var/lib/shell-mcp/backups").UnscopedSignals {
		t.Fatal("signals still scoped with CAP_KILL declared")
	}
}
