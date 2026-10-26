//go:build linux

package policy_test

import (
	"strconv"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// FuzzMaxMemoryMB: limits.max_memory_mb is accepted exactly when it is in
// 128..16384, and then taken as written; anything else is refused, never
// clamped or defaulted (handoff N-30).
func FuzzMaxMemoryMB(f *testing.F) {
	for _, v := range []int64{0, -1, 127, 128, 1024, 16384, 16385, 1 << 40, -1 << 62} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v int64) {
		y := "version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\nlimits:\n  max_memory_mb: " + strconv.FormatInt(v, 10) + "\n"
		p, err := policy.Parse([]byte(y), "/etc/shell-mcp/policy.yaml", &policy.LoadOptions{
			Trust: gatetest.Trust(), GateExecutable: "/usr/local/bin/shell-mcp-gate", ServiceHome: "/home/svc-shell",
		})
		ok := v >= policy.MaxMemoryMBMin && v <= policy.MaxMemoryMBMax
		switch {
		case ok && err != nil:
			t.Fatalf("%d refused: %v", v, err)
		case ok && int64(p.Limits.MaxMemoryMB) != v:
			t.Fatalf("%d read as %d", v, p.Limits.MaxMemoryMB)
		case !ok && err == nil:
			t.Fatalf("%d accepted as %d", v, p.Limits.MaxMemoryMB)
		}
	})
}
