//go:build linux

package policy_test

import (
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
)

// The built-in read deny list refuses other processes' environment and
// memory and the kernel's memory image (POLICY §3), as defence in depth
// behind Landlock and the rule that no root may be or be inside /proc. The
// gate and the helper both build their deny lists from it.
func TestBuiltinDenyCoversProcSecrets(t *testing.T) {
	m, err := pathx.NewMatcher(policy.BuiltinDeny())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/proc/1/environ", "/proc/self/environ", "/proc/4242/mem", "/proc/self/mem", "/proc/kcore", "/proc/1/task/1/environ", "/proc/self/task/4242/environ", "/proc/1/task/7/mem", "/proc/self/task/4242/mem"} {
		if !m.Covers(p) {
			t.Errorf("%s is not on the built-in read deny list", p)
		}
	}
	for _, p := range []string{"/proc/1/status", "/proc/meminfo", "/proc/self/cmdline", "/proc/1/task/1/status", "/proc/self/task/4242/cmdline"} {
		if m.Covers(p) {
			t.Errorf("%s is denied, but only environ, mem and kcore are", p)
		}
	}
}

// A loaded gate policy's deny list carries them.
func TestGatePolicyDeniesProcSecrets(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, "version: 1\nmax_tier: read\n")
	for _, d := range []string{"/proc/1/environ", "/proc/self/mem", "/proc/kcore", "/proc/1/task/1/environ", "/proc/1/task/1/mem"} {
		if !p.Paths.Deny.Covers(d) {
			t.Errorf("the gate's deny list does not cover %s", d)
		}
	}
}
