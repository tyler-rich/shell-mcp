//go:build linux

package ops_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

// TestSandboxRefusalMessages: sandbox_unavailable says what the kernel has,
// what the policy needs, and that best-effort is the alternative — for a
// low Landlock ABI, for no Landlock at all, and for a seccomp failure.
func TestSandboxRefusalMessages(t *testing.T) {
	cases := []struct {
		name string
		rep  sandbox.Report
		err  error
		want []string
	}{
		{"low ABI", sandbox.Report{Mode: "required", KernelABI: 3, RequiredMinABI: 4},
			fmt.Errorf("%w: kernel Landlock ABI 3", sandbox.ErrUnavailable), []string{"ABI 3", "needs ABI 4", "landlock: required", "best-effort"}},
		{"no Landlock", sandbox.Report{Mode: "required", KernelABI: 0, RequiredMinABI: 4},
			fmt.Errorf("%w: kernel Landlock ABI 0", sandbox.ErrUnavailable), []string{"no Landlock", "needs ABI 4", "best-effort"}},
		{"seccomp", sandbox.Report{Mode: "required", KernelABI: 7, RequiredMinABI: 4},
			fmt.Errorf("%w: %w", sandbox.ErrUnavailable, sandbox.ErrSeccomp), []string{"seccomp", "MPTCP", "best-effort"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "read")
			f.opts.ApplySandbox = func(*policy.Policy) (sandbox.Report, error) { return c.rep, c.err }
			r := f.call("hello", m{})
			if r.OK || r.Error.Code != "sandbox_unavailable" {
				t.Fatalf("%+v", r.Error)
			}
			for _, w := range c.want {
				if !strings.Contains(r.Error.Message, w) {
					t.Errorf("message %q lacks %q", r.Error.Message, w)
				}
			}
		})
	}
}
