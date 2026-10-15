//go:build linux && shellmcp_e2e_bypass

package fsx

import (
	"errors"
	"strings"
	"testing"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// testBypassTag marks this test build (-tags shellmcp_e2e_bypass).
const testBypassTag = true

// The built-in read deny list refuses /proc/*/environ, /proc/*/mem and
// /proc/kcore on its own (POLICY §3), as defence in depth behind Landlock
// and the rule that no root may be /proc. This test build skips fsx's
// forbidden-root check, the policy's root rule is bypassed by building the
// configuration directly with /proc as a root, and unit tests run without
// Landlock: the control shows /proc is then readable, and each path is
// still refused, with the refusal naming the deny rule. The deny list is
// the gate's and the helper's own (both are built from the same built-in
// list; the policy tests check each loader).
func TestBuiltinDenyRefusesProcSecretsWithRootChecksBypassed(t *testing.T) {
	if !bypassForbiddenRoots {
		t.Fatal("this test build must skip the forbidden-root check")
	}
	builtin := gpolicy.BuiltinDeny()
	deny, err := pathx.NewMatcher(builtin)
	if err != nil {
		t.Fatal(err)
	}
	f := New(&Config{ReadRoots: []string{"/proc"}, Deny: deny, BuiltinDeny: len(builtin), Limits: Limits{MaxReadBytes: 1 << 16}})
	// Control: with the root checks bypassed, /proc is readable through fsx.
	if _, err := f.Stat("/proc/self/status"); err != nil {
		t.Fatalf("control: /proc/self/status: %v", err)
	}
	for p, rule := range map[string]string{
		"/proc/self/environ": "/proc/*/environ",
		"/proc/1/environ":    "/proc/*/environ",
		"/proc/self/mem":     "/proc/*/mem",
		"/proc/kcore":        "/proc/kcore",
	} {
		for op, call := range map[string]func() error{
			"stat":      func() error { _, err := f.Stat(p); return err },
			"read_file": func() error { _, err := f.ReadFile(p, ReadOptions{MaxBytes: 64}); return err },
		} {
			err := call()
			var fe *Error
			if !errors.As(err, &fe) || fe.Code != protocol.CodePathDenied || !strings.Contains(fe.Msg, `built-in read deny list rule "`+rule+`"`) {
				t.Errorf("%s %s: %v, want path_denied naming %s", op, p, err, rule)
			}
		}
	}
}
