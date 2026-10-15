//go:build linux

package fsx

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// A deny refusal names the rule that applied: a built-in rule by its
// pattern (the built-in list is public), a policy rule only by its
// paths.deny index (the privileged policy is root-only, so its values never
// reach the wire). Invented layout under a temp dir.
func TestDenyRefusalNamesTheRule(t *testing.T) {
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	builtin := filepath.Join(d, "builtin-secret")
	user := filepath.Join(d, "policy-secret")
	deny, err := pathx.NewMatcher([]string{builtin})
	if err != nil {
		t.Fatal(err)
	}
	g, err := pathx.CompileGlob(user + "/**")
	if err != nil {
		t.Fatal(err)
	}
	deny.Add(g)
	f := New(&Config{ReadRoots: []string{d}, Deny: deny, BuiltinDeny: 1, Limits: Limits{MaxReadBytes: 1 << 10}})
	for p, want := range map[string]string{
		builtin:                       `built-in read deny list rule "` + builtin + `"`,
		filepath.Join(user, "a", "b"): "paths.deny[0]",
	} {
		_, err := f.Stat(p)
		var fe *Error
		if !errors.As(err, &fe) || fe.Code != protocol.CodePathDenied || !strings.Contains(fe.Msg, want) {
			t.Errorf("Stat(%s): %v, want path_denied naming %s", p, err, want)
		}
		if strings.Contains(want, "paths.deny") && strings.Contains(fe.Msg, user) {
			t.Errorf("a policy rule's value reached the message: %q", fe.Msg)
		}
	}
}

// The normal build never skips the forbidden-root check.
func TestNoForbiddenRootBypassInThisBuild(t *testing.T) {
	if bypassForbiddenRoots && !testBypassTag {
		t.Fatal("the forbidden-root check is bypassed in a normal build")
	}
}
