//go:build linux

package policy_test

import "testing"

// TestPathReadFDRefused (handoff N-22): {path:read:fd} is a gate
// placeholder. Root commands get closed paths only (N-10's chain rule), so
// no account but root can swap what a path names, and the privileged
// policy refuses the placeholder, naming why.
func TestPathReadFDRefused(t *testing.T) {
	f := newFixture(t)
	for _, tpl := range []string{`["{path:read:fd}"]`, `["-c", "keys", "{path:read:fd}"]`, `["{path:read}", "{path:read:fd}"]`} {
		f.mustFail(t, withCommand("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    templates: ["+tpl+"]\n"),
			"{path:read:fd} is not available in the privileged policy: root commands get closed paths only")
	}
	f.mustLoad(t, withCommand("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    templates: [[\"{path:read}\"]]\n"))
}
