//go:build linux

package ops_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The helper's deny refusal names a built-in rule by its pattern, and a
// rule from the root-only privileged policy only by its paths.deny index,
// never its value.
func TestHelperDenyRefusalNamesTheRule(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	key := filepath.Join(f.read, ".ssh", "id_invented")
	gatetest.WriteFile(t, key, "invented\n", 0o600)
	for p, want := range map[string]string{
		key: `built-in read deny list rule "**/.ssh/**"`,
		filepath.Join(f.read, "secrets", "token"): "paths.deny[0]",
	} {
		r := f.serve("priv_read_file", m{"path": p})
		if r.OK || r.Error == nil || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, want) {
			t.Fatalf("%s: got %+v, want path_denied naming %s", p, r.Error, want)
		}
		if strings.Contains(r.Error.Message, f.d) {
			t.Fatalf("%s: the message names a local path: %q", p, r.Error.Message)
		}
	}
}
