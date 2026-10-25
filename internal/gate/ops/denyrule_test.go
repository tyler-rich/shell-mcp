//go:build linux

package ops_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The gate's deny refusal names the rule: a built-in rule by its pattern
// (here "**/.ssh/**" inside an invented read root).
func TestGateDenyRefusalNamesBuiltinRule(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "read")
	key := filepath.Join(f.read, ".ssh", "id_invented")
	gatetest.WriteFile(t, key, "invented\n", 0o600)
	r := f.call("read_file", m{"path": key})
	if r.OK || r.Error == nil || r.Error.Code != "path_denied" || !strings.Contains(r.Error.Message, `built-in read deny list rule "**/.ssh/**"`) {
		t.Fatalf("got %+v", r.Error)
	}
}
