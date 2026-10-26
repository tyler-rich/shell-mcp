//go:build linux

package ops_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The protocol version (ARCHITECTURE §4; handoff N-22's protocol
// decision), at the helper: a request of another version is
// protocol_mismatch naming both versions and the side to upgrade, framed
// in version 1 for a version 1 request (a 0.1.0 gate passes it through),
// and nothing runs.
func TestHelperRefusesOtherVersions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, c := range []struct {
		v, frame int
		message  []string
	}{
		{1, 1, []string{"privileged helper speaks protocol version 2", "request is version 1", "upgrade shell-mcp-gate on this host"}},
		{3, 2, []string{"privileged helper speaks protocol version 2", "request is version 3", "upgrade shell-mcp-privd on this host"}},
	} {
		out, _ := f.serveRaw(fmt.Sprintf(`{"v":%d,"id":%q,"ceiling":"destructive","op":"priv_stat","args":{"path":%q}}`+"\n", c.v, reqID, f.read))
		var r response
		if err := json.Unmarshal([]byte(out), &r); err != nil || r.V != c.frame || r.Error == nil || r.Error.Code != "protocol_mismatch" {
			t.Fatalf("v%d: %q", c.v, out)
		}
		for _, w := range c.message {
			if !strings.Contains(r.Error.Message, w) {
				t.Fatalf("v%d: message %q lacks %q", c.v, r.Error.Message, w)
			}
		}
	}
}
