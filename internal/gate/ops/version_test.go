//go:build linux

package ops_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The protocol version (ARCHITECTURE §4; handoff N-22's protocol
// decision): a gate refuses a request of another version with
// protocol_mismatch, naming both versions and the side to upgrade, and
// answers a version 1 request in version 1's frame, so that a 0.1.0 server
// shows the message; a helper answering in another version refused the
// request, and the gate says which side to upgrade, never that the
// operation may have run.

// v1Response is protocol version 1's response, decoded as a 0.1.0 server
// decodes it: these fields only, nothing else.
type v1Response struct {
	V        int             `json:"v"`
	ID       string          `json:"id"`
	OK       bool            `json:"ok"`
	Data     json.RawMessage `json:"data"`
	Warnings []string        `json:"warnings"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Gate *struct {
		Version      string `json:"version"`
		Principal    string `json:"principal"`
		PolicySHA256 string `json:"policy_sha256"`
		MaxTier      string `json:"max_tier"`
		Unit         string `json:"unit"`
		DurationMS   int64  `json:"duration_ms"`
	} `json:"gate"`
}

func TestProtocolVersionIs2(t *testing.T) {
	if protocol.Version != 2 {
		t.Fatalf("protocol version %d, want 2", protocol.Version)
	}
	if protocol.Hello != "shell-mcp-gate/1" {
		t.Fatalf("the session hello changed to %q; a 0.1.0 gate would refuse it as install_insecure", protocol.Hello)
	}
}

func TestGateRefusesOtherVersions(t *testing.T) {
	f := newFixture(t, "destructive")
	for _, c := range []struct {
		v       int
		frame   int
		message []string
	}{
		{1, 1, []string{"protocol version 2", "request is version 1", "upgrade the server (shell-mcp)"}},
		{3, 2, []string{"protocol version 2", "request is version 3", "upgrade shell-mcp-gate and shell-mcp-privd on this host"}},
	} {
		t.Run(fmt.Sprintf("v%d", c.v), func(t *testing.T) {
			var out bytes.Buffer
			req := fmt.Sprintf(`{"v":%d,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"read","op":"hello","args":{},"timeout_ms":5000}`+"\n", c.v)
			if code := opsServe(f, req, &out); code != 0 {
				t.Fatalf("exit %d", code)
			}
			var r v1Response
			dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil {
				t.Fatalf("%q does not decode as a version 1 frame: %v", out.String(), err)
			}
			if r.V != c.frame || r.OK || r.Error == nil || r.Error.Code != "protocol_mismatch" || r.ID != "" {
				t.Fatalf("answer %q", out.String())
			}
			for _, w := range c.message {
				if !strings.Contains(r.Error.Message, w) {
					t.Fatalf("message %q lacks %q", r.Error.Message, w)
				}
			}
		})
	}
}

// TestForwardHelperOtherVersion: a helper that answers in another version
// refused the request before running it; for an operation that can change
// the host this is protocol_mismatch naming the side to upgrade, not
// outcome_unknown.
func TestForwardHelperOtherVersion(t *testing.T) {
	for _, c := range []struct {
		name, answer string
		message      []string
	}{
		{"a 0.1.0 helper", `{"v":1,"id":"","ok":false,"error":{"code":"protocol_mismatch","message":"unsupported protocol version"},"warnings":[]}` + "\n",
			[]string{"helper speaks protocol version 1", "this gate version 2", "upgrade shell-mcp-privd on this host", "nothing ran"}},
		{"a newer helper", `{"v":3,"id":"","ok":false,"error":{"code":"protocol_mismatch","message":"x"},"warnings":[],"gate":{"version":"9","principal":"shell-mcp-privd","duration_ms":1},"later":1}` + "\n",
			[]string{"helper speaks protocol version 3", "this gate version 2", "upgrade shell-mcp-gate on this host", "nothing ran"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "destructive")
			startHelper(t, f, reply(c.answer))
			r, _ := f.serveRaw(fmt.Sprintf(`{"v":%d,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"priv_write_file",`+
				`"args":{"path":"/etc/example-app/app.conf","content_b64":"eA=="},"timeout_ms":3000}`+"\n", protocol.Version))
			if r.OK || r.Error == nil || r.Error.Code != "protocol_mismatch" {
				t.Fatalf("got %+v", r.Error)
			}
			for _, w := range c.message {
				if !strings.Contains(r.Error.Message, w) {
					t.Fatalf("message %q lacks %q", r.Error.Message, w)
				}
			}
		})
	}
}

// opsServe runs the gate on one raw request line.
func opsServe(f *fixture, in string, out *bytes.Buffer) int {
	return ops.Serve(&f.opts, strings.NewReader(in), out)
}
