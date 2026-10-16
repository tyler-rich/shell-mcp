//go:build linux

package gateclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// forced runs the real gate (the harness binary) as the key's forced
// command, the way sshd does: the requested command reaches it only as
// SSH_ORIGINAL_COMMAND, stdin and stdout are the session's.
func forced(t *testing.T, g *gatetest.HarnessGate) sshtest.Exec {
	return func(ctx context.Context, s *sshtest.Session) uint32 {
		cmd := exec.CommandContext(ctx, g.Argv[0], g.Argv[1:]...) //nolint:gosec // G204: the test's own gate harness
		cmd.Env = append(append([]string{}, g.Env...), "SSH_ORIGINAL_COMMAND="+s.OriginalCommand,
			"SSH_CONNECTION=192.0.2.10 50000 192.0.2.20 22")
		cmd.Stdin, cmd.Stdout = s.Stdin, s.Stdout
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.WaitDelay = 2 * time.Second
		err := cmd.Run()
		if stderr.Len() > 0 {
			t.Errorf("gate wrote to stderr: %q", stderr.String())
		}
		var ee *exec.ExitError
		if ctx.Err() != nil {
			return 0 // the client closed the session after its answer
		}
		if errors.As(err, &ee) {
			return uint32(ee.ExitCode()) //nolint:gosec // G115: exit codes are 0..255
		}
		if err != nil {
			t.Errorf("gate did not run: %v", err)
			return 255
		}
		return 0
	}
}

func TestRealGateHelloAndPolicy(t *testing.T) {
	g := gatetest.NewHarnessGate(t, "test-principal", "")
	c, _ := target(t, forced(t, g), 4)
	cl := newClient()
	resp, err := cl.Call(t.Context(), c, protocol.OpHello, "read", nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var hello struct {
		Protocol  int    `json:"protocol"`
		Principal string `json:"principal"`
		MaxTier   string `json:"max_tier"`
	}
	if !resp.OK || json.Unmarshal(resp.Data, &hello) != nil || hello.Protocol != 1 || hello.Principal != "test-principal" || hello.MaxTier != "read" {
		t.Fatalf("hello: %+v %s", resp, resp.Data)
	}
	resp, err = cl.Call(t.Context(), c, protocol.OpPolicy, "read", nil, 10*time.Second)
	if err != nil || !resp.OK {
		t.Fatalf("policy: %+v %v", resp, err)
	}
	// An op above the policy's max_tier: the gate's own code, with the id.
	resp, err = cl.Call(t.Context(), c, protocol.OpWriteFile, "operator", map[string]any{"path": filepath.Join(g.Read, "x"), "content_b64": ""}, 10*time.Second)
	if err != nil || resp.OK || resp.Error.Code != protocol.CodeTierDenied || resp.ID == "" {
		t.Fatalf("write above max_tier: %+v %v", resp, err)
	}
}

func TestRealGateRefusalBeforeRequestPassesThrough(t *testing.T) {
	g := gatetest.NewHarnessGate(t, "test-principal", "")
	// A group-writable policy: the gate refuses before reading anything.
	if err := os.Chmod(g.Policy, 0o664); err != nil { //nolint:gosec // G302: the insecure mode under test
		t.Fatal(err)
	}
	c, _ := target(t, forced(t, g), 1)
	resp, err := newClient().Call(t.Context(), c, protocol.OpHello, "read", nil, 10*time.Second)
	if err != nil {
		t.Fatalf("refusal became a transport error: %v", err)
	}
	if resp.OK || resp.Error.Code != protocol.CodeInstallInsecure || resp.ID != "" {
		t.Fatalf("response %+v", resp)
	}
}
