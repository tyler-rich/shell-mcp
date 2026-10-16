//go:build linux

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// forcedGate runs the real gate harness as the key's forced command.
func forcedGate(t *testing.T, g *gatetest.HarnessGate) sshtest.Exec {
	return func(ctx context.Context, s *sshtest.Session) uint32 {
		cmd := exec.CommandContext(ctx, g.Argv[0], g.Argv[1:]...) //nolint:gosec // G204: the test's own gate harness
		cmd.Env = append(append([]string{}, g.Env...), "SSH_ORIGINAL_COMMAND="+s.OriginalCommand,
			"SSH_CONNECTION=192.0.2.10 50000 192.0.2.20 22")
		cmd.Stdin, cmd.Stdout = s.Stdin, s.Stdout
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.WaitDelay = 2 * time.Second
		err := cmd.Run()
		if ctx.Err() != nil {
			return 0
		}
		if stderr.Len() > 0 {
			t.Errorf("gate wrote to stderr: %q", stderr.String())
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return uint32(ee.ExitCode()) //nolint:gosec // G115: exit codes are 0..255
		}
		return 0
	}
}

func TestGetPolicyAgainstRealGate(t *testing.T) {
	g := gatetest.NewHarnessGate(t, "readonly-test", "")
	tg, c := sshTarget(t, forcedGate(t, g))
	h := newHarness(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "")
	env, _ := h.call("shell_get_policy", map[string]any{"target": "app-host"})
	if env["ok"] != true {
		t.Fatalf("envelope %v", env)
	}
	b, _ := json.Marshal(env["data"])
	var d PolicyData
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d.Gate.Principal != "readonly-test" || d.Gate.Protocol != 1 || d.Gate.MaxTier != "read" ||
		d.Policy.MaxTier != "read" || d.Policy.SHA256 != d.Gate.PolicySHA256 || len(d.Policy.Paths.Read) != 1 ||
		!strings.HasSuffix(d.Policy.Paths.Read[0], "/srv/app") || d.Policy.Limits.MaxTimeoutS == 0 || d.Sandbox.Mode == "" {
		t.Fatalf("data %s", b)
	}
}
