//go:build linux

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/setup"
)

var installArgs = []string{"install", "--policy", "/etc/shell-mcp/read-only.yaml", "--principal", "readonly", "--from", "192.0.2.10",
	"--key", "/nonexistent/ssh_key.pub", "--uid", "60123", "--gid", "60123", "--dry-run"}

// TestInstallNeverAsForcedCommand: with SSH_ORIGINAL_COMMAND set, install
// refuses before it reads anything, also in a dry run (handoff §3.1).
func TestInstallNeverAsForcedCommand(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "install --policy /etc/shell-mcp/admin.yaml")
	code, out, _ := runCmd(installArgs, "")
	if code != 1 || !strings.Contains(out, "never runs as an SSH forced command") {
		t.Fatalf("%d:\n%s", code, out)
	}
}

// TestInstallNotRoot: a non-root process is refused (as root this test has
// nothing to show).
func TestInstallNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as a non-root test process")
	}
	code, out, _ := runCmd(installArgs, "")
	if code != 1 || !strings.Contains(out, "runs as root only") {
		t.Fatalf("%d:\n%s", code, out)
	}
}

func TestInstallUsageExit(t *testing.T) {
	code, out, errb := runCmd([]string{"install", "--policy", "/etc/shell-mcp/a.yaml"}, "")
	if code != 2 || out != "" || !strings.Contains(errb, "--principal is required") || !strings.Contains(errb, setup.Usage) {
		t.Fatalf("%d %q %q", code, out, errb)
	}
	if code, _, errb := runCmd([]string{"host-key", "extra"}, ""); code != 2 || !strings.Contains(errb, "usage: shell-mcp-gate host-key") {
		t.Fatalf("host-key: %d %q", code, errb)
	}
}

// TestForcedCommandReachesOnlyServe: the forced command's argv is fixed
// (serve), and whatever the client asks for arrives in
// SSH_ORIGINAL_COMMAND, which never selects another subcommand: serve
// answers with one protocol response and nothing else.
func TestForcedCommandReachesOnlyServe(t *testing.T) {
	for _, client := range []string{"install --policy /etc/shell-mcp/a.yaml", "move-key --principal readonly --from-user svc-shell --to-user svc-shell-std", "host-key", "check-policy --policy /x", "shell-mcp-gate/1"} {
		t.Setenv("SSH_ORIGINAL_COMMAND", client)
		code, out, errb := runCmd([]string{"serve", "--policy", "/nonexistent/policy.yaml", "--principal", "readonly"},
			`{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"hello"}`+"\n")
		var r struct {
			OK bool `json:"ok"`
		}
		if code != 0 || errb != "" || json.Unmarshal([]byte(out), &r) != nil || strings.Count(out, "\n") != 1 ||
			strings.Contains(out, "shell-mcp-gate install") || strings.Contains(out, "owner scan") || strings.Contains(out, "SHELL_MCP_TARGET_HOST_KEYS") {
			t.Fatalf("SSH_ORIGINAL_COMMAND=%q: %d %q %q", client, code, out, errb)
		}
	}
}

var moveKeyArgs = []string{"move-key", "--principal", "readonly", "--from-user", "svc-shell", "--to-user", "svc-shell-std", "--dry-run"}

// TestMoveKeyNeverAsForcedCommand: move-key refuses as a forced command,
// also in a dry run, as install does.
func TestMoveKeyNeverAsForcedCommand(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "move-key --principal readonly")
	code, out, _ := runCmd(moveKeyArgs, "")
	if code != 1 || !strings.Contains(out, "never runs as an SSH forced command") {
		t.Fatalf("%d:\n%s", code, out)
	}
}

func TestMoveKeyUsageExit(t *testing.T) {
	code, out, errb := runCmd([]string{"move-key", "--principal", "readonly"}, "")
	if code != 2 || out != "" || !strings.Contains(errb, "--from-user is required") || !strings.Contains(errb, setup.MoveUsage) {
		t.Fatalf("%d %q %q", code, out, errb)
	}
	if code, out, _ := runCmd([]string{"move-key", "--help"}, ""); code != 0 || out != setup.MoveUsage {
		t.Fatalf("--help: %d %q", code, out)
	}
}
