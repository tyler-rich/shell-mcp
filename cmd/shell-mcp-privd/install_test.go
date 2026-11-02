//go:build linux

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const testHash = "1111111111111111111111111111111111111111111111111111111111111111"

// TestInstallNeverAsForcedCommand: install refuses with
// SSH_ORIGINAL_COMMAND set, before it reads anything (handoff §3.1).
func TestInstallNeverAsForcedCommand(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "install --policy /etc/shell-mcp/privileged.yaml")
	var out, errb bytes.Buffer
	if code := run([]string{"install", "--policy", "/etc/shell-mcp/privileged.yaml", "--accept", testHash}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "never runs as an SSH forced command") {
		t.Fatalf("%d:\n%s%s", code, out.String(), errb.String())
	}
}

func TestInstallNotRootAndUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if os.Geteuid() != 0 {
		if code := run([]string{"install", "--policy", "/etc/shell-mcp/privileged.yaml"}, &out, &errb); code != 1 || !strings.Contains(out.String(), "runs as root only") {
			t.Fatalf("non-root: %d:\n%s", code, out.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"install"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--policy is required") {
		t.Fatalf("usage: %d %q", code, errb.String())
	}
}

// TestUnitsNextSteps: units points at install and gives the hand steps in
// TARGET-SETUP §9.2's order, verify with --man=no (handoff F-2).
func TestUnitsNextSteps(t *testing.T) {
	env, p := testEnv(t, validPolicy)
	var so, se bytes.Buffer
	if code := unitsWith([]string{"--policy", p, "--out", t.TempDir()}, &so, &se, env); code != 0 {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	s := so.String()
	i, j, k := strings.Index(s, "install -o root -g root -m 0700 -d /var/lib/shell-mcp /var/lib/shell-mcp/backups"),
		strings.Index(s, "systemd-analyze verify --man=no"), strings.Index(s, "systemctl daemon-reload")
	if !strings.Contains(s, "shell-mcp-privd install --policy "+p) || i < 0 || j < i || k < j {
		t.Fatalf("next steps:\n%s", s)
	}
}
