//go:build linux

package gatetest

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

// HarnessEnv is the environment variable that makes the gate's test binary
// (cmd/shell-mcp-gate, built with go test -c) run the real serve path with
// test trust and the fake identity from the HARNESS_* variables.
const HarnessEnv = "SHELL_MCP_GATE_HARNESS"

var (
	harnessOnce sync.Once
	harnessDir  string
	harnessBin  string
	harnessErr  string
)

// HarnessGate is the real gate as a forced command: Argv and Env run
// `serve --policy Policy --principal <principal>` with the fake service
// identity; the caller adds SSH_ORIGINAL_COMMAND (and SSH_CONNECTION).
type HarnessGate struct {
	Argv   []string
	Env    []string
	Dir    string // the fixture root
	Read   string // a read root holding hello.txt
	Policy string
}

// HarnessPolicy is a minimal read-tier policy; {R} is the read root and
// {GATEDIR} the harness binary's directory (the gate re-executes itself as
// the exec trampoline, so the sandbox must let it run its own binary).
const HarnessPolicy = `version: 1
max_tier: read
sandbox:
  landlock: {MODE}
  system_read_exec: [{GATEDIR}]
paths:
  read: [{R}]
`

// NewHarnessGate builds the gate's test binary once per test process into
// a directory that passes the gate's own executable checks, and writes the
// policy (HarnessPolicy when policy is "") into a fresh secure fixture.
// It skips, or fails under RequireSecureEnv, without a secure TMPDIR.
func NewHarnessGate(t testing.TB, principal, policy string) *HarnessGate {
	t.Helper()
	harnessOnce.Do(func() {
		d, err := os.MkdirTemp("", "gate-harness")
		if err == nil {
			harnessDir, err = filepath.EvalSymlinks(d)
		}
		if err != nil {
			harnessErr = err.Error()
		}
	})
	if harnessErr != "" {
		t.Fatal(harnessErr)
	}
	RequireSecure(t, harnessDir)
	if harnessBin == "" {
		harnessBin = BuildTest(t, "cmd/shell-mcp-gate", harnessDir, "shell-mcp-gate", nil)
	}
	d := SecureDir(t)
	g := &HarnessGate{Dir: d, Read: filepath.Join(d, "srv", "app"), Policy: filepath.Join(d, "etc", "policy.yaml")}
	home := filepath.Join(d, "home")
	Mkdir(t, home, 0o755)
	WriteFile(t, filepath.Join(g.Read, "hello.txt"), "hello\n", 0o644)
	if policy == "" {
		policy = HarnessPolicy
	}
	mode := "best-effort"
	if sandbox.KernelABI() >= sandbox.RequiredMinABI {
		mode = "required"
	}
	WriteFile(t, g.Policy, strings.NewReplacer("{R}", g.Read, "{GATEDIR}", harnessDir, "{MODE}", mode).Replace(policy), 0o644)
	g.Argv = []string{harnessBin, "serve", "--policy", g.Policy, "--principal", principal}
	g.Env = []string{"PATH=/usr/bin:/bin", HarnessEnv + "=1", "HARNESS_UID=60123", "HARNESS_GIDS=60123",
		"HARNESS_GROUPS=60123=svc-shell", "HARNESS_HOME=" + home}
	return g
}
