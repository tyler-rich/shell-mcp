//go:build linux

// Package gatetest is test support for the gate packages. It is imported only
// by _test.go files (enforced by TestForTestingOnlyInTests in
// internal/gate/policy) and never by a binary.
package gatetest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// RequireSecureEnv names the environment variable that CI and
// scripts/ci-local.sh set so that an insecure temp directory fails the tests
// instead of skipping them.
const RequireSecureEnv = "SHELL_MCP_REQUIRE_SECURE_TMP"

// Trust is the test trust set: root and the uid running the tests.
func Trust() policy.Trust { return policy.TrustForTesting(uint32(os.Getuid())) }

// SecureDir returns a fresh temp directory whose whole parent chain passes
// the gate's ownership checks under Trust(). The default /tmp is world-
// writable, so the chain only passes when TMPDIR points somewhere private
// (CI and ci-local set it). Without RequireSecureEnv the test is skipped
// with the reason; with it, the test fails.
func SecureDir(t testing.TB) string {
	t.Helper()
	d := t.TempDir()
	real, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.CheckChain(Trust(), real); err != nil {
		msg := "temp directory chain is not trustworthy for gate ownership checks (" + err.Error() +
			"); set TMPDIR to a directory whose parents are not group/other-writable, as scripts/ci-local.sh and CI do"
		if os.Getenv(RequireSecureEnv) != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return real
}

// WriteFile writes a file (creating parents) with the given mode.
func WriteFile(t testing.TB, path string, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // not subject to umask
		t.Fatal(err)
	}
}

// Mkdir creates a directory (and parents) with the given mode.
func Mkdir(t testing.TB, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
