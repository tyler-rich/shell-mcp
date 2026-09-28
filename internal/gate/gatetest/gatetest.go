//go:build linux

// Package gatetest is test support for the gate packages. It is imported only
// by _test.go files (enforced by TestForTestingOnlyInTests in
// internal/gate/policy) and never by a binary.
package gatetest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// RequireSecureEnv names the environment variable that CI and
// scripts/ci-local.sh set so that an insecure temp directory fails the tests
// instead of skipping them.
const RequireSecureEnv = "SHELL_MCP_REQUIRE_SECURE_TMP"

// Trust is the test trust set: root and the uid running the tests.
func Trust() policy.Trust { return policy.TrustForTesting(install.ID(os.Getuid())) }

// SecureDir returns a fresh temp directory whose whole parent chain passes
// the gate's ownership checks under Trust(). The default /tmp is world-
// writable, so the chain only passes when TMPDIR points somewhere private
// (CI and ci-local set it). Without RequireSecureEnv the test is skipped
// with the reason; with it, the test fails.
func SecureDir(t testing.TB) string {
	t.Helper()
	d := t.TempDir()
	rp, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.CheckChain(Trust(), rp); err != nil {
		msg := "temp directory chain is not trustworthy for gate ownership checks (" + err.Error() +
			"); set TMPDIR to a directory whose parents are not group/other-writable, as scripts/ci-local.sh and CI do"
		if os.Getenv(RequireSecureEnv) != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return rp
}

// RequireSecure applies SecureDir's rule to an existing directory: skip,
// or fail under RequireSecureEnv, when its chain is not trustworthy.
func RequireSecure(t testing.TB, dir string) {
	t.Helper()
	if _, err := policy.CheckChain(Trust(), dir); err != nil {
		msg := "directory chain is not trustworthy for gate ownership checks (" + err.Error() + "); set TMPDIR as scripts/ci-local.sh and CI do"
		if os.Getenv(RequireSecureEnv) != "" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
}

// BuildTest compiles the test binary of a package of this module (go test
// -c) with CGO_ENABLED=0 unless env overrides it.
func BuildTest(t testing.TB, pkg, dir, name string, env []string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.CommandContext(t.Context(), "go", "test", "-c", "-trimpath", "-o", out, "./"+pkg) //nolint:gosec // G204: test helper, module-relative package
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0"), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go test -c %s: %v\n%s", pkg, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil { //nolint:gosec // G302: a test binary must be executable
		t.Fatal(err)
	}
	return out
}

// WriteFile writes a file (creating parents) with the given mode.
func WriteFile(t testing.TB, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // exact mode: not subject to umask
		t.Fatal(err)
	}
}

// moduleRoot finds the module root from the test's working directory.
func moduleRoot(t testing.TB) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatal("module root not found")
		}
		d = parent
	}
}

// Build compiles a package of this module (relative to the module root)
// with CGO_ENABLED=0 into dir/name, mode 0755, and returns the path.
func Build(t testing.TB, pkg, dir, name string, env []string, extraArgs ...string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	args := append([]string{"build", "-trimpath", "-o", out}, extraArgs...)
	args = append(args, "./"+pkg)
	cmd := exec.CommandContext(t.Context(), "go", args...) //nolint:gosec // G204: test helper, module-relative package
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0"), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil { //nolint:gosec // G302: a test binary must be executable
		t.Fatal(err)
	}
	return out
}

// BuildProbe builds the test child (testdata/probe) into dir/name. outside
// is baked into the binary as the path read-outside tries to read.
func BuildProbe(t testing.TB, dir, name, outside string) string {
	t.Helper()
	return Build(t, "internal/gate/gatetest/testdata/probe", dir, name, nil, "-ldflags", "-X main.outside="+outside)
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
