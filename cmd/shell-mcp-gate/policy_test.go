//go:build linux

package main

import (
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyNewUsage: policy without new, and policy new without its
// flags, are usage errors (exit 2); the usage lists the command.
func TestPolicyNewUsage(t *testing.T) {
	for _, args := range [][]string{
		{"policy"}, {"policy", "old"}, {"policy", "new"}, {"policy", "new", "--answers", "a.yaml"},
		{"policy", "new", "--answers", "a.yaml", "--out", "-", "--dry-run"},
	} {
		if code, _, stderr := runCmd(args, ""); code != 2 || !strings.Contains(stderr, "usage: shell-mcp-gate policy new") {
			t.Errorf("%q: %d\n%s", args, code, stderr)
		}
	}
	if code, stdout, _ := runCmd([]string{"help"}, ""); code != 0 || !strings.Contains(stdout, "  policy new --answers <file> --out <file>|-") {
		t.Fatalf("usage does not list policy new:\n%s", stdout)
	}
}

// TestPolicyNewNeverAsForcedCommand: with SSH_ORIGINAL_COMMAND set,
// policy new refuses before it reads the answers, also printing.
func TestPolicyNewNeverAsForcedCommand(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "policy new")
	answers := filepath.Join(t.TempDir(), "setup.yaml")
	if err := os.WriteFile(answers, []byte("preset: read-only\naccount: { user: svc-shell, uid: 60123 }\nread: [/srv/app]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCmd([]string{"policy", "new", "--answers", answers, "--out", "-"}, "")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "never runs as an SSH forced command") {
		t.Fatalf("%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// TestPolicyNewPrints: --out - prints the policy from the answers as any
// user, after loading it with the gate's own loader.
func TestPolicyNewPrints(t *testing.T) {
	answers := filepath.Join(t.TempDir(), "setup.yaml")
	if err := os.WriteFile(answers, []byte("preset: read-only\naccount: { user: svc-shell, uid: 60123 }\nread: [/srv/app]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCmd([]string{"policy", "new", "--answers", answers, "--out", "-"}, "")
	if code != 0 || !strings.HasPrefix(stdout, "# Run `shell-mcp-gate check-policy") || !strings.Contains(stdout, "\nmax_tier: read\n") ||
		!strings.Contains(stderr, "loads strictly") {
		t.Fatalf("%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	// A policy the gate's loader refuses is not printed.
	if err := os.WriteFile(answers, []byte("preset: operator\naccount: { user: svc-shell, uid: 60123 }\nwrite: [/etc/ssh]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCmd([]string{"policy", "new", "--answers", answers, "--out", "-"}, "")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "answers write[0]: /etc/ssh is, or is inside, a protected path") {
		t.Fatalf("%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

const module = "github.com/tyler-rich/shell-mcp"

// TestGateNeverLinksPrivd: the gate binary (the forced command) reaches no
// privd package, so it never links the privileged policy or its loader
// (handoff §5), and it reaches policy new's package.
func TestGateNeverLinksPrivd(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", "amd64", false
	seen := map[string]string{}
	var walk func(path, from string)
	walk = func(path, from string) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = from
		if strings.HasPrefix(path, module+"/internal/privd") {
			chain := path
			for p := from; p != ""; p = seen[p] {
				chain = p + " -> " + chain
			}
			t.Errorf("cmd/shell-mcp-gate links %s: %s", path, chain)
			return
		}
		pkg, err := ctx.ImportDir(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, module))), 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, imp := range pkg.Imports {
			if imp == module || strings.HasPrefix(imp, module+"/") {
				walk(imp, path)
			}
		}
	}
	walk(module+"/cmd/shell-mcp-gate", "")
	if _, ok := seen[module+"/internal/gate/policy/gen"]; !ok {
		t.Error("cmd/shell-mcp-gate does not link internal/gate/policy/gen: policy new is not wired")
	}
}
