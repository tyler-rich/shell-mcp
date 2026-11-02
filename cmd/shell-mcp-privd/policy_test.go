//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyNewUsage: policy without new, and policy new without its
// flags, are usage errors (exit 2); the usage lists the command.
func TestPolicyNewUsage(t *testing.T) {
	for _, args := range [][]string{
		{"policy"}, {"policy", "old"}, {"policy", "new"}, {"policy", "new", "--out", "-"},
		{"policy", "new", "--answers", "a.yaml", "--out", "-", "--dry-run"},
	} {
		var so, se bytes.Buffer
		if code := run(args, &so, &se); code != 2 || !strings.Contains(se.String(), "usage: shell-mcp-privd policy new") {
			t.Errorf("%q: %d\n%s", args, code, se.String())
		}
	}
	var so, se bytes.Buffer
	if code := run([]string{"help"}, &so, &se); code != 0 || !strings.Contains(so.String(), "  policy new --answers <file> --out <file>|-") {
		t.Fatalf("usage does not list policy new:\n%s", so.String())
	}
}

// TestPolicyNewNeedsRoot: answers without root: have no privileged policy
// (printing included), and with SSH_ORIGINAL_COMMAND set nothing is read.
func TestPolicyNewNeedsRoot(t *testing.T) {
	answers := filepath.Join(t.TempDir(), "setup.yaml")
	if err := os.WriteFile(answers, []byte("preset: read-only\naccount: { user: svc-shell, uid: 60123 }\nread: [/srv/app]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	if code := run([]string{"policy", "new", "--answers", answers, "--out", "-"}, &so, &se); code != 1 || so.Len() != 0 ||
		!strings.Contains(se.String(), "answers root: is absent") {
		t.Fatalf("%d\nstdout:\n%s\nstderr:\n%s", code, so.String(), se.String())
	}
	t.Setenv("SSH_ORIGINAL_COMMAND", "policy new")
	so.Reset()
	se.Reset()
	if code := run([]string{"policy", "new", "--answers", answers, "--out", "-"}, &so, &se); code != 1 || so.Len() != 0 ||
		!strings.Contains(se.String(), "never runs as an SSH forced command") {
		t.Fatalf("%d\nstdout:\n%s\nstderr:\n%s", code, so.String(), se.String())
	}
}
