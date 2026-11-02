package main

import (
	"bytes"
	"context"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/tyler-rich/shell-mcp"

// TestServerNeverLinksExecx: the server binary, built for Linux as released,
// reaches no package that starts processes (D-003). execx's init() turns any
// binary that links it into the exec trampoline, so linking it at all would
// give the server an exec path.
func TestServerNeverLinksExecx(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", "amd64", false
	forbidden := []string{module + "/internal/gate/execx", module + "/internal/gate/setupx/system", module + "/internal/privd"}
	seen := map[string]string{}
	var walk func(path, from string)
	walk = func(path, from string) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = from
		for _, f := range forbidden {
			if path == f || strings.HasPrefix(path, f+"/") {
				chain := path
				for p := from; p != ""; p = seen[p] {
					chain = p + " -> " + chain
				}
				t.Errorf("cmd/shell-mcp links %s: %s", path, chain)
				return
			}
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
	walk(module+"/cmd/shell-mcp", "")
	if _, ok := seen[module+"/internal/setup/serverinit"]; !ok {
		t.Error("cmd/shell-mcp does not link internal/setup/serverinit: init is not wired")
	}
	if _, ok := seen[module+"/internal/setup/compose"]; !ok {
		t.Error("cmd/shell-mcp does not link internal/setup/compose: init compose is not wired")
	}
}

func TestUsageListsInit(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), nil, []string{"help"}, emptyLookup, &out, &out); code != 0 || !strings.Contains(out.String(), "  init ") {
		t.Fatalf("usage does not list init:\n%s", out.String())
	}
}

func emptyLookup(string) (string, bool) { return "", false }

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func composeArgs(extra ...string) []string {
	return append([]string{"init", "compose", "--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0@sha256:" + testDigest,
		"--host-key", "ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--target-name", "app-host",
		"--target-host", "target-a.example.test", "--mcp-host", "mcp.example.test", "--subnet", "192.0.2.0/24",
		"--server-addr", "192.0.2.10", "--proxy-addr", "192.0.2.5"}, extra...)
}

func TestInitCompose(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "..", "internal", "setup", "compose", "testdata", "secrets.golden.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name         string
		args         []string
		code         int
		stdout       []byte
		stderrHas    string
		stdoutIsYAML bool
	}{
		{"secrets form", composeArgs(), 0, golden, "", true},
		{"operator without approvals", composeArgs("--profile", "operator"), 0, nil, "NOTE ", true},
		{"admin without approvals", composeArgs("--profile", "admin"), 1, []byte{}, "FAIL ", false},
		{"a tag alone", composeArgs("--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0"), 1, []byte{}, "FAIL ", false},
		{"usage", composeArgs("--token", "x"), 2, []byte{}, "usage", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(context.Background(), nil, c.args, emptyLookup, &out, &errb)
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, errb.String())
			}
			if c.stdout != nil && !bytes.Equal(out.Bytes(), c.stdout) {
				t.Errorf("stdout:\n%s", out.String())
			}
			if c.stdoutIsYAML && !strings.HasPrefix(out.String(), "# Reference deployment") {
				t.Errorf("stdout is not the compose file:\n%s", out.String())
			}
			if !strings.Contains(errb.String(), c.stderrHas) {
				t.Errorf("stderr does not contain %q:\n%s", c.stderrHas, errb.String())
			}
		})
	}
}
