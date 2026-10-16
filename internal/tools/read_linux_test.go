//go:build linux

package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// The read tools against the real gate (its test harness as the forced
// command): every native and git op the container can run, decoded
// strictly, so a wire field the server does not describe fails here. The
// systemd ops need a real systemd and run in the e2e-host job; here their
// policy refusal is checked. Everything is an invented fixture.

const readPolicy = `version: 1
max_tier: operator
sandbox:
  landlock: {MODE}
  system_read_exec: [{GATEDIR}]
paths:
  read: [{R}]
git:
  repos:
    - path: {R}/repo
      remote: https://git.example.test/example-app.git
commands:
  - id: kernel-name
    path: /usr/bin/uname
    tier: read
    templates: [["-s"]]
  - id: kernel-machine
    path: /usr/bin/uname
    tier: operator
    templates: [["-m"]]
`

func writeTestCert(t *testing.T, p string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "app.example.test"},
		DNSNames: []string{"app.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, p, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
}

func TestReadToolsAgainstRealGate(t *testing.T) {
	g := gatetest.NewHarnessGate(t, "readonly-test", readPolicy)
	r := g.Read
	gatetest.Mkdir(t, filepath.Join(r, "tree", "sub"), 0o755)
	gatetest.WriteFile(t, filepath.Join(r, "tree", "sub", "file.txt"), "one\ntwo\nthree\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(r, "tree", ".netrc"), "machine example.test\n", 0o644)
	if err := os.Symlink(filepath.Join(r, "tree", "sub"), filepath.Join(r, "tree", "abs-link")); err != nil {
		t.Fatal(err)
	}
	writeTestCert(t, filepath.Join(r, "cert.pem"))
	repo := filepath.Join(r, "repo")
	gatetest.Mkdir(t, repo, 0o755)
	gatetest.Git(t, repo, "init", "-q")
	gatetest.WriteFile(t, filepath.Join(repo, "config.yaml"), "a: 1\n", 0o644)
	gatetest.Git(t, repo, "add", "-A")
	gatetest.Git(t, repo, "commit", "-q", "-m", "initial example config")
	gatetest.WriteFile(t, filepath.Join(repo, "config.yaml"), "a: 2\n", 0o644)

	tg, c := sshTarget(t, forcedGate(t, g))
	h := newHarness(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "")
	ok := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		env, _ := h.call(tool, args)
		if env["ok"] != true {
			t.Fatalf("%s %v: %v", tool, args, env)
		}
		return env
	}
	refused := func(tool string, args map[string]any, code, msg string) {
		t.Helper()
		env, _ := h.call(tool, args)
		e, _ := env["error"].(map[string]any)
		m, _ := e["message"].(string)
		if e["code"] != code || !strings.Contains(m, msg) {
			t.Fatalf("%s %v: %v, want %s containing %q", tool, args, env, code, msg)
		}
	}

	if d := data(t, ok("shell_get_system_info", map[string]any{})); d["kernel"].(map[string]any)["sysname"] != "Linux" {
		t.Fatalf("sysinfo %v", d)
	}
	ok("shell_get_disk_usage", map[string]any{})
	ok("shell_get_disk_usage", map[string]any{"include_pseudo": true})
	if d := data(t, ok("shell_list_processes", map[string]any{"limit": 5, "sort_by": "pid"})); len(d["processes"].([]any)) == 0 {
		t.Fatalf("processes %v", d)
	}
	d := data(t, ok("shell_list_directory", map[string]any{"path": filepath.Join(r, "tree"), "include_hidden": true}))
	if s := jsonOf(t, d["entries"]); !strings.Contains(s, `"link_target":"`+filepath.Join(r, "tree", "sub")+`"`) || strings.Contains(s, ".netrc") {
		t.Fatalf("list_dir %s", s)
	}
	if d := data(t, ok("shell_stat_path", map[string]any{"path": filepath.Join(r, "tree", "abs-link")})); d["type"] != "symlink" {
		t.Fatalf("stat %v", d)
	}
	if d := data(t, ok("shell_read_file", map[string]any{"path": filepath.Join(r, "hello.txt")})); d["content"] != "hello\n" || d["sha256"] == "" {
		t.Fatalf("read_file %v", d)
	}
	if d := data(t, ok("shell_read_file", map[string]any{"path": filepath.Join(r, "tree", "sub", "file.txt"), "tail_lines": 1})); d["content"] != "three\n" {
		t.Fatalf("tail %v", d)
	}
	if d := data(t, ok("shell_find_files", map[string]any{"root": r, "name_glob": "*.txt", "type": "file", "modified_within": "1h"})); len(d["entries"].([]any)) < 2 {
		t.Fatalf("find %v", d)
	}
	if d := data(t, ok("shell_inspect_certificate", map[string]any{"path": filepath.Join(r, "cert.pem")})); !strings.Contains(jsonOf(t, d), `"app.example.test"`) {
		t.Fatalf("cert %v", d)
	}
	if d := data(t, ok("shell_get_git_status", map[string]any{"repo": repo})); !strings.Contains(jsonOf(t, d["entries"]), "config.yaml") {
		t.Fatalf("git status %v", d)
	}
	if d := data(t, ok("shell_get_git_log", map[string]any{"repo": repo})); !strings.Contains(jsonOf(t, d), "initial example config") {
		t.Fatalf("git log %v", d)
	}
	if d := data(t, ok("shell_get_git_diff", map[string]any{"repo": repo})); !strings.Contains(d["diff"].(string), "+a: 2") {
		t.Fatalf("git diff %v", d)
	}
	env := ok("shell_run_read_command", map[string]any{"command_id": "kernel-name", "args": []string{"-s"}})
	if data(t, env)["stdout"] != "Linux\n" || env["exec"].(map[string]any)["exit_code"] != 0.0 {
		t.Fatalf("exec %v", env)
	}

	// Refusals, with the gate's own codes and messages.
	refused("shell_list_directory", map[string]any{"path": filepath.Join(r, "tree", "abs-link", "x")}, "path_denied", "absolute")
	refused("shell_read_file", map[string]any{"path": filepath.Join(r, "tree", ".netrc")}, "path_denied", "")
	refused("shell_stat_path", map[string]any{"path": "/etc/hostname"}, "path_denied", "")
	refused("shell_get_git_status", map[string]any{"repo": filepath.Join(r, "tree")}, "policy_denied", "")
	refused("shell_get_service_status", map[string]any{"unit": "example-app.service"}, "policy_denied", "services.status")
	refused("shell_list_services", map[string]any{}, "policy_denied", "services.status")
	refused("shell_get_journal", map[string]any{"unit": "example-app.service"}, "policy_denied", "journal")
	refused("shell_run_read_command", map[string]any{"command_id": "kernel-machine", "args": []string{"-m"}}, "tier_denied", "")
	refused("shell_run_read_command", map[string]any{"command_id": "kernel-name", "args": []string{"-a"}}, "template_mismatch", "")
}
