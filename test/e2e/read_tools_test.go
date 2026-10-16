//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The read tools end to end: the real shell-mcp binary (stdio, read-only
// profile), the real test sshd and the installed gate with the read policy
// (/etc/shell-mcp/gate-read.yaml, principal e2e-read, from setup.sh). Each
// tool has its own test with one success and one refusal case. Static
// fixtures come from setup.sh; the token-bearing file and journal line,
// the certificate, a private key and the git repository (cloned from a
// local HTTPS server, as in the gate's git tests) are made here. Every
// value is invented; tokens are random per run.

const (
	readRoot  = "/srv/example-app"
	readRepo  = readRoot + "/repo"
	tokenFile = readRoot + "/tree/token.txt"
	certFile  = readRoot + "/certs/cert.pem"
	keyFile   = readRoot + "/certs/key.pem"
)

var (
	fixtureOnce sync.Once
	fixtureErr  string
	e2eToken    = "e2etok_" + randomHex(16)

	serverOnce sync.Once
	serverErr  string
	session    *mcp.ClientSession
	serverLog  syncedBuffer
)

type syncedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncedBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncedBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// readFixtures makes the test-time fixtures once. The sshd check (a bare
// TCP connect) runs once too: sshd's PerSourcePenalties counts each
// connection that never authenticates against its source, and a check per
// call made 127.0.0.1 refused for the tests that follow.
func readFixtures(t *testing.T) {
	t.Helper()
	fixtureOnce.Do(func() {
		// Failed until it finishes: a t.Fatal or t.Skip inside stops it early.
		fixtureErr = "the fixture setup did not finish (see the first read tool test)"
		defer func() {
			if r := recover(); r != nil {
				fixtureErr = fmt.Sprint(r)
			}
		}()
		needSSHD(t)
		if err := makeFixtures(t); err != nil {
			fixtureErr = err.Error()
			return
		}
		fixtureErr = ""
	})
	if fixtureErr != "" {
		t.Fatalf("read fixtures: %s", fixtureErr)
	}
}

func makeFixtures(t *testing.T) error {
	if err := os.WriteFile(tokenFile, []byte("api: "+e2eToken+"\nmode: example\n"), 0o644); err != nil { //nolint:gosec // G306: the gate's service account reads it
		return err
	}
	// A certificate, and a private key the certificate tool must refuse.
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "app.example.test"},
		DNSNames: []string{"app.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(45 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return err
	}
	if cerr := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); cerr != nil { //nolint:gosec // G306: public certificate
		return cerr
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if kerr := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o644); kerr != nil { //nolint:gosec // G306: a throwaway key the gate must refuse to show
		return kerr
	}

	// The repository: cloned from a local HTTPS server, one commit behind
	// its upstream after a fetch over HTTPS, one local commit ahead, and an
	// uncommitted change carrying the token.
	if rerr := os.RemoveAll(readRepo); rerr != nil {
		return rerr
	}
	g := gatetest.NewGitServer(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	g.WriteCA(t, ca)
	work := g.Seed(t, "example-app.git", map[string]string{"config.yaml": "version: 1\n"})
	g.Clone(t, "example-app.git", readRepo)
	gatetest.Push(t, work, "upstream.txt", "from upstream\n", "upstream change")
	gatetest.Git(t, readRepo, "-c", "http.sslCAInfo="+ca, "fetch", "-q", "origin")
	gatetest.Git(t, readRepo, "branch", "-q", "--set-upstream-to=origin/main")
	gatetest.WriteFile(t, filepath.Join(readRepo, "local.txt"), "local\n", 0o644)
	gatetest.Git(t, readRepo, "add", "local.txt")
	gatetest.Git(t, readRepo, "commit", "-q", "-m", "local example change")
	gatetest.WriteFile(t, filepath.Join(readRepo, "config.yaml"), "version: 2\ntoken: "+e2eToken+"\n", 0o644)
	if out, err := exec.CommandContext(t.Context(), "chmod", "-R", "a+rX", readRoot).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod: %w: %s", err, out)
	}

	// A journal line carrying the token, from a transient unit the read
	// policy lists.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	//nolint:gosec // G204: fixed argv; the token is this run's random fixture
	if out, err := exec.CommandContext(ctx, "systemd-run", "--quiet", "--wait", "--collect", "--unit=example-journal.service",
		"/usr/bin/echo", "example-journal using "+e2eToken).CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, out)
	}
	for range 50 {
		out, _ := exec.CommandContext(ctx, "journalctl", "--no-pager", "-u", "example-journal.service", "-o", "cat").Output()
		if bytes.Contains(out, []byte(e2eToken)) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("the journal line did not appear")
}

// server starts the real shell-mcp once: stdio, read-only profile, the
// read key, and a server-only redaction pattern for the run's token.
func server(t *testing.T) *mcp.ClientSession {
	t.Helper()
	readFixtures(t)
	serverOnce.Do(func() {
		pin := hostPin(t, "ssh_host_ed25519_key.pub")
		cmd := exec.CommandContext(context.Background(), filepath.Join(bin(), "shell-mcp"), "serve", "--transport", "stdio") //nolint:gosec // G204: the binary under test
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"SHELL_MCP_AUTH_MODE=none",
			"SHELL_MCP_PROFILE=read-only",
			"SHELL_MCP_TARGET_NAME=app-host",
			"SHELL_MCP_TARGET_HOST=" + sshdHost,
			"SHELL_MCP_TARGET_PORT=" + strconv.Itoa(sshdPort),
			"SHELL_MCP_TARGET_USER=svc-shell",
			"SHELL_MCP_TARGET_HOST_KEYS=" + pin.String(),
			"SHELL_MCP_SSH_KEY_FILE=" + filepath.Join(bin(), "e2e-client-key-read"),
			"SHELL_MCP_REDACT_PATTERNS=e2etok_[0-9a-f]{32}",
			"SHELL_MCP_MAX_OUTPUT_BYTES=65536",
		}
		cmd.Stderr = &serverLog
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil).
			Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			serverErr = fmt.Sprintf("connect: %v; server log: %s", err, serverLog.String())
			return
		}
		session = cs
	})
	if serverErr != "" {
		t.Fatal(serverErr)
	}
	return session
}

// callTool calls a tool through the real server and returns the envelope.
// It checks the result's shape: a summary line, then the envelope, and the
// run's token nowhere in the result or the server's log.
func callTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	cs := server(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), e2eToken[7:]) {
		t.Fatalf("%s: the token reached the result: %s", name, raw)
	}
	if strings.Contains(serverLog.String(), e2eToken[7:]) {
		t.Fatalf("%s: the token reached the server log", name)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("%s: structuredContent %s", name, b)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok || !strings.HasPrefix(tc.Text, "ok") && !strings.HasPrefix(tc.Text, "error: ") {
		t.Fatalf("%s: text block %v", name, res.Content)
	}
	if res.IsError == (env["ok"] == true) {
		t.Fatalf("%s: isError %v, envelope %v", name, res.IsError, env)
	}
	t.Logf("%s -> %s", name, firstLine(tc.Text)) // never the arguments: one carries the run's token
	return env
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func okData(t *testing.T, env map[string]any) map[string]any {
	t.Helper()
	d, ok := env["data"].(map[string]any)
	if !ok || env["ok"] != true || env["target"] != "app-host" {
		t.Fatalf("not a success: %v", env)
	}
	if g, _ := env["gate"].(map[string]any); g["principal"] != "e2e-read" {
		t.Fatalf("gate block %v", env["gate"])
	}
	return d
}

func refusal(t *testing.T, env map[string]any, code, contains string) {
	t.Helper()
	e, _ := env["error"].(map[string]any)
	msg, _ := e["message"].(string)
	if env["ok"] != false || e["code"] != code || !strings.Contains(msg, contains) || env["data"] != nil {
		t.Fatalf("envelope %v, want %s containing %q", env, code, contains)
	}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestReadToolGetSystemInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_system_info", map[string]any{}))
		if d["kernel"].(map[string]any)["sysname"] != "Linux" || d["cpu"].(map[string]any)["online"].(float64) < 1 {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_system_info", map[string]any{"target": "other-host"}), "unknown_target", "")
	})
}

func TestReadToolGetDiskUsage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_disk_usage", map[string]any{}))
		if !strings.Contains(asJSON(d["mounts"]), `"mount_point":"/"`) {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_disk_usage", map[string]any{"include_pseudo": "yes"}), "validation_error", "")
	})
}

func TestReadToolListProcesses(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_list_processes", map[string]any{"name_contains": "sleep", "limit": 20}))
		if !strings.Contains(asJSON(d["processes"]), `"comm":"sleep"`) { // example-app.service runs sleep
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_list_processes", map[string]any{"limit": 1001}), "validation_error", "limit")
	})
}

func TestReadToolGetServiceStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_service_status", map[string]any{"unit": "example-app.service"}))
		if d["active_state"] != "active" || d["load_state"] != "loaded" || d["main_pid"] == nil {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_service_status", map[string]any{"unit": "ssh.service"}), "policy_denied", "services.status")
	})
}

func TestReadToolListServices(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_list_services", map[string]any{"name_contains": "example-"}))
		s := asJSON(d["units"])
		if !strings.Contains(s, `"unit":"example-app.service"`) || strings.Contains(s, "ssh") {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_list_services", map[string]any{"limit": 0}), "validation_error", "limit")
	})
}

func TestReadToolGetJournal(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_journal", map[string]any{"unit": "example-journal.service", "since": "-1h", "lines": 50}))
		out, _ := d["output"].(string)
		if !strings.Contains(out, "example-journal using [REDACTED]") {
			t.Fatalf("the journal line is missing or not redacted: %q", out)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_journal", map[string]any{"unit": "example-other.service"}), "policy_denied", "journal.units")
	})
}

func TestReadToolListDirectory(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_list_directory", map[string]any{"path": readRoot + "/tree", "include_hidden": true}))
		s := asJSON(d["entries"])
		if !strings.Contains(s, `"link_target":"`+readRoot+`/tree/sub"`) || strings.Contains(s, ".netrc") {
			t.Fatalf("entries %s", s)
		}
	})
	t.Run("refusal_absolute_symlink", func(t *testing.T) {
		refusal(t, callTool(t, "shell_list_directory", map[string]any{"path": readRoot + "/tree/abs-link/sub"}), "path_denied", "absolute target")
	})
}

func TestReadToolStatPath(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_stat_path", map[string]any{"path": readRoot + "/tree/abs-link"}))
		if d["type"] != "symlink" || d["link_target"] != readRoot+"/tree/sub" {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal_outside_roots", func(t *testing.T) {
		refusal(t, callTool(t, "shell_stat_path", map[string]any{"path": "/etc/hostname"}), "path_denied", "")
	})
}

func TestReadToolReadFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_read_file", map[string]any{"path": tokenFile}))
		if d["content"] != "api: [REDACTED]\nmode: example\n" || d["binary"] != false {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal_denied_file", func(t *testing.T) {
		refusal(t, callTool(t, "shell_read_file", map[string]any{"path": readRoot + "/tree/.netrc"}), "path_denied", ".netrc")
		refusal(t, callTool(t, "shell_read_file", map[string]any{"path": readRoot + "/tree/private/note.txt"}), "path_denied", "paths.deny[0]")
	})
}

func TestReadToolFindFiles(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_find_files", map[string]any{"root": readRoot + "/tree", "name_glob": "*.txt", "type": "file", "modified_within": "1d"}))
		s := asJSON(d["entries"])
		if !strings.Contains(s, "file.txt") || !strings.Contains(s, "token.txt") || strings.Contains(s, "note.txt") {
			t.Fatalf("entries %s", s)
		}
	})
	t.Run("refusal_outside_roots", func(t *testing.T) {
		refusal(t, callTool(t, "shell_find_files", map[string]any{"root": "/etc"}), "path_denied", "")
	})
}

func TestReadToolInspectCertificate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_inspect_certificate", map[string]any{"path": certFile}))
		s := asJSON(d["certificates"])
		if !strings.Contains(s, `"dns_names":["app.example.test"]`) || !strings.Contains(s, `"key_type":"ECDSA"`) {
			t.Fatalf("certificates %s", s)
		}
	})
	t.Run("refusal_private_key", func(t *testing.T) {
		refusal(t, callTool(t, "shell_inspect_certificate", map[string]any{"path": keyFile}), "path_denied", "private key")
	})
}

func TestReadToolGetGitStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_git_status", map[string]any{"repo": readRepo}))
		if d["branch"] != "main" || d["upstream"] != "origin/main" || d["ahead"] != 1.0 || d["behind"] != 1.0 ||
			!strings.Contains(asJSON(d["entries"]), "config.yaml") {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("refusal_unlisted_repo", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_git_status", map[string]any{"repo": readRoot + "/tree"}), "policy_denied", "git.repos")
	})
}

func TestReadToolGetGitLog(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_git_log", map[string]any{"repo": readRepo, "limit": 5}))
		s := asJSON(d["commits"])
		if !strings.Contains(s, "local example change") || !strings.Contains(s, "initial") {
			t.Fatalf("commits %s", s)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_git_log", map[string]any{"repo": readRepo, "limit": 201}), "validation_error", "limit")
	})
}

func TestReadToolGetGitDiff(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := okData(t, callTool(t, "shell_get_git_diff", map[string]any{"repo": readRepo}))
		diff, _ := d["diff"].(string)
		if !strings.Contains(diff, "+version: 2") || !strings.Contains(diff, "+token: [REDACTED]") {
			t.Fatalf("diff %q", diff)
		}
		d = okData(t, callTool(t, "shell_get_git_diff", map[string]any{"repo": readRepo, "max_output_bytes": 40}))
		if diff, _ := d["diff"].(string); len(diff) > 40 || d["truncated"] != true {
			t.Fatalf("capped diff %v", d)
		}
	})
	t.Run("refusal_relative_repo", func(t *testing.T) {
		refusal(t, callTool(t, "shell_get_git_diff", map[string]any{"repo": "srv/example-app/repo"}), "validation_error", "absolute")
	})
}

func TestReadToolRunReadCommand(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		env := callTool(t, "shell_run_read_command", map[string]any{"command_id": "probe-echo", "args": []string{"echo", e2eToken}})
		d := okData(t, env)
		if d["stdout"] != "[REDACTED]\n" || env["exec"].(map[string]any)["exit_code"] != 0.0 {
			t.Fatalf("envelope %v", env)
		}
		// A non-zero exit is data, not a failure.
		env = callTool(t, "shell_run_read_command", map[string]any{"command_id": "probe-exit", "args": []string{"exit", "3"}})
		if okData(t, env) == nil || env["exec"].(map[string]any)["exit_code"] != 3.0 {
			t.Fatalf("envelope %v", env)
		}
	})
	t.Run("refusal_operator_command", func(t *testing.T) {
		// Control: the gate runs the operator command at ceiling operator
		// (its max_tier is operator), so the refusal below comes from the
		// read tool's ceiling, checked by the gate in the same step as
		// max_tier.
		resp := gateExec(t, "probe-operator", []string{"echo", "operator"})
		if !resp.OK {
			t.Fatalf("control: the gate refused the operator command: %+v", resp.Error)
		}
		start := time.Now()
		refusal(t, callTool(t, "shell_run_read_command", map[string]any{"command_id": "probe-operator", "args": []string{"echo", "operator"}}),
			"tier_denied", "ceiling read")
		// The gate refused it (its own audit line), before running anything.
		findJournal(t, "shell-mcp-gate", start, `"principal":"e2e-read"`, `"op":"exec"`, `"command_id":"probe-operator"`, `"outcome":"tier_denied"`)
	})
}

// gateExec sends one exec request straight to the gate with the read key.
func gateExec(t *testing.T, id string, args []string) *protocol.Response {
	t.Helper()
	c := sshClient(t, []config.HostKey{hostPin(t, "ssh_host_ed25519_key.pub")}, clientKey(t, "e2e-client-key-read"))
	resp, err := gateclient.New(gateclient.Options{}).Call(t.Context(), c, protocol.OpExec,
		map[string]any{"command_id": id, "args": args}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
