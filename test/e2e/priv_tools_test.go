//go:build e2e && linux

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The privileged read tools and the privileged foundations end to end
// (handoff docs/handoff/S4C-PRIVILEGED.md, S4c-1): the real shell-mcp
// (stdio, admin profile) with the key whose forced command serves the
// main gate policy (privileged forwarding on, principal e2e-ssh), the real
// gate and the real helper units. Every file and value is invented; tokens
// are random per run.

const privReadDir = "/etc/example-app/e2e-priv-read"

var (
	privOnce    sync.Once
	privErr     string
	privSession *mcp.ClientSession
	privLog     syncedBuffer
	privToken   = "e2eprivtok_" + randomHex(16)
)

// privServer makes the fixtures and starts the admin server, once.
func privServer(t *testing.T) *mcp.ClientSession {
	t.Helper()
	privOnce.Do(func() {
		privErr = "the privileged fixture setup did not finish (see the first privileged tool test)"
		defer func() {
			if r := recover(); r != nil {
				privErr = fmt.Sprint(r)
			}
		}()
		needSSHD(t)
		if err := privFixtures(); err != nil {
			privErr = err.Error()
			return
		}
		// The run's token is redacted only by this server-side pattern.
		cs, err := startServer(t, &privLog, "SHELL_MCP_PROFILE=admin", "SHELL_MCP_SSH_KEY_FILE="+filepath.Join(bin(), "e2e-client-key"),
			"SHELL_MCP_REDACT_PATTERNS=e2eprivtok_[0-9a-f]{32}")
		if err != nil {
			privErr = fmt.Sprintf("connect: %v; server log: %s", err, privLog.String())
			return
		}
		privSession, privErr = cs, ""
	})
	if privErr != "" {
		t.Fatalf("privileged fixtures: %s", privErr)
	}
	return privSession
}

// privFixtures: a root-only directory under the privileged read and write
// root, which the gate's service account cannot read: a root-only file
// carrying a bearer token (the helper's built-in redaction) and the run's
// token (only the server's pattern knows it), a file larger than the
// server's output cap, a private key, and a symlink; and a file under the
// policy's deny list.
func privFixtures() error {
	if err := os.RemoveAll(privReadDir); err != nil {
		return err
	}
	if err := os.Mkdir(privReadDir, 0o700); err != nil {
		return err
	}
	files := map[string]string{
		"root-only.conf": "mode: example\nAuthorization: Bearer abc.def.ghi\napi: " + privToken + "\n",
		"big.txt":        strings.Repeat("example line of text\n", 5000),
		"id_example":     "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAexample\n-----END OPENSSH PRIVATE KEY-----\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(privReadDir, name), []byte(content), 0o600); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/example-app/secrets", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/example-app/secrets/token", []byte("denied\n"), 0o600); err != nil {
		return err
	}
	return os.Symlink("root-only.conf", filepath.Join(privReadDir, "link.conf"))
}

func privCall(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	env := callOn(t, privServer(t), &privLog, name, args)
	raw := asJSON(env)
	if strings.Contains(raw, privToken[11:]) || strings.Contains(privLog.String(), privToken[11:]) {
		t.Fatalf("%s: the run's token reached the result or the server log", name)
	}
	return env
}

func fileSHA256(t *testing.T, p string) string {
	t.Helper()
	s := sha256.Sum256([]byte(readFile(t, p)))
	return hex.EncodeToString(s[:])
}

// TestPrivToolsListed: the read tools (read-only) and the write-class tools
// of S4c-2 to S4c-5 (destructiveHint, always approval-gated) are in the
// admin catalogue, and no other privileged tool yet.
func TestPrivToolsListed(t *testing.T) {
	res, err := privServer(t).ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := "shell_priv_change_owner shell_priv_copy_path shell_priv_delete_path shell_priv_make_directory shell_priv_move_path shell_priv_restore_backup shell_priv_set_permissions shell_priv_write_file"
	var got []string
	for _, tool := range res.Tools {
		if strings.HasPrefix(tool.Name, "shell_priv_") {
			got = append(got, tool.Name)
			a := tool.Annotations
			switch {
			case strings.Contains(writes, tool.Name):
				if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || tool.Meta["anthropic/requiresUserInteraction"] != true {
					t.Fatalf("%s: annotations %+v meta %v", tool.Name, a, tool.Meta)
				}
			case a == nil || !a.ReadOnlyHint:
				t.Fatalf("%s is not read-only: %+v", tool.Name, a)
			}
		}
	}
	if want := "shell_priv_change_owner shell_priv_copy_path shell_priv_delete_path shell_priv_list_backups shell_priv_list_directory shell_priv_make_directory shell_priv_move_path shell_priv_preview_delete shell_priv_read_file shell_priv_restore_backup shell_priv_set_permissions shell_priv_stat_path shell_priv_write_file"; strings.Join(got, " ") != want {
		t.Fatalf("privileged tools %v, want %s", got, want)
	}
}

// TestPrivToolReadFile: a root-only file read through the real server and
// the core unit, redacted by the helper's built-in rules and the server's
// pattern; the refusals: outside the roots, the deny list, the never list,
// a private key, a final symlink, a max_bytes above the policy's.
func TestPrivToolReadFile(t *testing.T) {
	d := okDataAs(t, privCall(t, "shell_priv_read_file", map[string]any{"path": privReadDir + "/root-only.conf"}), "e2e-ssh")
	content, _ := d["content"].(string)
	if !strings.Contains(content, "mode: example") || strings.Contains(content, "abc.def.ghi") || !strings.Contains(content, "[REDACTED]") {
		t.Fatalf("content %q", content)
	}
	// The server's own cap (SHELL_MCP_MAX_OUTPUT_BYTES=65536).
	d = okDataAs(t, privCall(t, "shell_priv_read_file", map[string]any{"path": privReadDir + "/big.txt", "max_bytes": 200000}), "e2e-ssh")
	if c, _ := d["content"].(string); len(c) > 65536 || d["truncated"] != true {
		t.Fatalf("big file: %d bytes, truncated %v", len(c), d["truncated"])
	}
	for _, c := range []struct {
		path, code, contains string
		extra                map[string]any
	}{
		{"/etc/example-other/secret.txt", "path_denied", "", nil},
		{"/etc/example-app/secrets/token", "path_denied", "", nil},
		{"/etc/shadow", "path_denied", "", nil},
		{privReadDir + "/id_example", "path_denied", "private key", nil},
		{privReadDir + "/link.conf", "path_denied", "symlink", nil},
		{privReadDir + "/root-only.conf", "bad_request", "max_bytes", map[string]any{"max_bytes": 4 << 20}},
	} {
		args := map[string]any{"path": c.path}
		for k, v := range c.extra {
			args[k] = v
		}
		refusal(t, privCall(t, "shell_priv_read_file", args), c.code, c.contains)
	}
}

// TestPrivToolListAndStat: the root-only directory is listed and its
// symlink reported, not followed; outside the roots is refused.
func TestPrivToolListAndStat(t *testing.T) {
	d := okDataAs(t, privCall(t, "shell_priv_list_directory", map[string]any{"path": privReadDir}), "e2e-ssh")
	types := map[string]any{}
	es, _ := d["entries"].([]any)
	for _, e := range es {
		m, _ := e.(map[string]any)
		types[fmt.Sprint(m["name"])] = m["type"]
	}
	if types["root-only.conf"] != "file" || types["link.conf"] != "symlink" || types["id_example"] != "file" {
		t.Fatalf("entries %v", d["entries"])
	}
	d = okDataAs(t, privCall(t, "shell_priv_stat_path", map[string]any{"path": privReadDir + "/link.conf"}), "e2e-ssh")
	if d["type"] != "symlink" || d["link_target"] != "root-only.conf" {
		t.Fatalf("stat %v", d)
	}
	d = okDataAs(t, privCall(t, "shell_priv_stat_path", map[string]any{"path": privReadDir}), "e2e-ssh")
	if d["mode"] != "0700" || d["uid"] != float64(0) {
		t.Fatalf("stat %v", d)
	}
	refusal(t, privCall(t, "shell_priv_list_directory", map[string]any{"path": "/etc/example-other"}), "path_denied", "")
	refusal(t, privCall(t, "shell_priv_stat_path", map[string]any{"path": "/etc/ssh/sshd_config"}), "path_denied", "")
}

// TestPrivToolListBackups: a backup the helper wrote is listed, filtered by
// path.
func TestPrivToolListBackups(t *testing.T) {
	privServer(t)
	p := privReadDir + "/backed-up.conf"
	mustGate(t, "priv_write_file", map[string]any{"path": p, "content_b64": "b25lCg=="}, nil)
	var w struct {
		BackupIDs []string `json:"backup_ids"`
	}
	mustGate(t, "priv_write_file", map[string]any{"path": p, "content_b64": "dHdvCg=="}, &w)
	if len(w.BackupIDs) != 1 {
		t.Fatalf("backup ids %v", w.BackupIDs)
	}
	d := okDataAs(t, privCall(t, "shell_priv_list_backups", map[string]any{"path": p}), "e2e-ssh")
	bs, _ := d["backups"].([]any)
	if len(bs) != 1 || bs[0].(map[string]any)["id"] != w.BackupIDs[0] || bs[0].(map[string]any)["path"] != p {
		t.Fatalf("backups %v, want %v", bs, w.BackupIDs)
	}
}

// TestPrivToolJournalJoin: the helper's journal line and the gate's for the
// same tool call join on the request id.
func TestPrivToolJournalJoin(t *testing.T) {
	privServer(t)
	marker := privReadDir + "/join-" + randomHex(4)
	since := time.Now()
	refusal(t, privCall(t, "shell_priv_stat_path", map[string]any{"path": marker}), "not_found", "")
	h := findJournal(t, "shell-mcp-privd", since, `"op":"priv_stat"`, marker)
	var line struct {
		ID      string `json:"id"`
		Ceiling string `json:"ceiling"`
	}
	if err := json.Unmarshal([]byte(h.Message), &line); err != nil || line.ID == "" || line.Ceiling != "read" {
		t.Fatalf("helper line %q", h.Message)
	}
	findJournal(t, "shell-mcp-gate", since, `"id":"`+line.ID+`"`, `"op":"priv_stat"`, `"principal":"e2e-ssh"`, `"outcome":"not_found"`)
}

// TestPrivHelperBlockReachesServer: the server's gate client sees the
// helper's block (P-1): the privileged policy's SHA-256 and the unit that
// answered, beside the gate's own policy hash.
func TestPrivHelperBlockReachesServer(t *testing.T) {
	needSSHD(t)
	c := sshClient(t, []config.HostKey{hostPin(t, "ssh_host_ed25519_key.pub")}, clientKey(t, "e2e-client-key"))
	resp, err := gateclient.New(gateclient.Options{}).Call(t.Context(), c, protocol.OpPrivStat, protocol.TierRead,
		map[string]any{"path": "/etc/example-app"}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Gate == nil || resp.Gate.PolicySHA256 != fileSHA256(t, gatePolicy) || resp.Gate.Principal != "e2e-ssh" {
		t.Fatalf("gate block %+v (error %+v)", resp.Gate, resp.Error)
	}
	if h := resp.Helper; h == nil || h.PolicySHA256 != fileSHA256(t, privPolicy) || h.Unit != "core" || h.Principal != "shell-mcp-privd" {
		t.Fatalf("helper block %+v", resp.Helper)
	}
}

// TestPrivTimeoutAnswerAfterCommandEnded (P-7): a request whose timeout is
// above the gate's max_timeout_s (5 s here) runs a command that ignores
// SIGTERM, in each unit. The gate forwards the timeout it waits for, so
// the helper's own deadline comes first: it kills the command and answers
// timed_out, and the gate's answer comes only after the command has ended.
// Before the clamp the gate answered `timeout` at 5 s plus its 15 s grace
// while the helper let the command run to the request's 40 s.
func TestPrivTimeoutAnswerAfterCommandEnded(t *testing.T) {
	short := "/etc/shell-mcp/gate-e2e-short.yaml"
	y := strings.Replace(readFile(t, gatePolicy), "paths:\n", "limits:\n  max_timeout_s: 5\n  default_timeout_s: 5\npaths:\n", 1)
	if err := os.WriteFile(short, []byte(y), 0o644); err != nil { //nolint:gosec // G306: a gate policy is root-owned and world-readable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(short) })
	sleepArgs := []string{"ignore-term", "60s"}
	for _, c := range []struct{ command, unit string }{{"probe-attrs", "core"}, {"probe-broad", "broad"}} {
		t.Run(c.unit, func(t *testing.T) {
			a := map[string]any{"command_id": c.command, "args": sleepArgs}
			if c.unit == "broad" {
				a["unit"] = "broad"
			}
			args, _ := json.Marshal(a)
			req := fmt.Sprintf(`{"v":1,"id":%q,"ceiling":"destructive","op":"priv_exec","args":%s,"timeout_ms":40000}`+"\n", newID(), args)
			cmd := exec.CommandContext(t.Context(), gateBin, "serve", "--policy", short, "--principal", "e2e")
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred(t, svcShell)}
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			cmd.Dir = "/"
			cmd.Stdin = strings.NewReader(req)
			var out bytes.Buffer
			cmd.Stdout = &out
			start := time.Now()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			p := gatetest.FindChild(t, 0, sleepArgs...)
			t.Cleanup(p.Kill)
			p.WaitIgnoring(t, syscall.SIGTERM)
			if _, unit := helperOf(t, p, c.unit == "broad"); unit == "" {
				t.Fatal("no helper unit")
			}
			_ = cmd.Wait()
			took := time.Since(start)
			if p.Alive() {
				t.Fatalf("the gate answered after %v while the command (pid %d) was still running: %s", took, p.Pid, out.String())
			}
			var r struct {
				OK    bool `json:"ok"`
				Error *struct {
					Code string `json:"code"`
				} `json:"error"`
				Data struct {
					TimedOut bool    `json:"timed_out"`
					Signal   *string `json:"signal"`
				} `json:"data"`
				Helper *struct {
					Unit string `json:"unit"`
				} `json:"helper"`
			}
			if err := json.Unmarshal(out.Bytes(), &r); err != nil || !r.OK || !r.Data.TimedOut || r.Data.Signal == nil || *r.Data.Signal != "SIGKILL" {
				t.Fatalf("answer after %v: %s", took, out.String())
			}
			if r.Helper == nil || r.Helper.Unit != c.unit {
				t.Fatalf("helper block %s", out.String())
			}
			if took > 15*time.Second {
				t.Fatalf("the answer took %v under max_timeout_s 5", took)
			}
		})
	}
}
