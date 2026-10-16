//go:build e2e && linux

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http/cgi" //nolint:gosec // G504: test-only CGI host for git http-backend; the httpoxy issue was fixed in Go 1.6.3
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

// The operator tools end to end: the real shell-mcp binary (stdio,
// operator profile), the real test sshd and the installed gate with the
// operator policy (/etc/shell-mcp/gate-operator.yaml, principal
// e2e-operator, from setup.sh). Each tool has its own test with success
// and refusal cases, and each refusal checks that the host did not change.
// The git remote is a local HTTPS server on 127.0.0.1:44443 (the port the
// policy's sandbox opens) with a certificate authority generated for this
// run and added to the runner VM's trust store, because the gate's git
// trusts only the system store. Every value is invented.

const (
	opsRoot    = "/srv/example-ops"
	opsWork    = opsRoot + "/work"
	opsRepos   = opsRoot + "/repos"
	opsRepo    = opsRepos + "/app"
	opsForeign = opsRepos + "/foreign"
	opsGitAddr = "127.0.0.1:44443"
	opsRemote  = "https://" + opsGitAddr + "/example-ops.git"
	opsCAFile  = "/usr/local/share/ca-certificates/shell-mcp-e2e-git.crt"
	opsKey     = "e2e-client-key-operator"
	opsWho     = "e2e-operator"
)

var operatorToolNames = []string{
	"shell_control_service", "shell_write_file", "shell_make_directory", "shell_copy_path",
	"shell_move_path", "shell_set_permissions", "shell_git_pull", "shell_run_command",
}

var (
	opsOnce    sync.Once
	opsErr     string
	opsSession *mcp.ClientSession
	opsLog     syncedBuffer
	opsSeed    string // the working copy that pushes upstream changes
	opsBare    string // the bare repository the HTTPS server serves
)

// startServer starts the real shell-mcp (stdio, none auth) with the
// operator key and profile, plus extra environment.
func startServer(t *testing.T, log *syncedBuffer, extra ...string) (*mcp.ClientSession, error) {
	t.Helper()
	pin := hostPin(t, "ssh_host_ed25519_key.pub")
	cmd := exec.CommandContext(context.Background(), filepath.Join(bin(), "shell-mcp"), "serve", "--transport", "stdio") //nolint:gosec // G204: the binary under test
	cmd.Env = append([]string{
		"PATH=/usr/bin:/bin",
		"SHELL_MCP_AUTH_MODE=none",
		"SHELL_MCP_PROFILE=operator",
		"SHELL_MCP_TARGET_NAME=app-host",
		"SHELL_MCP_TARGET_HOST=" + sshdHost,
		"SHELL_MCP_TARGET_PORT=" + strconv.Itoa(sshdPort),
		"SHELL_MCP_TARGET_USER=svc-shell",
		"SHELL_MCP_TARGET_HOST_KEYS=" + pin.String(),
		"SHELL_MCP_SSH_KEY_FILE=" + filepath.Join(bin(), opsKey),
		"SHELL_MCP_MAX_OUTPUT_BYTES=65536",
	}, extra...)
	cmd.Stderr = log
	return mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil).
		Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
}

// opsServer makes the fixtures and starts the operator server, once.
func opsServer(t *testing.T) *mcp.ClientSession {
	t.Helper()
	opsOnce.Do(func() {
		// Failed until it finishes: a t.Fatal or t.Skip inside stops it early.
		opsErr = "the operator fixture setup did not finish (see the first operator tool test)"
		defer func() {
			if r := recover(); r != nil {
				opsErr = fmt.Sprint(r)
			}
		}()
		needSSHD(t)
		if err := opsFixtures(t); err != nil {
			opsErr = err.Error()
			return
		}
		cs, err := startServer(t, &opsLog)
		if err != nil {
			opsErr = fmt.Sprintf("connect: %v; server log: %s", err, opsLog.String())
			return
		}
		opsSession, opsErr = cs, ""
	})
	if opsErr != "" {
		t.Fatalf("operator fixtures: %s", opsErr)
	}
	return opsSession
}

func opCall(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	return callOn(t, opsServer(t), &opsLog, name, args)
}

func opOK(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	return okDataAs(t, opCall(t, name, args), opsWho)
}

// opsFixtures starts the HTTPS git server and makes the repositories: app
// is one commit behind its upstream; foreign's origin is another URL.
func opsFixtures(t *testing.T) error {
	ca, cert, err := gitCerts()
	if err != nil {
		return err
	}
	if werr := os.WriteFile(opsCAFile, ca, 0o644); werr != nil { //nolint:gosec // G306: a public CA certificate for the trust store
		return werr
	}
	if out, uerr := exec.CommandContext(t.Context(), "update-ca-certificates").CombinedOutput(); uerr != nil {
		return fmt.Errorf("update-ca-certificates: %w: %s", uerr, out)
	}
	root, err := os.MkdirTemp("", "e2e-git-")
	if err != nil {
		return err
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", opsGitAddr)
	if err != nil {
		return fmt.Errorf("the git server cannot listen on %s: %w", opsGitAddr, err)
	}
	srv := httptest.NewUnstartedServer(&cgi.Handler{Path: gatetest.GitBin, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}})
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS() // lives until the test binary exits

	opsSeed = filepath.Join(root, "seed")
	gatetest.Mkdir(t, opsSeed, 0o755)
	gatetest.Git(t, opsSeed, "init", "-q")
	gatetest.WriteFile(t, filepath.Join(opsSeed, "app.conf"), "version: 1\n", 0o644)
	gatetest.Git(t, opsSeed, "add", "-A")
	gatetest.Git(t, opsSeed, "commit", "-q", "-m", "initial")
	gatetest.Git(t, root, "clone", "-q", "--bare", opsSeed, "example-ops.git")
	opsBare = filepath.Join(root, "example-ops.git")
	for _, kv := range [][2]string{{"receive.autogc", "false"}, {"maintenance.auto", "false"}, {"gc.auto", "0"}} {
		gatetest.Git(t, opsBare, "config", kv[0], kv[1])
	}
	gatetest.Git(t, opsSeed, "remote", "add", "origin", opsBare)
	for _, r := range []struct{ dir, url string }{{"app", opsRemote}, {"foreign", "https://" + opsGitAddr + "/other.git"}} {
		_ = os.RemoveAll(filepath.Join(opsRepos, r.dir))
		gatetest.Git(t, opsRepos, "clone", "-q", opsBare, r.dir)
		gatetest.Git(t, filepath.Join(opsRepos, r.dir), "remote", "set-url", "origin", r.url)
	}
	gatetest.Push(t, opsSeed, "upstream.txt", "from upstream\n", "upstream change")
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "svc-shell:svc-shell", opsRepos, opsWork).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %w: %s", err, out)
	}
	return nil
}

// gitCerts makes a CA for this run and a server certificate for
// 127.0.0.1 signed by it. The CA's key never leaves this process.
func gitCerts() (caPEM []byte, server tls.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, server, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shell-mcp e2e git CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, server, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, server, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, server, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, server, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// --- Host-side helpers ------------------------------------------------------------

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// opsFile writes a fixture file owned by the service account.
func opsFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	_ = os.RemoveAll(p)
	gatetest.WriteFile(t, p, content, mode)
	if err := os.Chown(p, svcShell, svcShell); err != nil {
		t.Fatal(err)
	}
}

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func owner(t *testing.T, p string) uint32 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	return st.Uid
}

// repoGit runs git as root in a repository the service account owns.
func repoGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return strings.TrimSpace(gatetest.Git(t, dir, append([]string{"-c", "safe.directory=*"}, args...)...))
}

// --- Tests -----------------------------------------------------------------------

// TestOperatorToolsListed: the operator profile lists every operator tool
// next to the read tools.
func TestOperatorToolsListed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, err := opsServer(t).ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	have := []string{}
	for _, tl := range res.Tools {
		have = append(have, tl.Name)
	}
	for _, want := range append(slices.Clone(operatorToolNames), "shell_read_file", "shell_run_read_command") {
		if !slices.Contains(have, want) {
			t.Fatalf("%s is not listed (have %v)", want, have)
		}
	}
}

func TestOperatorToolWriteFile(t *testing.T) {
	t.Run("success_read_back", func(t *testing.T) {
		p := opsWork + "/notes.txt"
		_ = os.Remove(p)
		start := time.Now()
		v1 := "line one\nline two\n"
		env := opCall(t, "shell_write_file", map[string]any{"path": p, "content": v1, "mode": "0640"})
		d := okDataAs(t, env, opsWho)
		if env["verified"] != true || d["created"] != true || d["new_sha256"] != sha(v1) || d["old_sha256"] != "" || d["lines_new"] != 2.0 {
			t.Fatalf("envelope %v", env)
		}
		// Read back independently: the bytes on disk are what was sent.
		if got := readFile(t, p); got != v1 || sha(got) != d["new_sha256"] || perm(t, p) != 0o640 || owner(t, p) != svcShell {
			t.Fatalf("on disk: %q mode %v owner %d", got, perm(t, p), owner(t, p))
		}
		// The current hash allows the next write (optimistic concurrency).
		v2 := v1 + "line three\n"
		env = opCall(t, "shell_write_file", map[string]any{"path": p, "content": v2, "expected_sha256": sha(v1)})
		d = okDataAs(t, env, opsWho)
		if env["verified"] != true || d["created"] != false || d["old_sha256"] != sha(v1) || d["new_sha256"] != sha(v2) || d["lines_delta"] != 1.0 {
			t.Fatalf("envelope %v", env)
		}
		if got := readFile(t, p); got != v2 {
			t.Fatalf("on disk: %q", got)
		}
		// The gate's audit line records the operator ceiling, and never the content.
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"write_file"`, `"ceiling":"operator"`, `"outcome":"ok"`)
		for _, j := range journal(t, "shell-mcp-gate", start) {
			if strings.Contains(j.Message, "line one") {
				t.Fatalf("the gate's audit carries content: %q", j.Message)
			}
		}
	})
	t.Run("refusal_stale_expected_sha256", func(t *testing.T) {
		p := opsWork + "/stale.txt"
		_ = os.Remove(p)
		okDataAs(t, opCall(t, "shell_write_file", map[string]any{"path": p, "content": "v1\n"}), opsWho)
		// Someone else changes the file after the caller read it.
		if err := os.WriteFile(p, []byte("v2 by someone else\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		refusal(t, opCall(t, "shell_write_file", map[string]any{"path": p, "content": "v3\n", "expected_sha256": sha("v1\n")}),
			"exists", "expected_sha256")
		if got := readFile(t, p); got != "v2 by someone else\n" {
			t.Fatalf("a stale write changed the file: %q", got)
		}
	})
	t.Run("refusal_outside_write_roots", func(t *testing.T) {
		refusal(t, opCall(t, "shell_write_file", map[string]any{"path": opsRoot + "/readonly.txt", "content": "x\n"}), "path_denied", "write roots")
		refusal(t, opCall(t, "shell_write_file", map[string]any{"path": opsRoot + "/new.txt", "content": "x\n"}), "path_denied", "write roots")
		if got := readFile(t, opsRoot+"/readonly.txt"); got != "read only\n" {
			t.Fatalf("readonly.txt: %q", got)
		}
		if _, err := os.Lstat(opsRoot + "/new.txt"); !os.IsNotExist(err) {
			t.Fatalf("new.txt exists: %v", err)
		}
	})
	t.Run("refusal_git_directory", func(t *testing.T) {
		opsServer(t)
		before := readFile(t, opsRepo+"/.git/config")
		refusal(t, opCall(t, "shell_write_file", map[string]any{"path": opsRepo + "/.git/config", "content": "[core]\n"}), "path_denied", "protected")
		if readFile(t, opsRepo+"/.git/config") != before {
			t.Fatal(".git/config changed")
		}
	})
}

func TestOperatorToolMakeDirectory(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opsServer(t)
		_ = os.RemoveAll(opsWork + "/conf.d")
		_ = os.RemoveAll(opsWork + "/a")
		d := opOK(t, "shell_make_directory", map[string]any{"path": opsWork + "/conf.d", "mode": "0750"})
		if d["created"] != true || perm(t, opsWork+"/conf.d") != 0o750 {
			t.Fatalf("data %v", d)
		}
		opOK(t, "shell_make_directory", map[string]any{"path": opsWork + "/a/b/c", "parents": true})
		if fi, err := os.Lstat(opsWork + "/a/b/c"); err != nil || !fi.IsDir() {
			t.Fatalf("a/b/c: %v", err)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		opsServer(t)
		refusal(t, opCall(t, "shell_make_directory", map[string]any{"path": opsRepo + "/.git/extra"}), "path_denied", "protected")
		refusal(t, opCall(t, "shell_make_directory", map[string]any{"path": opsWork + "/missing/x"}), "not_found", "")
		for _, p := range []string{opsRepo + "/.git/extra", opsWork + "/missing"} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("%s exists: %v", p, err)
			}
		}
	})
}

func TestOperatorToolCopyPath(t *testing.T) {
	src, dst := opsWork+"/app.conf", opsWork+"/app.conf.bak"
	t.Run("success", func(t *testing.T) {
		opsServer(t)
		opsFile(t, src, "key: value\n", 0o644)
		_ = os.Remove(dst)
		env := opCall(t, "shell_copy_path", map[string]any{"source": src, "destination": dst})
		d := okDataAs(t, env, opsWho)
		if env["verified"] != true || d["created"] != true || d["sha256"] != sha("key: value\n") || readFile(t, dst) != "key: value\n" {
			t.Fatalf("envelope %v", env)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		opsServer(t)
		opsFile(t, src, "key: other\n", 0o644)
		opsFile(t, dst, "kept\n", 0o644)
		refusal(t, opCall(t, "shell_copy_path", map[string]any{"source": src, "destination": dst}), "exists", "")
		refusal(t, opCall(t, "shell_copy_path", map[string]any{"source": src, "destination": opsRoot + "/copy.txt"}), "path_denied", "write roots")
		if readFile(t, dst) != "kept\n" {
			t.Fatal("a refused copy replaced the destination")
		}
		if _, err := os.Lstat(opsRoot + "/copy.txt"); !os.IsNotExist(err) {
			t.Fatalf("copy.txt exists: %v", err)
		}
	})
}

func TestOperatorToolMovePath(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opsServer(t)
		a, b := opsWork+"/move-a.txt", opsWork+"/move-b.txt"
		opsFile(t, a, "moving\n", 0o644)
		_ = os.Remove(b)
		d := opOK(t, "shell_move_path", map[string]any{"source": a, "destination": b})
		if d["type"] != "file" || d["replaced"] != false || readFile(t, b) != "moving\n" {
			t.Fatalf("data %v", d)
		}
		if _, err := os.Lstat(a); !os.IsNotExist(err) {
			t.Fatalf("the source still exists: %v", err)
		}
	})
	t.Run("refusal_into_git_directory", func(t *testing.T) {
		opsServer(t)
		loose := opsRepos + "/loose.txt"
		opsFile(t, loose, "loose\n", 0o644)
		refusal(t, opCall(t, "shell_move_path", map[string]any{"source": loose, "destination": opsRepo + "/.git/loose.txt"}), "path_denied", "protected")
		if readFile(t, loose) != "loose\n" {
			t.Fatal("the source changed")
		}
		if _, err := os.Lstat(opsRepo + "/.git/loose.txt"); !os.IsNotExist(err) {
			t.Fatalf("moved into .git: %v", err)
		}
	})
}

func TestOperatorToolSetPermissions(t *testing.T) {
	p := opsWork + "/perm.txt"
	t.Run("success", func(t *testing.T) {
		opsServer(t)
		opsFile(t, p, "x\n", 0o644)
		d := opOK(t, "shell_set_permissions", map[string]any{"path": p, "mode": "0600"})
		if d["old_mode"] != "0644" || d["mode"] != "0600" || perm(t, p) != 0o600 {
			t.Fatalf("data %v, on disk %v", d, perm(t, p))
		}
	})
	t.Run("refusal_setuid_and_world_writable", func(t *testing.T) {
		opsServer(t)
		opsFile(t, p, "x\n", 0o640)
		refusal(t, opCall(t, "shell_set_permissions", map[string]any{"path": p, "mode": "4755"}), "policy_denied", "setuid")
		refusal(t, opCall(t, "shell_set_permissions", map[string]any{"path": p, "mode": "0666"}), "policy_denied", "world-writable")
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode changed: %v %v", fi.Mode(), err)
		}
	})
}

func mainPID(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(run(t, "systemctl", "show", "-p", "MainPID", "--value", "example-app.service"))
}

func TestOperatorToolControlService(t *testing.T) {
	t.Run("success_restart", func(t *testing.T) {
		opsServer(t)
		before := mainPID(t)
		args := map[string]any{"unit": "example-app.service", "action": "restart"}
		// An earlier test removes and restores the polkit rule; give polkitd
		// a moment to reload it.
		env := opCall(t, "shell_control_service", args)
		for i := 0; i < 20 && errCodeOf(env) == "not_authorized"; i++ {
			time.Sleep(500 * time.Millisecond)
			env = opCall(t, "shell_control_service", args)
		}
		d := okDataAs(t, env, opsWho)
		st, _ := d["status"].(map[string]any)
		if d["action"] != "restart" || st["active_state"] != "active" {
			t.Fatalf("data %v", d)
		}
		if after := mainPID(t); after == before || after == "0" {
			t.Fatalf("the unit was not restarted: main PID %s before, %s after", before, after)
		}
	})
	t.Run("refusal_not_in_policy", func(t *testing.T) {
		opsServer(t)
		refusal(t, opCall(t, "shell_control_service", map[string]any{"unit": "example-other.service", "action": "restart"}),
			"policy_denied", "services.control.units")
		refusal(t, opCall(t, "shell_control_service", map[string]any{"unit": "example-app.service", "action": "reload"}),
			"policy_denied", "services.control.verbs")
	})
	t.Run("refusal_polkit", func(t *testing.T) {
		opsServer(t)
		// stop is in the gate policy but not in the polkit rule.
		refusal(t, opCall(t, "shell_control_service", map[string]any{"unit": "example-app.service", "action": "stop"}), "not_authorized", "polkit")
		if active := strings.TrimSpace(run(t, "systemctl", "is-active", "example-app.service")); active != "active" {
			t.Fatalf("a refused stop stopped the unit: %s", active)
		}
	})
}

func errCodeOf(env map[string]any) string {
	e, _ := env["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestOperatorToolGitPull(t *testing.T) {
	t.Run("success_fast_forward", func(t *testing.T) {
		opsServer(t)
		old := repoGit(t, opsRepo, "rev-parse", "HEAD")
		upstream := repoGit(t, opsBare, "rev-parse", "main")
		d := opOK(t, "shell_git_pull", map[string]any{"repo": opsRepo})
		if d["updated"] != true || d["old_head"] != old || d["new_head"] != upstream || d["changed_files"] != 1.0 {
			t.Fatalf("data %v (old %s, upstream %s)", d, old, upstream)
		}
		if readFile(t, opsRepo+"/upstream.txt") != "from upstream\n" || repoGit(t, opsRepo, "rev-parse", "HEAD") != upstream {
			t.Fatal("the working tree was not fast-forwarded")
		}
	})
	t.Run("refusal_dirty_tree", func(t *testing.T) {
		opsServer(t)
		gatetest.Push(t, opsSeed, "second.txt", "second\n", "second upstream change")
		head := repoGit(t, opsRepo, "rev-parse", "HEAD")
		opsFile(t, opsRepo+"/app.conf", "version: local edit\n", 0o644)
		t.Cleanup(func() { opsFile(t, opsRepo+"/app.conf", "version: 1\n", 0o644) })
		refusal(t, opCall(t, "shell_git_pull", map[string]any{"repo": opsRepo}), "policy_denied", "uncommitted")
		if repoGit(t, opsRepo, "rev-parse", "HEAD") != head || readFile(t, opsRepo+"/app.conf") != "version: local edit\n" {
			t.Fatal("a refused pull changed the repository")
		}
	})
	t.Run("refusal_foreign_remote", func(t *testing.T) {
		opsServer(t)
		head := repoGit(t, opsForeign, "rev-parse", "HEAD")
		refusal(t, opCall(t, "shell_git_pull", map[string]any{"repo": opsForeign}), "policy_denied", "remote.origin.url")
		if repoGit(t, opsForeign, "rev-parse", "HEAD") != head {
			t.Fatal("a refused pull moved HEAD")
		}
	})
}

func TestOperatorToolRunCommand(t *testing.T) {
	t.Run("success_stdin", func(t *testing.T) {
		env := opCall(t, "shell_run_command", map[string]any{"command_id": "probe-stdin", "args": []string{"stdin"}, "stdin": "hello from stdin\n"})
		d := okDataAs(t, env, opsWho)
		if d["stdout"] != "hello from stdin\n" || env["exec"].(map[string]any)["exit_code"] != 0.0 {
			t.Fatalf("envelope %v", env)
		}
		if strings.Contains(opsLog.String(), "hello from stdin") {
			t.Fatal("stdin reached the server log")
		}
	})
	t.Run("success_non_zero_exit", func(t *testing.T) {
		env := opCall(t, "shell_run_command", map[string]any{"command_id": "probe-exit", "args": []string{"exit", "3"}})
		if okDataAs(t, env, opsWho) == nil || env["exec"].(map[string]any)["exit_code"] != 3.0 {
			t.Fatalf("envelope %v", env)
		}
	})
	t.Run("refusal_destructive_command", func(t *testing.T) {
		opsServer(t)
		// Control: the gate runs the destructive command at ceiling
		// destructive (its max_tier is destructive), so the refusal below
		// comes from the operator tool's ceiling.
		resp := gateExecAt(t, opsKey, protocol.TierDestructive, "probe-destructive", []string{"echo", "destructive"})
		if !resp.OK {
			t.Fatalf("control: the gate refused the destructive command: %+v", resp.Error)
		}
		start := time.Now()
		refusal(t, opCall(t, "shell_run_command", map[string]any{"command_id": "probe-destructive", "args": []string{"echo", "destructive"}}),
			"tier_denied", "ceiling operator")
		findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"exec"`, `"command_id":"probe-destructive"`,
			`"ceiling":"operator"`, `"outcome":"tier_denied"`)
	})
}

// TestOperatorToolsApprovalGuard: with operator in SHELL_MCP_APPROVAL_TIERS
// the operator tools refuse with approval_unavailable and nothing reaches
// the gate; read tools still work.
func TestOperatorToolsApprovalGuard(t *testing.T) {
	opsServer(t)
	var log syncedBuffer
	cs, err := startServer(t, &log, "SHELL_MCP_APPROVAL_TIERS=operator,destructive")
	if err != nil {
		t.Fatalf("connect: %v; server log: %s", err, log.String())
	}
	t.Cleanup(func() { _ = cs.Close() })
	p := opsWork + "/guarded.txt"
	_ = os.Remove(p)
	// journal() reads from one second before start (whole seconds), so
	// let the earlier tests' gate lines fall outside that window.
	time.Sleep(2100 * time.Millisecond)
	start := time.Now()
	for _, name := range operatorToolNames {
		args := map[string]any{"path": p, "content": "x\n"}
		if name != "shell_write_file" {
			args = map[string]any{}
		}
		refusal(t, callOn(t, cs, &log, name, args), "approval_unavailable", "later release")
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("the guarded write happened: %v", err)
	}
	okDataAs(t, callOn(t, cs, &log, "shell_stat_path", map[string]any{"path": opsWork}), opsWho)
	// The stat reached the gate; nothing before it did.
	findJournal(t, "shell-mcp-gate", start, `"principal":"`+opsWho+`"`, `"op":"stat"`)
	for _, j := range journal(t, "shell-mcp-gate", start) {
		if strings.Contains(j.Message, `"principal":"`+opsWho+`"`) && !strings.Contains(j.Message, `"op":"stat"`) {
			t.Fatalf("a guarded call reached the gate: %q", j.Message)
		}
	}
}

// gateExecAt sends one exec request straight to the gate with key, at the
// given ceiling.
func gateExecAt(t *testing.T, key, ceiling, id string, args []string) *protocol.Response {
	t.Helper()
	c := sshClient(t, []config.HostKey{hostPin(t, "ssh_host_ed25519_key.pub")}, clientKey(t, key))
	resp, err := gateclient.New(gateclient.Options{}).Call(t.Context(), c, protocol.OpExec, ceiling,
		map[string]any{"command_id": id, "args": args}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
