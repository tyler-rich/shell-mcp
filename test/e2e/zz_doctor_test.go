//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDoctorOnRunner: `shell-mcp doctor` (handoff §4.E) against the runner's
// real sshd, gate and both helper units, and a real `shell-mcp serve` with
// its approval page, healthy and then with each component broken in turn:
// a wrong host key, the gate missing, the core socket stopped, the network's
// gateway trusted, the approval page unreachable, the token missing. Each
// break is undone in a cleanup registered before it, so it runs on failure
// too, and a last healthy run shows everything was put back. It runs after
// every other test but the install ones (zz_init, zz_install), which change
// the units.
func TestDoctorOnRunner(t *testing.T) {
	needSSHD(t)
	pin := hostPin(t, "ssh_host_ed25519_key.pub")
	h := newHuman(t, singleApprover)
	mcpPort, approvalPort := freePort(t), freePort(t)
	env := []string{
		"PATH=/usr/bin:/bin",
		"SHELL_MCP_TOKEN=e2e-token-0123456789abcdefghijklmnopqrstuvwxyzABCD",
		"SHELL_MCP_PORT=" + strconv.Itoa(mcpPort),
		"SHELL_MCP_TRUSTED_PROXIES=127.0.0.1",
		"SHELL_MCP_TARGET_NAME=app-host",
		"SHELL_MCP_TARGET_HOST=" + sshdHost,
		"SHELL_MCP_TARGET_PORT=" + strconv.Itoa(sshdPort),
		"SHELL_MCP_TARGET_USER=svc-shell",
		"SHELL_MCP_TARGET_HOST_KEYS=" + pin.String(),
		"SHELL_MCP_SSH_KEY_FILE=" + filepath.Join(bin(), "e2e-client-key"),
		"SHELL_MCP_APPROVAL_METHOD=web",
		"SHELL_MCP_APPROVAL_PORT=" + strconv.Itoa(approvalPort),
		"SHELL_MCP_APPROVAL_PUBLIC_URL=http://127.0.0.1:" + strconv.Itoa(approvalPort),
		"SHELL_MCP_APPROVERS_FILE=" + h.file(t),
	}
	stop := startHTTPServer(t, env, mcpPort, approvalPort)
	mcpURL := "http://127.0.0.1:" + strconv.Itoa(mcpPort) + "/mcp"

	healthy := func(when string) {
		t.Helper()
		code, rep, out := doctor(t, env, "--mcp-url", mcpURL)
		if code != 0 || !rep.OK {
			t.Fatalf("%s: doctor exit %d:\n%s", when, code, out)
		}
		rep.want(t, "configuration", "ok")
		rep.want(t, "target app-host", "ok", pin.String(), "principal e2e-ssh", "sandbox required", "applied true")
		rep.want(t, "helper app-host core", "ok", "unit core")
		rep.want(t, "helper app-host broad", "ok", "priv_pkg_update_index_preview", "unit broad")
		rep.want(t, "trusted proxy 127.0.0.1", "ok")
		rep.want(t, "approval page", "ok", "answered 200 from the approval page")
		rep.want(t, "mcp endpoint", "ok", "401")
	}
	healthy("healthy")

	t.Run("wrong host key", func(t *testing.T) {
		code, rep, out := doctor(t, withEnv(env, "SHELL_MCP_TARGET_HOST_KEYS", pin.Type+" SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "--mcp-url", mcpURL)
		wantFail(t, code, out)
		rep.want(t, "target app-host", "FAIL", "host_key_mismatch", "shell-mcp-gate host-key", "docs/TARGET-SETUP.md §12.2")
	})

	t.Run("gate missing", func(t *testing.T) {
		aside := gateBin + ".e2e-doctor-aside"
		t.Cleanup(func() {
			if _, err := os.Stat(aside); err == nil {
				if err := os.Rename(aside, gateBin); err != nil {
					t.Errorf("the gate could not be put back: %v", err)
				}
			}
		})
		if err := os.Rename(gateBin, aside); err != nil {
			t.Fatal(err)
		}
		code, rep, out := doctor(t, env, "--mcp-url", mcpURL)
		wantFail(t, code, out)
		rep.want(t, "target app-host", "FAIL", "gate_unavailable", "/usr/local/bin/shell-mcp-gate", "docs/TARGET-SETUP.md §3")
	})

	t.Run("core socket stopped", func(t *testing.T) {
		t.Cleanup(func() {
			if out, err := exec.CommandContext(context.Background(), "systemctl", "start", "shell-mcp-privd.socket").CombinedOutput(); err != nil {
				t.Errorf("the socket could not be started again: %v: %s", err, out)
			}
		})
		if out, err := exec.CommandContext(t.Context(), "systemctl", "stop", "shell-mcp-privd.socket").CombinedOutput(); err != nil {
			t.Fatalf("systemctl stop: %v: %s", err, out)
		}
		code, rep, out := doctor(t, env, "--mcp-url", mcpURL)
		wantFail(t, code, out)
		rep.want(t, "helper app-host core", "FAIL", "helper_unavailable", "shell-mcp-privd install", "docs/TARGET-SETUP.md §12.3")
		rep.want(t, "helper app-host broad", "NOTE", "not probed")
	})

	t.Run("gateway trusted", func(t *testing.T) {
		gw := defaultGateway(t)
		code, rep, out := doctor(t, withEnv(env, "SHELL_MCP_TRUSTED_PROXIES", gw.String()), "--mcp-url", mcpURL)
		wantFail(t, code, out)
		rep.want(t, "trusted proxy "+gw.String(), "FAIL", "holds "+gw.String()+", a gateway", "docs/CLIENTS.md §1")
	})

	t.Run("token missing", func(t *testing.T) {
		e := withEnv(withEnv(env, "SHELL_MCP_TOKEN", ""), "SHELL_MCP_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
		code, rep, out := doctor(t, e, "--mcp-url", mcpURL)
		wantFail(t, code, out)
		rep.want(t, "configuration", "FAIL", "SHELL_MCP_TOKEN_FILE", `deploy/README.md, "Secrets"`)
		if len(rep.Rows) != 1 {
			t.Fatalf("rows after a refused configuration:\n%s", out)
		}
	})

	healthy("after every break was undone")

	t.Run("approval page unreachable", func(t *testing.T) {
		stop()
		code, rep, out := doctor(t, env, "--mcp-url", mcpURL)
		wantFail(t, code, out)
		rep.want(t, "approval page", "FAIL", "unreachable", "deploy/caddy/README.md")
		rep.want(t, "mcp endpoint", "FAIL", "unreachable")
	})
}

type doctorReport struct {
	OK   bool `json:"ok"`
	Rows []struct {
		Status    string `json:"status"`
		Component string `json:"component"`
		Detail    string `json:"detail"`
		Fix       string `json:"fix"`
	} `json:"rows"`
}

func (r *doctorReport) want(t *testing.T, component, status string, needles ...string) {
	t.Helper()
	for _, row := range r.Rows {
		if row.Component != component {
			continue
		}
		if row.Status != status {
			t.Fatalf("%s: %s, want %s: %s (fix: %s)", component, row.Status, status, row.Detail, row.Fix)
		}
		for _, n := range needles {
			if !strings.Contains(row.Detail+" "+row.Fix, n) {
				t.Fatalf("%s: %q not in %s (fix: %s)", component, n, row.Detail, row.Fix)
			}
		}
		return
	}
	t.Fatalf("no row %q", component)
}

func doctor(t *testing.T, env []string, args ...string) (code int, rep doctorReport, out string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(bin(), "shell-mcp"), append([]string{"doctor", "--json"}, args...)...) //nolint:gosec // G204: the binary under test
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("doctor did not run: %v", err)
	}
	if jerr := json.Unmarshal(stdout, &rep); jerr != nil {
		t.Fatalf("doctor --json: %v\n%s\nstderr: %s", jerr, stdout, stderr.String())
	}
	return code, rep, string(stdout)
}

func wantFail(t *testing.T, code int, out string) {
	t.Helper()
	if code != 1 {
		t.Fatalf("doctor exit %d, want 1:\n%s", code, out)
	}
}

// withEnv replaces (or, with value "", removes) one variable.
func withEnv(env []string, name, value string) []string {
	out := []string{}
	for _, e := range env {
		if !strings.HasPrefix(e, name+"=") {
			out = append(out, e)
		}
	}
	if value != "" {
		out = append(out, name+"="+value)
	}
	return out
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("not a TCP address")
	}
	return addr.Port
}

// startHTTPServer runs `shell-mcp serve` over HTTP until stop is called (or
// the test ends) and waits until /healthz and the approval page answer.
func startHTTPServer(t *testing.T, env []string, port, approvalPort int) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(bin(), "shell-mcp"), "serve") //nolint:gosec // G204: the binary under test
	cmd.Env = env
	log := &syncedBuffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	stop = func() {
		cancel()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(20 * time.Second)
	for _, u := range []string{"http://127.0.0.1:" + strconv.Itoa(port) + "/healthz", "http://127.0.0.1:" + strconv.Itoa(approvalPort) + "/"} {
		for {
			res, err := http.Get(u) //nolint:noctx,gosec // test: the server just started on loopback
			if err == nil {
				_ = res.Body.Close()
				if res.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not answer: %v; server log: %s", u, err, log.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return stop
}

// defaultGateway is the runner's default IPv4 gateway, read from its own
// routing table (not doctor's parser: a second reading).
func defaultGateway(t *testing.T) netip.Addr {
	t.Helper()
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		raw, err1 := hex.DecodeString(f[2])
		flags, err2 := strconv.ParseUint(f[3], 16, 32)
		if err1 != nil || err2 != nil || len(raw) != 4 || flags&2 == 0 {
			continue
		}
		var a [4]byte
		binary.NativeEndian.PutUint32(a[:], binary.BigEndian.Uint32(raw))
		return netip.AddrFrom4(a)
	}
	need(t, false, "the runner has no default IPv4 gateway")
	return netip.Addr{}
}
