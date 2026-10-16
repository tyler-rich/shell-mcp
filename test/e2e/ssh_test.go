//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// The server's SSH client and gate client against the machine's real
// OpenSSH (the dedicated test sshd from setup.sh, 127.0.0.1:2222) and the
// installed gate as the keys' forced command.

const (
	sshdDir  = "/etc/shell-mcp-e2e-sshd"
	sshdHost = "127.0.0.1"
	sshdPort = 2222
)

func needSSHD(t *testing.T) {
	t.Helper()
	_, err := os.Stat(filepath.Join(sshdDir, "sshd_config"))
	ok := err == nil
	if ok {
		c, derr := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", net.JoinHostPort(sshdHost, strconv.Itoa(sshdPort)))
		if ok = derr == nil; ok {
			_ = c.Close()
		}
	}
	need(t, ok, "the test sshd from setup.sh is not running (needs /usr/sbin/sshd)")
}

// hostPin is the typed pin of one of the test sshd's host keys.
func hostPin(t *testing.T, name string) config.HostKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sshdDir, name)) //nolint:gosec // G304: setup.sh's fixed fixture
	if err != nil {
		t.Fatal(err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return config.HostKey{Type: pk.Type(), Fingerprint: ssh.FingerprintSHA256(pk)}
}

func clientKey(t *testing.T, name string) *config.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(bin(), name)) //nolint:gosec // G304: setup.sh's fixed fixture
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return config.PrivateKeyFromSigner(s)
}

func sshClient(t *testing.T, pins []config.HostKey, key *config.PrivateKey) *sshx.Client {
	t.Helper()
	c, err := sshx.New(&config.Target{Name: "app-host", Host: sshdHost, Port: sshdPort, User: "svc-shell", HostKeys: pins, Key: key},
		sshx.Options{ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func hello(t *testing.T, c *sshx.Client) (*protocol.Response, error) {
	t.Helper()
	return gateclient.New(gateclient.Options{}).Call(t.Context(), c, protocol.OpHello, nil, 20*time.Second)
}

func wantSSHCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *envelope.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

// TestServerSSHReachesGate: a key with restrict,from=,command= reaches the
// installed gate. The sshd also has an ECDSA host key; each pinned type is
// the one negotiated and verified.
func TestServerSSHReachesGate(t *testing.T) {
	needSSHD(t)
	for _, hk := range []string{"ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub"} {
		t.Run(hk, func(t *testing.T) {
			pin := hostPin(t, hk)
			c := sshClient(t, []config.HostKey{pin}, clientKey(t, "e2e-client-key"))
			resp, err := hello(t, c)
			if err != nil {
				t.Fatal(err)
			}
			var d struct {
				Protocol  int    `json:"protocol"`
				Principal string `json:"principal"`
			}
			if !resp.OK || json.Unmarshal(resp.Data, &d) != nil || d.Protocol != protocol.Version || d.Principal != "e2e-ssh" {
				t.Fatalf("hello: %+v %s", resp, resp.Data)
			}
			if c.VerifiedHostKey() != pin.String() {
				t.Fatalf("verified %q, want %q", c.VerifiedHostKey(), pin.String())
			}
		})
	}
}

// TestServerSSHWrongPinRefused: the real sshd's key does not match the pin.
func TestServerSSHWrongPinRefused(t *testing.T) {
	needSSHD(t)
	wrong := hostPin(t, "ssh_host_ed25519_key.pub")
	wrong.Fingerprint = "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := hello(t, sshClient(t, []config.HostKey{wrong}, clientKey(t, "e2e-client-key")))
	wantSSHCode(t, err, envelope.CodeHostKeyMismatch)
	// A pin of a type the target does not offer.
	rsa := config.HostKey{Type: "ssh-rsa", Fingerprint: wrong.Fingerprint}
	_, err = hello(t, sshClient(t, []config.HostKey{rsa}, clientKey(t, "e2e-client-key")))
	wantSSHCode(t, err, envelope.CodeHostKeyMismatch)
}

// TestServerSSHKeyOutsideFromRefused: a key restricted to from="192.0.2.1"
// is refused when used from 127.0.0.1 (the control is the key above).
func TestServerSSHKeyOutsideFromRefused(t *testing.T) {
	needSSHD(t)
	_, err := hello(t, sshClient(t, []config.HostKey{hostPin(t, "ssh_host_ed25519_key.pub")}, clientKey(t, "e2e-client-key-other-from")))
	wantSSHCode(t, err, envelope.CodeAuthFailedSSH)
}

// TestServerSSHRestrictRefusesPTY: independently of the client, sshd
// refuses a PTY for the restricted key, and runs only the forced command.
func TestServerSSHRestrictRefusesPTY(t *testing.T) {
	needSSHD(t)
	pin := hostPin(t, "ssh_host_ed25519_key.pub")
	signer := clientKey(t, "e2e-client-key").Signer()
	cfg := &ssh.ClientConfig{User: "svc-shell", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: 5 * time.Second,
		HostKeyAlgorithms: []string{pin.Type},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if ssh.FingerprintSHA256(k) != pin.Fingerprint {
				return errors.New("host key not pinned")
			}
			return nil
		}}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(sshdHost, strconv.Itoa(sshdPort)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	s, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("sshd granted a PTY to the restricted key")
	}
	// Any other command still runs only the gate, which refuses it.
	out, _ := s.Output("id")
	var r struct {
		OK    bool `json:"ok"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &r) != nil || r.OK || r.Error == nil {
		t.Fatalf("a requested command ran something other than the gate: %q", out)
	}
}

// TestServerCheckCLI: `shell-mcp check` against the real sshd and gate.
func TestServerCheckCLI(t *testing.T) {
	needSSHD(t)
	pin := hostPin(t, "ssh_host_ed25519_key.pub")
	env := []string{
		"PATH=/usr/bin:/bin",
		"SHELL_MCP_TOKEN=e2e-token-0123456789abcdefghijklmnopqrstuvwxyzABCD",
		"SHELL_MCP_TARGET_NAME=app-host",
		"SHELL_MCP_TARGET_HOST=" + sshdHost,
		"SHELL_MCP_TARGET_PORT=" + strconv.Itoa(sshdPort),
		"SHELL_MCP_TARGET_USER=svc-shell",
		"SHELL_MCP_SSH_KEY_FILE=" + filepath.Join(bin(), "e2e-client-key"),
	}
	check := func(pins string) (int, map[string]any) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(bin(), "shell-mcp"), "check") //nolint:gosec // G204: the binary under test
		cmd.Env = append(append([]string{}, env...), "SHELL_MCP_TARGET_HOST_KEYS="+pins)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("check did not run: %v", err)
		}
		var m map[string]any
		if json.Unmarshal(out, &m) != nil {
			t.Fatalf("check output %q stderr %q", out, stderr.String())
		}
		return code, m
	}
	code, m := check(pin.String())
	targets, _ := m["targets"].([]any)
	if code != 0 || m["ok"] != true || len(targets) != 1 {
		t.Fatalf("check exit %d: %v", code, m)
	}
	tg, _ := targets[0].(map[string]any)
	gate, _ := tg["gate"].(map[string]any)
	if tg["host_key_verified"] != pin.String() || gate["principal"] != "e2e-ssh" || gate["policy_sha256"] == "" {
		t.Fatalf("target report %v", tg)
	}
	code, m = check(pin.Type + " SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	targets, _ = m["targets"].([]any)
	tg, _ = targets[0].(map[string]any)
	e, _ := tg["error"].(map[string]any)
	if code == 0 || e["code"] != envelope.CodeHostKeyMismatch {
		t.Fatalf("wrong pin: exit %d %v", code, m)
	}
}
