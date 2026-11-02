//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestInitBindFormFromHostDirectory: shell-mcp init's bind form from a real
// host directory (handoff §4.C; the maintainer approved this run for
// e2e-host only, the disposable runner VM). The documented host command
// creates the directory, init runs in the server image built from this
// commit as 65532 with no network, a read-only root and no capabilities,
// and init compose's printed bind form starts the server with that directory
// bind-mounted, so the host directory's owner and mode and the container's
// traversal of it are exercised for real. The compose override changes only
// the image (the local build has no registry digest) and the labels. The
// target is an address where nothing listens: the server starts healthy
// and check loads every secret before it fails closed on the target. The
// directory, the containers and the network are removed in a cleanup that
// runs on failure too, and checked gone.
func TestInitBindFormFromHostDirectory(t *testing.T) {
	image := os.Getenv("E2E_SERVER_IMAGE")
	need(t, image != "", "E2E_SERVER_IMAGE (the server image built from this commit) is not set")
	_, code := runCode(t, "docker", "compose", "version")
	need(t, code == 0, "docker compose is not available")

	parent, err := os.MkdirTemp("", "shell-mcp-e2e-init-")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "secrets")
	proj := "shell-mcp-e2e-init-" + strconv.Itoa(os.Getpid())
	label := "shell-mcp.e2e-init=" + proj
	compose := filepath.Join(parent, "docker-compose.yml")
	override := filepath.Join(parent, "override.yml")
	dc := []string{"compose", "-p", proj, "--project-directory", parent, "-f", compose, "-f", override}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", append(dc, "down", "--timeout", "5")...).Run()                                              //nolint:gosec // G204: fixed test command
		if ids, _ := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "label="+label).Output(); len(bytes.TrimSpace(ids)) > 0 { //nolint:gosec // G204: fixed test command
			_ = exec.CommandContext(ctx, "docker", append([]string{"rm", "-f"}, strings.Fields(string(ids))...)...).Run() //nolint:gosec // G204: ids this test started
		}
		if nets, _ := exec.CommandContext(ctx, "docker", "network", "ls", "-q", "--filter", "label="+label).Output(); len(bytes.TrimSpace(nets)) > 0 { //nolint:gosec // G204: fixed test command
			_ = exec.CommandContext(ctx, "docker", append([]string{"network", "rm"}, strings.Fields(string(nets))...)...).Run() //nolint:gosec // G204: networks this test created
		}
		if rerr := os.RemoveAll(parent); rerr != nil {
			t.Errorf("cleanup: %v", rerr)
		}
		if exists(parent) {
			t.Errorf("cleanup: %s remains", parent)
		}
		for _, args := range [][]string{{"ps", "-aq", "--filter", "label=" + label}, {"network", "ls", "-q", "--filter", "label=" + label}} {
			if out, _ := exec.CommandContext(ctx, "docker", args...).Output(); len(bytes.TrimSpace(out)) > 0 { //nolint:gosec // G204: fixed test command
				t.Errorf("cleanup: docker %v still lists %s", args, out)
			}
		}
	})

	// The documented host command, then init in the image.
	if out, icode := runCode(t, "install", "-d", "-o", "65532", "-g", "65532", "-m", "0700", dir); icode != 0 {
		t.Fatalf("install -d: %s", out)
	}
	hardened := []string{"run", "--rm", "--label", label, "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true"}
	if out, icode := runCode(t, "docker", append(hardened, "-v", dir+":/secrets", image, "init", "--dir", "/secrets")...); icode != 0 {
		t.Fatalf("init in the image: exit %d\n%s", icode, out)
	}
	for name, mode := range map[string]fs.FileMode{"": fs.ModeDir | 0o700, "mcp_token": 0o600, "ssh_key": 0o600, "ssh_key.pub": 0o644} {
		p := filepath.Join(dir, name)
		fi, lerr := os.Lstat(p)
		if lerr != nil {
			t.Fatal(lerr)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if fi.Mode() != mode || st.Uid != 65532 || st.Gid != 65532 {
			t.Errorf("%s on the host: %v %d:%d, want %v 65532:65532", p, fi.Mode(), st.Uid, st.Gid, mode)
		}
	}
	pubLine, err := os.ReadFile(filepath.Join(dir, "ssh_key.pub")) //nolint:gosec // G304: the directory this test made
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}

	// init compose's bind form, and the test-only override.
	sub := fmt.Sprintf("10.%d.%d", 200+rand.IntN(50), rand.IntN(256)) //nolint:gosec // G404: a test subnet, not a secret
	printed, code := runStdout(t, "docker", append(hardened, image, "init", "compose", "--form", "bind", "--dir", dir,
		"--image", "ghcr.io/tyler-rich/shell-mcp:0.0.0-e2e@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"--host-key", "ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--target-name", "app-host", "--target-host", sub+".20",
		"--mcp-host", "mcp.example.test", "--subnet", sub+".0/24", "--server-addr", sub+".10", "--proxy-addr", sub+".5")...)
	if code != 0 {
		t.Fatalf("init compose: exit %d", code)
	}
	if err = os.WriteFile(compose, printed, 0o600); err != nil { //nolint:gosec // G703: a file in the directory os.MkdirTemp made
		t.Fatal(err)
	}
	k, v, _ := strings.Cut(label, "=")
	ov := fmt.Sprintf("services:\n  shell-mcp:\n    image: %s\n    labels: { %q: %q }\nnetworks:\n  front:\n    labels: { %q: %q }\n", image, k, v, k, v)
	if err = os.WriteFile(override, []byte(ov), 0o600); err != nil { //nolint:gosec // G703: a file in the directory os.MkdirTemp made
		t.Fatal(err)
	}
	merged, code := runCode(t, "docker", append(dc, "config")...)
	if code != 0 || !strings.Contains(merged, "source: "+dir) || !strings.Contains(merged, "target: /run/secrets") || strings.Contains(merged, "secrets:\n") {
		t.Fatalf("the merged compose file does not bind-mount %s on /run/secrets (exit %d):\n%s", dir, code, merged)
	}

	if out, ucode := runCode(t, "docker", append(dc, "up", "-d", "--wait", "--wait-timeout", "120")...); ucode != 0 {
		logs, _ := runCode(t, "docker", append(dc, "logs", "--no-color")...)
		t.Fatalf("the server does not start from the host directory: exit %d\n%s\n%s", ucode, out, logs)
	}
	report, _ := runStdout(t, "docker", append(dc, "exec", "-T", "shell-mcp", "/shell-mcp", "check")...)
	var r struct {
		OK     bool `json:"ok"`
		Config struct {
			TokenLength int      `json:"token_length"`
			Warnings    []string `json:"warnings"`
			Targets     []struct {
				KeyFingerprint string `json:"key_fingerprint"`
			} `json:"targets"`
		} `json:"config"`
		Targets []struct {
			Error *struct {
				Code string `json:"code"`
			} `json:"error"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		t.Fatalf("check printed no report (the configuration did not load?): %v\n%s", err, report)
	}
	if r.Config.TokenLength != 43 || len(r.Config.Warnings) != 0 || len(r.Config.Targets) != 1 ||
		r.Config.Targets[0].KeyFingerprint != ssh.FingerprintSHA256(pub) {
		t.Errorf("the server did not load init's token and key through the host directory: %+v", r.Config)
	}
	if r.OK || len(r.Targets) != 1 || r.Targets[0].Error == nil || r.Targets[0].Error.Code == "" {
		t.Errorf("check against an address where nothing listens should fail closed on the target: %s", report)
	}
}

// runStdout runs a command and returns its stdout alone and its exit code.
func runStdout(t *testing.T, name string, args ...string) (stdout []byte, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: fixed test commands
	cmd.Stdout, cmd.Stderr = &out, &stderr
	var ee *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &ee) {
		t.Fatalf("%s %v: %v\n%s", name, args, err, stderr.Bytes())
	}
	return out.Bytes(), cmd.ProcessState.ExitCode()
}
