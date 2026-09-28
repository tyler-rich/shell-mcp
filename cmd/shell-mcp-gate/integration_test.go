//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// requireABIEnv: CI sets it to the runner's Landlock ABI so sandbox tests
// that need a newer kernel than the local containers fail instead of skip.
const requireABIEnv = "SHELL_MCP_REQUIRE_LANDLOCK_ABI"

func needABI(t *testing.T, n int) {
	t.Helper()
	k := sandbox.KernelABI()
	if k >= n {
		return
	}
	if req, _ := strconv.Atoi(os.Getenv(requireABIEnv)); req >= n {
		t.Fatalf("%s=%d but the kernel's Landlock ABI is %d; this test needs ABI %d", requireABIEnv, req, k, n)
	}
	where := "runs in CI (ABI 7)"
	if n > 7 {
		where = "no current runner has it (CI has ABI 7)"
	}
	t.Skipf("needs Landlock ABI %d (kernel has %d); %s", n, k, where)
}

var (
	dirOnce, buildOnce sync.Once
	buildDir           string
	dirErr             error
	harnessPath        string
)

// harness returns the CGO_ENABLED=0 harness binary, built once into a
// directory whose parent chain passes the gate's own executable checks.
func harness(t *testing.T) string {
	t.Helper()
	dirOnce.Do(func() {
		d, err := os.MkdirTemp("", "gate-harness")
		if err == nil {
			buildDir, err = filepath.EvalSymlinks(d)
		}
		dirErr = err
	})
	if dirErr != nil {
		t.Fatal(dirErr)
	}
	gatetest.RequireSecure(t, buildDir)
	buildOnce.Do(func() {
		harnessPath = gatetest.BuildTest(t, "cmd/shell-mcp-gate", buildDir, "shell-mcp-gate", nil)
	})
	if harnessPath == "" {
		t.Fatal("harness build failed earlier")
	}
	return harnessPath
}

// gate is an invented target layout under a secure temp dir.
type gate struct {
	t                                                  *testing.T
	dir, read, write, secrets, bin, home, outside, pol string
	probe                                              string
	env                                                []string
}

const integrationPolicy = `version: 1
max_tier: {TIER}
sandbox:
  landlock: {MODE}
  system_read_exec: [{BIN}]
{PORTS}limits:
  max_output_bytes: 65536
paths:
  read: [{R}]
  write: [{W}]
  deny: ["{R}/secrets/**"]
commands:
  - id: probe
    path: {BIN}/probe
    tier: read
    templates:
      - ["read-outside"]
      - ["nnp"]
      - ["mptcp"]
      - ["echo", "{regex:^[a-z0-9 -]+$}"]
      - ["echo", "{path:read}"]
      - ["connect", "{int:1-65535}"]
      - ["bind"]
      - ["signal", "{int:1-4194304}"]
      - ["fork-sleep", "{enum:60s}"]
      - ["flood", "{int:1-100000000}"]
`

// defaultMode is required where the kernel can enforce it, else best-effort.
func defaultMode() string {
	if sandbox.KernelABI() >= sandbox.RequiredMinABI {
		return "required"
	}
	return "best-effort"
}

func newGate(t *testing.T) *gate {
	t.Helper()
	harness(t)
	d := gatetest.SecureDir(t)
	g := &gate{t: t, dir: d,
		read: filepath.Join(d, "srv", "app"), write: filepath.Join(d, "srv", "app", "config"),
		secrets: filepath.Join(d, "srv", "app", "secrets"), bin: filepath.Join(d, "bin"),
		home: filepath.Join(d, "home"), outside: filepath.Join(d, "outside"), pol: filepath.Join(d, "etc", "policy.yaml")}
	for _, p := range []string{g.write, g.secrets, g.bin, g.home, g.outside} {
		gatetest.Mkdir(t, p, 0o755)
	}
	gatetest.WriteFile(t, filepath.Join(g.read, "hello.txt"), "hello\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.secrets, "token"), "TOPSECRET", 0o644)
	gatetest.WriteFile(t, filepath.Join(g.outside, "secret.txt"), "OUTSIDE", 0o644)
	g.probe = gatetest.BuildProbe(t, g.bin, "probe", filepath.Join(g.outside, "secret.txt"))
	g.policy("destructive", defaultMode(), "")
	g.env = []string{harnessEnv + "=1", "HARNESS_UID=60123", "HARNESS_GIDS=60123,60124",
		"HARNESS_GROUPS=60123=svc-shell,60124=svc-shell-priv,101=systemd-journal,999=docker", "HARNESS_HOME=" + g.home}
	return g
}

func (g *gate) policy(tier, mode, ports string) {
	y := strings.NewReplacer("{TIER}", tier, "{MODE}", mode, "{PORTS}", ports,
		"{R}", g.read, "{W}", g.write, "{BIN}", g.bin).Replace(integrationPolicy)
	gatetest.WriteFile(g.t, g.pol, y, 0o644)
}

func (g *gate) rawPolicy(y string) {
	gatetest.WriteFile(g.t, g.pol, strings.NewReplacer("{R}", g.read, "{W}", g.write, "{BIN}", g.bin).Replace(y), 0o644)
}

type resp struct {
	OK       bool            `json:"ok"`
	ID       string          `json:"id"`
	Data     json.RawMessage `json:"data"`
	Warnings []string        `json:"warnings"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// serve runs the harness as `serve --policy … --principal test` with in on stdin.
func (g *gate) serve(in string, extraEnv ...string) *resp {
	g.t.Helper()
	cmd := exec.CommandContext(g.t.Context(), harness(g.t), "serve", "--policy", g.pol, "--principal", "test") //nolint:gosec // G204: the test's own harness
	cmd.Env = append(append([]string{"PATH=/usr/bin:/bin"}, g.env...), extraEnv...)
	cmd.Stdin = strings.NewReader(in)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		g.t.Fatalf("gate exited %v; stderr %q; stdout %q", err, stderr.String(), out)
	}
	var r resp
	if json.Unmarshal(out, &r) != nil || strings.Count(string(out), "\n") != 1 {
		g.t.Fatalf("gate output is not one JSON line: %q (stderr %q)", out, stderr.String())
	}
	if stderr.Len() != 0 {
		g.t.Fatalf("gate wrote to stderr: %q", stderr.String())
	}
	return &r
}

func (g *gate) call(op string, args any, extraEnv ...string) *resp {
	g.t.Helper()
	a, _ := json.Marshal(args)
	return g.serve(fmt.Sprintf(`{"v":1,"id":"it-1","op":%q,"args":%s,"timeout_ms":10000}`+"\n", op, a), extraEnv...)
}

func (g *gate) want(r *resp, code string) *resp {
	g.t.Helper()
	if code == "" {
		if !r.OK {
			g.t.Fatalf("want ok, got %+v", r.Error)
		}
		return r
	}
	if r.OK || r.Error == nil || r.Error.Code != code {
		g.t.Fatalf("want %s, got ok=%v err=%+v data=%s", code, r.OK, r.Error, r.Data)
	}
	return r
}

type execOut struct {
	ExitCode        *int    `json:"exit_code"`
	Signal          *string `json:"signal"`
	TimedOut        bool    `json:"timed_out"`
	Stdout          string  `json:"stdout"`
	StdoutTruncated bool    `json:"stdout_truncated"`
}

func (g *gate) exec(args []string, extra map[string]any) execOut {
	g.t.Helper()
	a := map[string]any{"command_id": "probe", "args": args}
	for k, v := range extra {
		a[k] = v
	}
	r := g.want(g.call("exec", a), "")
	var d execOut
	if err := json.Unmarshal(r.Data, &d); err != nil {
		g.t.Fatal(err)
	}
	return d
}

type m = map[string]any

func TestIntegrationReadsAndPaths(t *testing.T) {
	g := newGate(t)
	var rd struct {
		Content string `json:"content"`
	}
	r := g.want(g.call("read_file", m{"path": filepath.Join(g.read, "hello.txt")}), "")
	if json.Unmarshal(r.Data, &rd) != nil || rd.Content != "hello\n" || r.ID != "it-1" {
		t.Fatalf("read %+v %s", r, r.Data)
	}
	g.want(g.call("read_file", m{"path": g.read + "/../outside/secret.txt"}), "bad_request")
	// Symlink inside a root pointing outside it; to a denied file inside the root; final component.
	if err := os.Symlink(g.outside, filepath.Join(g.read, "escape")); err != nil {
		t.Fatal(err)
	}
	g.want(g.call("read_file", m{"path": filepath.Join(g.read, "escape", "secret.txt")}), "path_denied")
	if err := os.Symlink("secrets/token", filepath.Join(g.read, "tok")); err != nil {
		t.Fatal(err)
	}
	g.want(g.call("read_file", m{"path": filepath.Join(g.read, "tok")}), "path_denied")
	if err := os.Symlink("hello.txt", filepath.Join(g.read, "hl")); err != nil {
		t.Fatal(err)
	}
	g.want(g.call("read_file", m{"path": filepath.Join(g.read, "hl")}), "path_denied")
	if err := os.Symlink("secrets", filepath.Join(g.read, "sdir")); err != nil {
		t.Fatal(err)
	}
	g.want(g.call("read_file", m{"path": filepath.Join(g.read, "sdir", "token")}), "path_denied")
}

func TestIntegrationWrites(t *testing.T) {
	g := newGate(t)
	b64 := base64.StdEncoding.EncodeToString([]byte("data"))
	g.want(g.call("write_file", m{"path": filepath.Join(g.write, "ok.txt"), "content_b64": b64}), "")
	g.want(g.call("write_file", m{"path": filepath.Join(g.read, "x.txt"), "content_b64": b64}), "path_denied")
	g.want(g.call("write_file", m{"path": filepath.Join(g.outside, "x.txt"), "content_b64": b64}), "path_denied")
	gatetest.Mkdir(t, filepath.Join(g.write, ".ssh"), 0o755)
	g.want(g.call("write_file", m{"path": filepath.Join(g.write, ".ssh", "authorized_keys"), "content_b64": b64}), "path_denied")
	g.want(g.call("write_file", m{"path": filepath.Join(g.write, "s.bin"), "content_b64": b64, "mode": "4755"}), "policy_denied")
	g.want(g.call("chmod", m{"path": filepath.Join(g.write, "ok.txt"), "mode": "2755"}), "policy_denied")
	g.want(g.call("write_file", m{"path": filepath.Join(g.write, "v.txt"), "content_b64": b64}, "HARNESS_FAULT=readback"), "verify_failed")
}

// TestIntegrationSwapRace swaps a directory for a symlink to outside the
// root while gate processes read and write through it.
func TestIntegrationSwapRace(t *testing.T) {
	g := newGate(t)
	sub, stash, link := filepath.Join(g.write, "sub"), filepath.Join(g.write, "sub.real"), filepath.Join(g.write, "sub.link")
	gatetest.WriteFile(t, filepath.Join(sub, "f"), "INSIDE", 0o644)
	if err := os.Symlink(g.outside, link); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = os.Rename(sub, stash)
			_ = os.Rename(link, sub)
			time.Sleep(time.Millisecond)
			_ = os.Rename(sub, link)
			_ = os.Rename(stash, sub)
			time.Sleep(time.Millisecond)
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	n, oks := 0, 0
	for time.Now().Before(deadline) {
		r := g.call("read_file", m{"path": filepath.Join(sub, "f")})
		if r.OK {
			oks++
		}
		if r.OK && strings.Contains(string(r.Data), "OUTSIDE") {
			stop.Store(true)
			wg.Wait()
			t.Fatal("gate read outside the root")
		}
		g.call("write_file", m{"path": filepath.Join(sub, "w"), "content_b64": "eA=="})
		n++
	}
	stop.Store(true)
	wg.Wait()
	ents, _ := os.ReadDir(g.outside)
	if len(ents) != 1 {
		t.Fatalf("outside directory was written: %v", ents)
	}
	t.Logf("%d request pairs under the swap, %d successful reads", n, oks)
	if oks == 0 {
		t.Fatal("race test is vacuous: no read succeeded")
	}
}

func TestIntegrationTemplates(t *testing.T) {
	g := newGate(t)
	if d := g.exec([]string{"echo", "hi there"}, nil); d.Stdout != "hi there\n" {
		t.Fatalf("echo %+v", d)
	}
	g.want(g.call("exec", m{"command_id": "probe", "args": []string{"echo", "UPPER"}}), "template_mismatch")
	g.want(g.call("exec", m{"command_id": "probe", "args": []string{"echo", "-x"}}), "template_mismatch")
	g.want(g.call("exec", m{"command_id": "probe", "args": []string{"echo", "--output=/etc/x"}}), "template_mismatch")
	g.want(g.call("exec", m{"command_id": "probe", "args": []string{"echo", filepath.Join(g.secrets, "token")}}), "path_denied")
	g.want(g.call("exec", m{"command_id": "probe", "args": []string{"echo", "a", "b"}}), "template_mismatch")
}

func TestIntegrationPolicyRefusals(t *testing.T) {
	g := newGate(t)
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh to point a link at")
	}
	if err := os.Symlink(shell, filepath.Join(g.bin, "ls")); err != nil {
		t.Fatal(err)
	}
	g.rawPolicy("version: 1\nmax_tier: read\ncommands:\n  - id: lister\n    path: {BIN}/ls\n    tier: read\n    templates: [[\"-l\"]]\n")
	g.want(g.call("hello", m{}), "install_insecure")
	g.rawPolicy("version: 1\nmax_tier: read\nsudo: true\n")
	g.want(g.call("hello", m{}), "install_insecure")
	g.rawPolicy("version: 1\nmax_tier: operator\nprivileged:\n  enabled: true\n  socket: /tmp/privd.sock\n")
	g.want(g.call("hello", m{}), "install_insecure")
}

func TestIntegrationTiersAndDecoding(t *testing.T) {
	g := newGate(t)
	g.policy("read", defaultMode(), "")
	g.want(g.call("write_file", m{"path": filepath.Join(g.write, "x"), "content_b64": ""}), "tier_denied")
	g.want(g.call("delete", m{"path": filepath.Join(g.write, "x")}), "tier_denied")
	g.want(g.call("priv_read_file", m{"path": "/etc/example-app/x"}), "privileged_disabled")
	g.want(g.serve(`{"v":1,"id":"a","op":"hello"}`+strings.Repeat(" ", protocol.MaxRequestBytes)+"\n"), "too_large")
	g.want(g.serve(`{"v":1,"id":"a","op":"hello","op":"write_file"}`+"\n"), "bad_request")
	g.want(g.serve(`{"v":1,"id":"a","op":"hello","unknown":true}`+"\n"), "bad_request")
	g.want(g.serve(`{"v":1,"id":"a","op":"sysinfo"}`+"\n"), "unknown_op")
}

func TestIntegrationIdentity(t *testing.T) {
	g := newGate(t)
	g.want(g.call("hello", m{}, "HARNESS_UID="+strconv.Itoa(os.Getuid())), "install_insecure") // the trusted owner
	g.want(g.call("hello", m{}, "HARNESS_UID=0"), "install_insecure")
	g.want(g.call("hello", m{}, "HARNESS_GIDS=60123,999"), "install_insecure") // docker
	g.want(g.call("hello", m{}, "HARNESS_GIDS=60123,60124,101"), "")           // helper socket group, systemd-journal
	g.want(g.call("hello", m{}, "SSH_ORIGINAL_COMMAND=id"), "install_insecure")
	g.want(g.call("hello", m{}, "SSH_ORIGINAL_COMMAND="+protocol.Hello), "")
}

func grandchildDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return
		}
		s := string(b)
		if i := strings.LastIndexByte(s, ')'); i >= 0 && len(s) > i+2 && (s[i+2] == 'Z' || s[i+2] == 'X') {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("grandchild %d survived the gate", pid)
}

func TestIntegrationExecLimits(t *testing.T) {
	g := newGate(t)
	r := g.want(g.serve(`{"v":1,"id":"a","op":"exec","args":{"command_id":"probe","args":["fork-sleep","60s"]},"timeout_ms":800}`+"\n"), "")
	var d execOut
	if json.Unmarshal(r.Data, &d) != nil || !d.TimedOut || d.Signal == nil {
		t.Fatalf("timeout %s", r.Data)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(d.Stdout))
	if err != nil {
		t.Fatalf("grandchild pid %q", d.Stdout)
	}
	grandchildDead(t, pid)
	d = g.exec([]string{"flood", "5000000"}, m{"max_output_bytes": 1000})
	if !d.StdoutTruncated || len(d.Stdout) > 1000 {
		t.Fatalf("output cap: truncated=%v len=%d", d.StdoutTruncated, len(d.Stdout))
	}
}

// Sandbox, filesystem: runs locally (ABI 3) and in CI (ABI 7).
func TestIntegrationSandboxFilesystem(t *testing.T) {
	needABI(t, 1)
	g := newGate(t)
	// Without the kernel sandbox the probe would print READ:OUTSIDE; the
	// gate's userspace checks never see this hard-coded path.
	if d := g.exec([]string{"read-outside"}, nil); strings.TrimSpace(d.Stdout) != "EACCES" {
		t.Fatalf("read outside every root: %q", d.Stdout)
	}
	if d := g.exec([]string{"nnp"}, nil); strings.TrimSpace(d.Stdout) != "NoNewPrivs: 1" {
		t.Fatalf("child no_new_privs: %q", d.Stdout)
	}
	// Landlock cannot govern MPTCP; the seccomp filter makes it unavailable
	// to every child.
	if d := g.exec([]string{"mptcp"}, nil); strings.TrimSpace(d.Stdout) != "EPROTONOSUPPORT" {
		t.Fatalf("child MPTCP socket: %q", d.Stdout)
	}
}

// Sandbox, refusal and degradation: runs on kernels below ABI 4 (local).
func TestIntegrationSandboxRefusalAndDegradation(t *testing.T) {
	k := sandbox.KernelABI()
	if k >= sandbox.RequiredMinABI || k < 1 {
		t.Skipf("needs a kernel with Landlock below ABI %d (this one has %d); runs locally on ABI 3", sandbox.RequiredMinABI, k)
	}
	g := newGate(t)
	g.policy("read", "required", "")
	g.want(g.call("hello", m{}), "sandbox_unavailable")
	g.policy("read", "best-effort", "")
	r := g.want(g.call("hello", m{}), "")
	var h struct {
		Sandbox sandbox.Report `json:"sandbox"`
	}
	if json.Unmarshal(r.Data, &h) != nil {
		t.Fatal(string(r.Data))
	}
	want := "net,unix_socket,scope"
	if k < sandbox.ABIFSFull {
		want = "fs," + want
	}
	if h.Sandbox.MPTCP != "blocked by seccomp" {
		t.Fatalf("hello mptcp %q", h.Sandbox.MPTCP)
	}
	if got := strings.Join(h.Sandbox.NotEnforced, ","); got != want || h.Sandbox.RequiredMinABI != 4 || !h.Sandbox.Applied {
		t.Fatalf("hello sandbox %+v", h.Sandbox)
	}
}

func listen(t *testing.T) (port int, stop func()) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { _ = l.Close() }
}

// Sandbox, network: CI only (ABI 4+). A declared child is denied a TCP
// connect to an unlisted port and any bind.
func TestIntegrationSandboxNetwork(t *testing.T) {
	needABI(t, sandbox.ABINet)
	g := newGate(t)
	listed, c1 := listen(t)
	defer c1()
	other, c2 := listen(t)
	defer c2()
	g.policy("read", "required", "  tcp_connect_ports: ["+strconv.Itoa(listed)+"]\n")
	if d := g.exec([]string{"connect", strconv.Itoa(other)}, nil); strings.TrimSpace(d.Stdout) != "EACCES" {
		t.Fatalf("unlisted connect: %q", d.Stdout)
	}
	if d := g.exec([]string{"bind"}, nil); strings.TrimSpace(d.Stdout) != "EACCES" {
		t.Fatalf("bind: %q", d.Stdout)
	}
	if d := g.exec([]string{"connect", strconv.Itoa(listed)}, nil); strings.TrimSpace(d.Stdout) != "CONNECTED" {
		t.Fatalf("listed connect: %q", d.Stdout)
	}
}

// Sandbox, scope: CI only (ABI 6+). A declared child cannot signal a
// process outside the gate's domain.
func TestIntegrationSandboxSignalScope(t *testing.T) {
	needABI(t, sandbox.ABIScope)
	g := newGate(t)
	victim := exec.CommandContext(t.Context(), g.probe, "sleep", "30s") //nolint:gosec // G204: test child
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Process.Kill(); _ = victim.Wait() }()
	if d := g.exec([]string{"signal", strconv.Itoa(victim.Process.Pid)}, nil); strings.TrimSpace(d.Stdout) != "EPERM" {
		t.Fatalf("signal outside the domain: %q", d.Stdout)
	}
	if err := syscall.Kill(victim.Process.Pid, 0); err != nil {
		t.Fatalf("victim is gone: %v", err)
	}
}

// TestProductionBinaryRefusesTestOwnedPolicy runs the real gate binary: with
// production trust (root only), a policy owned by the test uid is refused.
func TestProductionBinaryRefusesTestOwnedPolicy(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	g := newGate(t)
	bin := gatetest.Build(t, "cmd/shell-mcp-gate", g.dir, "real-gate", nil)
	cmd := exec.CommandContext(t.Context(), bin, "serve", "--policy", g.pol) //nolint:gosec // G204: the binary this test built
	cmd.Stdin = strings.NewReader(`{"v":1,"id":"a","op":"hello"}` + "\n")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	var r resp
	if err != nil || json.Unmarshal(out, &r) != nil {
		t.Fatalf("real gate: %v %q", err, out)
	}
	g.want(&r, "install_insecure")
}

// TestCGOBuiltGateRefuses: a gate built with cgo refuses to serve.
func TestCGOBuiltGateRefuses(t *testing.T) {
	g := newGate(t)
	d := t.TempDir()
	out, err := exec.CommandContext(t.Context(), "go", "env", "CC").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = exec.LookPath(strings.TrimSpace(string(out))); err != nil {
		if os.Getenv(gatetest.RequireSecureEnv) != "" {
			t.Fatalf("no C compiler (%s) to prove the cgo guard", strings.TrimSpace(string(out)))
		}
		t.Skip("no C compiler")
	}
	dir, _ := filepath.EvalSymlinks(d)
	cgoHarness := gatetest.BuildTest(t, "cmd/shell-mcp-gate", dir, "cgo-gate", []string{"CGO_ENABLED=1"})
	gateCmd := exec.CommandContext(t.Context(), cgoHarness, "serve", "--policy", g.pol, "--principal", "test") //nolint:gosec // G204: built by this test
	gateCmd.Env = append([]string{"PATH=/usr/bin:/bin"}, g.env...)
	gateCmd.Stdin = strings.NewReader(`{"v":1,"id":"a","op":"hello"}` + "\n")
	out, err = gateCmd.Output()
	var r resp
	if err != nil || json.Unmarshal(out, &r) != nil {
		t.Fatalf("cgo gate: %v %q", err, out)
	}
	g.want(&r, "install_insecure")
	if !strings.Contains(r.Error.Message, "cgo") {
		t.Fatalf("message %q", r.Error.Message)
	}
}
