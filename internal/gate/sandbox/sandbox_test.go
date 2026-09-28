//go:build linux

package sandbox_test

import (
	"encoding/json"
	"errors"
	"net"
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

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/sandbox"
)

// RequireABIEnv names the variable CI sets (to the runner's ABI) so that
// sandbox tests needing a newer kernel fail instead of skipping there.
const RequireABIEnv = "SHELL_MCP_REQUIRE_LANDLOCK_ABI"

func needABI(t *testing.T, n int) {
	t.Helper()
	k := sandbox.KernelABI()
	if k >= n {
		return
	}
	if req, _ := strconv.Atoi(os.Getenv(RequireABIEnv)); req >= n {
		t.Fatalf("%s=%d but the kernel's Landlock ABI is %d; this test needs ABI %d", RequireABIEnv, req, k, n)
	}
	where := "runs in CI (ABI 7)"
	if n > 7 {
		where = "no current runner has it (CI has ABI 7)"
	}
	t.Skipf("needs Landlock ABI %d (kernel has %d); %s", n, k, where)
}

func parse(t *testing.T, y string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(y), "/nonexistent/policy.yaml", &policy.LoadOptions{
		Trust: policy.RootTrust(), GateExecutable: "/nonexistent/shell-mcp-gate", ServiceHome: "/nonexistent/home",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestCompute(t *testing.T) {
	p := parse(t, `version: 1
max_tier: operator
sandbox:
  system_read_exec: [/opt/example/bin]
  tcp_connect_ports: [443]
paths:
  read: [/srv/app]
  write: [/srv/app/config]
`)
	r := sandbox.Compute(p)
	if !slices.Equal(r.ReadExec, []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt/example/bin"}) {
		t.Fatalf("read+exec %v", r.ReadExec)
	}
	if !slices.Equal(r.ReadOnly, []string{"/etc", "/proc", "/srv/app"}) {
		t.Fatalf("read %v", r.ReadOnly)
	}
	if !slices.Equal(r.ReadWrite, []string{"/srv/app/config"}) || !slices.Equal(r.TCPConnect, []uint16{443}) {
		t.Fatalf("write %v tcp %v", r.ReadWrite, r.TCPConnect)
	}
	if r.DevNull != "/dev/null" || r.DevURandom != "/dev/urandom" {
		t.Fatalf("dev files %q %q", r.DevNull, r.DevURandom)
	}
	if len(r.UnixSocketDirs) != 0 {
		t.Fatalf("no sockets expected: %v", r.UnixSocketDirs)
	}
	// Journal directories, the D-Bus socket and the helper sockets only when configured.
	p = parse(t, `version: 1
max_tier: operator
journal:
  units: ["*"]
services:
  control:
    units: [example-app.service]
    verbs: [restart]
privileged:
  enabled: true
  socket: /run/shell-mcp/privd.sock
  broad_socket: /run/shell-mcp/broad/privd-broad.sock
`)
	r = sandbox.Compute(p)
	if !slices.Contains(r.ReadOnly, "/var/log/journal") || !slices.Contains(r.ReadOnly, "/run/log/journal") {
		t.Fatalf("journal dirs missing: %v", r.ReadOnly)
	}
	if !slices.Equal(r.UnixSocketDirs, []string{"/run/dbus", "/run/shell-mcp", "/run/shell-mcp/broad"}) {
		t.Fatalf("socket dirs %v", r.UnixSocketDirs)
	}
	// Privileged sockets are not granted when forwarding is disabled.
	p = parse(t, "version: 1\nmax_tier: read\nprivileged:\n  enabled: false\n  socket: /run/shell-mcp/privd.sock\n")
	if r := sandbox.Compute(p); len(r.UnixSocketDirs) != 0 {
		t.Fatalf("disabled privileged still granted: %v", r.UnixSocketDirs)
	}
}

func TestPlan(t *testing.T) {
	req := parse(t, "version: 1\nmax_tier: read\n")
	best := parse(t, "version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\n")
	for abi := 0; abi < sandbox.RequiredMinABI; abi++ {
		r, err := sandbox.Plan(req, abi)
		if !errors.Is(err, sandbox.ErrUnavailable) {
			t.Fatalf("required at ABI %d: %v", abi, err)
		}
		if r.RequiredMinABI != 4 || r.KernelABI != abi {
			t.Fatalf("report %+v", r)
		}
	}
	cases := []struct {
		abi  int
		want sandbox.Enforcement
		not  []string
	}{
		{0, sandbox.Enforcement{}, []string{"fs", "net", "unix_socket", "scope"}},
		{2, sandbox.Enforcement{}, []string{"fs", "net", "unix_socket", "scope"}},
		{3, sandbox.Enforcement{FS: true}, []string{"net", "unix_socket", "scope"}},
		{5, sandbox.Enforcement{FS: true, Net: true}, []string{"unix_socket", "scope"}},
		{7, sandbox.Enforcement{FS: true, Net: true}, []string{"unix_socket", "scope"}}, // scoping needs one domain: TSYNC, ABI 8
		{8, sandbox.Enforcement{FS: true, Net: true, Scope: true}, []string{"unix_socket"}},
		{9, sandbox.Enforcement{FS: true, Net: true, Scope: true, UnixSocket: true}, []string{}},
		{12, sandbox.Enforcement{FS: true, Net: true, Scope: true, UnixSocket: true}, []string{}},
	}
	for _, c := range cases {
		r, err := sandbox.Plan(best, c.abi)
		if err != nil {
			t.Fatalf("best-effort ABI %d: %v", c.abi, err)
		}
		if r.Enforced != c.want || !slices.Equal(r.NotEnforced, c.not) || r.Mode != "best-effort" {
			t.Errorf("ABI %d: %+v", c.abi, r)
		}
		if c.abi >= sandbox.RequiredMinABI {
			if _, err := sandbox.Plan(req, c.abi); err != nil {
				t.Errorf("required at ABI %d: %v", c.abi, err)
			}
		}
		if (c.abi >= 9) == strings.Contains(r.UnixSocketControl, "file permissions") {
			t.Errorf("ABI %d unix socket control %q", c.abi, r.UnixSocketControl)
		}
		if c.abi >= 10 && r.EffectiveABI != 10 {
			t.Errorf("effective ABI must be capped at 10: %d", r.EffectiveABI)
		}
	}
	r, _ := sandbox.Plan(best, 7)
	if !slices.Equal(r.ExtraFiles, []string{"/dev/null (read, write, truncate)", "/dev/urandom (read)"}) {
		t.Fatalf("extra files %v", r.ExtraFiles)
	}
	if r.MPTCP != "blocked by seccomp" {
		t.Fatalf("mptcp %q", r.MPTCP)
	}
}

func TestKernelABI(t *testing.T) {
	k := sandbox.KernelABI()
	t.Logf("kernel Landlock ABI %d", k)
	if req, _ := strconv.Atoi(os.Getenv(RequireABIEnv)); req > 0 && k < req {
		t.Fatalf("%s=%d but kernel ABI is %d", RequireABIEnv, req, k)
	}
	if k < 1 {
		t.Skip("Landlock unavailable in this environment")
	}
}

var (
	applierOnce sync.Once
	applierPath string
	applierDir  string
)

func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "sandbox-applier")
	if err != nil {
		panic(err)
	}
	applierDir = d
	code := m.Run()
	_ = os.RemoveAll(d)
	os.Exit(code)
}

func applier(t *testing.T) string {
	t.Helper()
	applierOnce.Do(func() {
		applierPath = gatetest.Build(t, "internal/gate/sandbox/testdata/applier", applierDir, "applier", nil)
	})
	if applierPath == "" {
		t.Fatal("applier build failed earlier")
	}
	return applierPath
}

type threadResult struct {
	TID        int    `json:"tid"`
	NoNewPrivs string `json:"no_new_privs"`
	Seccomp    string `json:"seccomp"`
	Filters    string `json:"seccomp_filters"`
	Read       string `json:"read"`
}

type applierOut struct {
	FiltersBefore string            `json:"seccomp_filters_before"`
	CGO           string            `json:"cgo"`
	Report        sandbox.Report    `json:"report"`
	Error         string            `json:"error"`
	Threads       []threadResult    `json:"threads"`
	Probes        map[string]string `json:"probes"`
}

// layout: <d>/allowed/ok.txt (a read root), <d>/outside/secret.txt (no root).
func layout(t *testing.T, mode, extra string) (policyFile, allowed, outside string) {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(d, "allowed", "ok.txt"), "ok", 0o644)
	gatetest.WriteFile(t, filepath.Join(d, "outside", "secret.txt"), "secret", 0o644)
	policyFile = filepath.Join(d, "policy.yaml")
	gatetest.WriteFile(t, policyFile, "version: 1\nmax_tier: read\nsandbox:\n  landlock: "+mode+"\n"+extra+
		"paths:\n  read: ["+filepath.Join(d, "allowed")+"]\n", 0o644)
	return policyFile, filepath.Join(d, "allowed", "ok.txt"), filepath.Join(d, "outside", "secret.txt")
}

func runApplier(t *testing.T, args ...string) applierOut {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), applier(t), args...) //nolint:gosec // G204: test program built by this test
	b, err := cmd.Output()
	var out applierOut
	if jerr := json.Unmarshal(b, &out); jerr != nil {
		t.Fatalf("applier output %q (err %v): %v", b, err, jerr)
	}
	if out.CGO != "0" {
		t.Fatalf("applier must be built with CGO_ENABLED=0, got %q", out.CGO)
	}
	return out
}

// TestApplyFilesystemAllThreads: every thread, including goroutines locked
// to their own OS threads before Apply, reports NoNewPrivs 1 and is denied a
// path outside the policy by the kernel. Runs wherever Landlock exists
// (locally ABI 3, CI ABI 7).
func TestApplyFilesystemAllThreads(t *testing.T) {
	needABI(t, 1)
	pf, allowed, outside := layout(t, "best-effort", "")
	out := runApplier(t, "-policy", pf, "-threads", "6", "-read", outside, "-allowed", allowed, "-bind")
	if out.Error != "" {
		t.Fatalf("apply: %s", out.Error)
	}
	if !out.Report.Applied || !out.Report.NoNewPrivs {
		t.Fatalf("report %+v", out.Report)
	}
	if len(out.Threads) != 6 {
		t.Fatalf("threads %+v", out.Threads)
	}
	tids := map[int]bool{}
	for _, th := range out.Threads {
		tids[th.TID] = true
		before, _ := strconv.Atoi(out.FiltersBefore)
		if after, err := strconv.Atoi(th.Filters); err != nil || after != before+1 {
			t.Fatalf("thread %d: seccomp filters %q after, %q before; want exactly one more", th.TID, th.Filters, out.FiltersBefore)
		}
		if th.NoNewPrivs != "1" || th.Read != "EACCES" || th.Seccomp != "2" {
			t.Fatalf("thread %+v", th)
		}
	}
	if len(tids) != 6 {
		t.Fatalf("goroutines were not on distinct threads: %v", tids)
	}
	if out.Probes["read"] != "EACCES" || out.Probes["allowed"] != "READ" {
		t.Fatalf("probes %v", out.Probes)
	}
	// MPTCP is unavailable (seccomp), so a default Go listener falls back to
	// plain TCP: it binds where Landlock cannot govern TCP (ABI < 4) and is
	// denied where it can.
	if out.Report.MPTCP != "blocked by seccomp" {
		t.Fatalf("mptcp report %q", out.Report.MPTCP)
	}
	wantBind := "BOUND"
	if out.Report.Enforced.Net {
		wantBind = "EACCES"
	}
	if out.Probes["bind"] != wantBind {
		t.Fatalf("default listener: %q, want %q", out.Probes["bind"], wantBind)
	}
}

// TestRequiredRefusedBelowMinABI runs only on kernels below ABI 4 (the local
// ABI 3 containers): `required` must refuse, changing nothing.
func TestRequiredRefusedBelowMinABI(t *testing.T) {
	k := sandbox.KernelABI()
	if k >= sandbox.RequiredMinABI {
		t.Skipf("needs a kernel below Landlock ABI %d (this one has %d); runs locally on ABI 3", sandbox.RequiredMinABI, k)
	}
	pf, _, outside := layout(t, "required", "")
	out := runApplier(t, "-policy", pf, "-read", outside)
	if !strings.Contains(out.Error, sandbox.ErrUnavailable.Error()) || out.Report.Applied {
		t.Fatalf("required below min ABI: %+v", out)
	}
}

// TestBestEffortReportsGaps runs on kernels below ABI 4: best-effort serves
// and reports exactly which classes are not enforced.
func TestBestEffortReportsGaps(t *testing.T) {
	k := sandbox.KernelABI()
	if k >= sandbox.RequiredMinABI || k < 1 {
		t.Skipf("needs a kernel with Landlock below ABI %d (this one has %d); runs locally on ABI 3", sandbox.RequiredMinABI, k)
	}
	pf, _, _ := layout(t, "best-effort", "")
	out := runApplier(t, "-policy", pf)
	if out.Error != "" || !out.Report.Applied {
		t.Fatalf("best-effort: %+v", out)
	}
	want := []string{"net", "unix_socket", "scope"}
	if k < sandbox.ABIFSFull {
		want = append([]string{"fs"}, want...)
	}
	if !slices.Equal(out.Report.NotEnforced, want) {
		t.Fatalf("not enforced %v, want %v", out.Report.NotEnforced, want)
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

// TestApplyNetwork (ABI 4+, CI): connect only to listed ports, no bind.
func TestApplyNetwork(t *testing.T) {
	needABI(t, sandbox.ABINet)
	listed, closeA := listen(t)
	defer closeA()
	other, closeB := listen(t)
	defer closeB()
	pf, _, _ := layout(t, "required", "  tcp_connect_ports: ["+strconv.Itoa(listed)+"]\n")
	out := runApplier(t, "-policy", pf, "-connect", strconv.Itoa(other), "-bind")
	if out.Error != "" || !out.Report.Enforced.Net {
		t.Fatalf("apply: %+v", out)
	}
	if out.Probes["connect"] != "EACCES" || out.Probes["bind"] != "EACCES" {
		t.Fatalf("unlisted connect / bind not denied: %v", out.Probes)
	}
	out = runApplier(t, "-policy", pf, "-connect", strconv.Itoa(listed))
	if out.Probes["connect"] != "CONNECTED" {
		t.Fatalf("listed port refused: %v", out.Probes)
	}
}

// TestApplySignalScope (ABI 6+, CI): no signals to processes outside the domain.
func TestApplySignalScope(t *testing.T) {
	needABI(t, sandbox.ABIScope)
	victim := exec.CommandContext(t.Context(), gatetest.BuildProbe(t, t.TempDir(), "probe", "/nonexistent"), "sleep", "30s") //nolint:gosec // G204: test child
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Process.Kill(); _ = victim.Wait() }()
	pf, _, _ := layout(t, "required", "")
	out := runApplier(t, "-policy", pf, "-signal", strconv.Itoa(victim.Process.Pid))
	if out.Error != "" || !out.Report.Enforced.Scope {
		t.Fatalf("apply: %+v", out)
	}
	if out.Probes["signal"] != "EPERM" {
		t.Fatalf("signal outside the domain not denied: %v", out.Probes)
	}
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(victim.Process.Pid, 0); err != nil {
		t.Fatalf("victim is gone: %v", err)
	}
}

// requireMPTCPEnv: CI sets it so the MPTCP test fails, never skips, when
// the control case cannot open an MPTCP socket on the runner's kernel.
const requireMPTCPEnv = "SHELL_MCP_REQUIRE_MPTCP"

// TestApplyMPTCPBlocked is two-sided. Control: this (unsandboxed) test
// process opens an MPTCP socket on this kernel. Filtered: the applier makes
// the identical socket(2) call after Apply and gets EPROTONOSUPPORT. Without
// the control the filtered result would prove nothing on a kernel that has
// no MPTCP.
func TestApplyMPTCPBlocked(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP)
	if err != nil {
		msg := "control: this kernel does not open an MPTCP socket without the filter (" + err.Error() + "); the filter cannot be proven here"
		if os.Getenv(requireMPTCPEnv) != "" {
			t.Fatal(msg)
		}
		t.Skip(msg + "; runs in CI")
	}
	_ = unix.Close(fd)
	pf, _, _ := layout(t, "best-effort", "")
	out := runApplier(t, "-policy", pf, "-mptcp")
	if out.Error != "" || out.Report.MPTCP != "blocked by seccomp" {
		t.Fatalf("apply: %+v", out)
	}
	if out.Probes["mptcp"] != "EPROTONOSUPPORT" {
		t.Fatalf("filtered: MPTCP socket after Apply: %q", out.Probes["mptcp"])
	}
}

// TestComputeServiceAndSyslogGrants: the system D-Bus socket directory is
// granted when any service feature is configured (services.status, which
// also enables service_list, or services.control) and never otherwise; the
// syslog socket is always granted, for the audit line.
func TestComputeServiceAndSyslogGrants(t *testing.T) {
	cases := []struct {
		name string
		y    string
		bus  bool
	}{
		{"nothing", "version: 1\nmax_tier: read\n", false},
		{"journal only", "version: 1\nmax_tier: read\njournal:\n  units: [\"*\"]\n", false},
		{"status", "version: 1\nmax_tier: read\nservices:\n  status: [\"example-*.service\"]\n", true},
		{"control", "version: 1\nmax_tier: operator\nservices:\n  control:\n    units: [example-app.service]\n    verbs: [restart]\n", true},
	}
	for _, c := range cases {
		r := sandbox.Compute(parse(t, c.y))
		if got := slices.Contains(r.UnixSocketDirs, "/run/dbus"); got != c.bus {
			t.Errorf("%s: D-Bus granted=%v, want %v (%v)", c.name, got, c.bus, r.UnixSocketDirs)
		}
		if r.SyslogSocket != "/dev/log" {
			t.Errorf("%s: syslog socket %q", c.name, r.SyslogSocket)
		}
	}
}

// TestSocketDir: the syslog grant is the directory that really holds the
// socket (/dev/log is a symlink into /run/systemd/journal on systemd
// hosts); a missing path or a non-socket grants nothing.
func TestSocketDir(t *testing.T) {
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(d, "journal", "dev-log")
	gatetest.Mkdir(t, filepath.Dir(sock), 0o755)
	l, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	gatetest.Mkdir(t, filepath.Join(d, "dev"), 0o755)
	link := filepath.Join(d, "dev", "log")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	if got, ok := sandbox.SocketDir(link); !ok || got != filepath.Dir(sock) {
		t.Fatalf("SocketDir(link) = %q %v", got, ok)
	}
	if got, ok := sandbox.SocketDir(sock); !ok || got != filepath.Dir(sock) {
		t.Fatalf("SocketDir(real) = %q %v", got, ok)
	}
	gatetest.WriteFile(t, filepath.Join(d, "plain"), "x", 0o644)
	for _, p := range []string{filepath.Join(d, "missing"), filepath.Join(d, "plain"), d} {
		if got, ok := sandbox.SocketDir(p); ok {
			t.Fatalf("SocketDir(%s) = %q", p, got)
		}
	}
}
