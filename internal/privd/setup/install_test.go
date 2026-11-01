//go:build linux

package setup_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/setuptest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/setup"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// Invented, with TARGET-SETUP's placeholders: svc-shell 60123, its socket
// group svc-shell-priv 60124.
const (
	polPath  = "/etc/shell-mcp/privileged.yaml"
	gatePath = "/etc/shell-mcp/admin.yaml"
	hashA    = "1111111111111111111111111111111111111111111111111111111111111111"
	hashB    = "2222222222222222222222222222222222222222222222222222222222222222"
	sock     = "/etc/systemd/system/shell-mcp-privd.socket"
	svc      = "/etc/systemd/system/shell-mcp-privd@.service"
	bsock    = "/etc/systemd/system/shell-mcp-privd-broad.socket"
	bsvc     = "/etc/systemd/system/shell-mcp-privd-broad@.service"
)

func corePolicy(hash string) *policy.Policy {
	return &policy.Policy{
		ClientUID: 60123, SocketGroup: "svc-shell-priv", SocketGID: 60124,
		MaxTier: policy.TierRead, Landlock: policy.LandlockRequired,
		Limits:       policy.Limits{MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxOutputBytes: 1 << 20, DefaultTimeoutS: 60, MaxTimeoutS: 900, MaxDeleteEntries: 1000, MaxMemoryMB: 1024},
		ModesMax:     0o755,
		BackupsKeep:  10,
		Capabilities: append([]string(nil), policy.BaseCapabilities...),
		SHA256:       hash,
		File:         polPath,
	}
}

func broadPolicy() *policy.Policy {
	p := corePolicy(hashA)
	p.Packages.Enabled = true
	return p
}

type host struct {
	*setuptest.Fake
	pol       *policy.Policy
	fails     int
	gate      map[string]*gpolicy.Policy
	verifyErr bool
	// sockMode is the mode systemd gives the sockets (default 0660).
	sockMode fs.FileMode
	order    []string
	// onCheck runs after CheckPolicy has read the policy.
	onCheck func()
	// security replaces systemd-analyze security's output.
	security *setupx.Output
}

func (h *host) CheckPolicy(path string, out io.Writer) (p *policy.Policy, fails int) {
	_, _ = fmt.Fprintf(out, "shell-mcp-privd test check-policy %s\n", path)
	if h.onCheck != nil {
		h.onCheck()
	}
	if h.pol == nil {
		return nil, 1
	}
	c := *h.pol
	return &c, h.fails
}

func (h *host) LoadGatePolicy(path, _ string) (*gpolicy.Policy, error) {
	if g, ok := h.gate[path]; ok {
		return g, nil
	}
	return nil, errors.New("no such gate policy")
}

func (h *host) programs(f *setuptest.Fake, prog string, args []string) (setupx.Output, error) {
	h.order = append(h.order, strings.TrimPrefix(strings.TrimPrefix(prog, "/usr/bin/"), "/usr/sbin/")+" "+strings.Join(args, " "))
	switch {
	case prog == setupx.SystemdAnalyze && args[0] == "verify":
		if h.verifyErr {
			return setuptest.Failed("shell-mcp-privd@.service: Unknown key name 'Bogus'"), nil
		}
	case prog == setupx.SystemdAnalyze && args[0] == "security" && h.security != nil:
		return *h.security, nil
	case prog == setupx.SystemdAnalyze && args[0] == "security":
		return setuptest.OK("→ Overall exposure level for shell-mcp-privd@.service: 1.3 OK :-)\n"), nil
	case prog == setupx.Systemctl && args[0] == "enable":
		// systemd creates the directory and the socket node.
		f.Dir(setup.RunDir, 0o711, 0, 0)
		p := units.SocketPath
		if args[2] == units.BroadSocketUnit {
			p = units.BroadSocketPath
		}
		f.Files[p] = &setuptest.File{Mode: fs.ModeSocket | h.sockMode, UID: 0, GID: 60124}
	}
	return setupx.Output{}, nil
}

func newHost(p *policy.Policy) *host {
	f := setuptest.New()
	f.Exe = units.HelperPath
	f.Put(units.HelperPath, "\x7fELF", 0o755, 0, 0)
	for _, d := range []string{"/etc/shell-mcp", "/etc/systemd", "/etc/systemd/system"} {
		f.Dir(d, 0o755, 0, 0)
	}
	f.Put(polPath, "invented privileged policy\n", 0o600, 0, 0)
	f.Put("/etc/passwd", "root:x:0:0::/root:/bin/bash\nsvc-shell:x:60123:60123::/var/lib/svc-shell:/bin/sh\n", 0o644, 0, 0)
	f.Put("/etc/group", "root:x:0:\nsvc-shell:x:60123:\nsvc-shell-priv:x:60124:svc-shell\n", 0o644, 0, 0)
	h := &host{Fake: f, pol: p, sockMode: 0o660, gate: map[string]*gpolicy.Policy{}}
	f.Programs = h.programs
	return h
}

type result struct {
	code   int
	out    string
	audit  string
	before map[string]setuptest.File
}

func install(t *testing.T, h *host, args ...string) result {
	t.Helper()
	o, err := setup.ParseFlags(append([]string{"--policy", polPath}, args...))
	if err != nil {
		t.Fatal(err)
	}
	var out, aud bytes.Buffer
	before := h.Snapshot()
	h.order = nil
	code := setup.Install(o, h, &out, &setupx.Auditor{Stderr: &aud, Component: "privd", DryRun: o.DryRun})
	if l := h.Temps(); len(l) > 0 {
		t.Fatalf("temp files left: %v", l)
	}
	return result{code, out.String(), aud.String(), before}
}

// TestInstallUnits: the units written are exactly what units --out writes
// (internal/privd/units), root:root 0644; the backup store is created
// root:root 0700; then verify, daemon-reload and enable --now in that
// order; the sockets' modes and the score are checked.
func TestInstallUnits(t *testing.T) {
	for _, p := range []*policy.Policy{corePolicy(hashA), broadPolicy()} {
		h := newHost(p)
		r := install(t, h, "--accept", hashA)
		if r.code != 0 {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
		core, _ := units.Core(p)
		want := map[string]string{sock: core.Socket, svc: core.Service}
		if p.UsesBroad() {
			b, _ := units.Broad(p)
			want[bsock], want[bsvc] = b.Socket, b.Service
		} else if _, ok := h.Get(bsock); ok {
			t.Fatal("a broad socket for a core-only policy")
		}
		for path, w := range want {
			got, ok := h.Get(path)
			if e := h.Files[path]; !ok || got != w || e.Mode != 0o644 || e.UID != 0 || e.GID != 0 {
				t.Errorf("%s: %v %+v", path, ok, e)
			}
		}
		for _, d := range []string{setup.StateDir, units.BackupDir} {
			if e := h.Files[d]; e == nil || e.Mode != fs.ModeDir|0o700 || e.UID != 0 {
				t.Errorf("%s: %+v", d, e)
			}
		}
		seq := []string{"systemd-analyze verify --man=no " + sock + " " + svc, "systemctl daemon-reload", "systemctl enable --now shell-mcp-privd.socket", "systemd-analyze security --no-pager shell-mcp-privd@.service"}
		if p.UsesBroad() {
			seq = []string{"systemd-analyze verify --man=no " + sock + " " + svc, "systemd-analyze verify --man=no " + bsock + " " + bsvc, "systemctl daemon-reload",
				"systemctl enable --now shell-mcp-privd.socket", "systemctl enable --now shell-mcp-privd-broad.socket"}
		}
		if !inOrder(h.order, seq) {
			t.Errorf("order %q, want %q", h.order, seq)
		}
		if !strings.Contains(r.audit, `"action":"accept","object":"review"`) || !strings.Contains(r.audit, `"unit":"shell-mcp-privd.socket"`) {
			t.Errorf("audit:\n%s", r.audit)
		}
	}
}

func inOrder(have, want []string) bool {
	i := 0
	for _, h := range have {
		if i < len(want) && h == want[i] {
			i++
		}
	}
	return i == len(want)
}

// TestReviewStop: without --accept, or with another hash, install prints
// the review and stops with exit 3, writing nothing, on every run: a first
// install, a re-run of an installed unchanged policy, and a policy with no
// REVIEW item and no broad unit (handoff §7 Q4).
func TestReviewStop(t *testing.T) {
	h := newHost(corePolicy(hashA))
	for _, args := range [][]string{nil, {"--accept", hashB}} {
		r := install(t, h, args...)
		if r.code != setup.ExitReview || !strings.Contains(r.out, "--accept "+hashA) || !reflect.DeepEqual(h.Snapshot(), r.before) || len(h.order) != 0 {
			t.Fatalf("%v: exit %d, ran %v:\n%s", args, r.code, h.order, r.out)
		}
		if !strings.Contains(r.audit, `"action":"review"`) || strings.Contains(r.audit, `"action":"refuse"`) {
			t.Fatalf("the review stop is audited at notice: %s", r.audit)
		}
	}
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatalf("install: %d\n%s", r.code, r.out)
	}
	r := install(t, h)
	if r.code != setup.ExitReview || !reflect.DeepEqual(h.Snapshot(), r.before) {
		t.Fatalf("an unchanged re-run without --accept: %d\n%s", r.code, r.out)
	}
	r = install(t, h, "--dry-run")
	if r.code != setup.ExitReview {
		t.Fatalf("a dry run without --accept: %d", r.code)
	}
}

// TestAcceptBindsTheBytesRead: the hash accepted and the units' hash are of
// the policy as check-policy read it once; a file swapped afterwards is not
// read again.
func TestAcceptBindsTheBytesRead(t *testing.T) {
	h := newHost(corePolicy(hashA))
	h.onCheck = func() { h.Put(polPath, "swapped after the check\n", 0o600, 0, 0) }
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatalf("%d\n%s", r.code, r.out)
	}
	got, _ := h.Get(svc)
	if !strings.Contains(got, "SHELL_MCP_PRIVD_POLICY_SHA256="+hashA) {
		t.Fatalf("the unit is not pinned to the accepted bytes:\n%s", got)
	}
}

// TestSecondRunUnchanged: the same policy again writes nothing and reloads
// nothing, and confirms the sockets.
func TestSecondRunUnchanged(t *testing.T) {
	h := newHost(corePolicy(hashA))
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatal(r.out)
	}
	writes := h.Writes
	r := install(t, h, "--accept", hashA)
	if r.code != 0 || h.Writes != writes || !strings.Contains(r.out, "nothing to do: every item unchanged") || slices.Contains(h.order, "systemctl daemon-reload") {
		t.Fatalf("%d, %d writes, ran %v:\n%s", r.code, h.Writes-writes, h.order, r.out)
	}
	if !slices.Contains(h.order, "systemctl enable --now shell-mcp-privd.socket") {
		t.Fatalf("the socket is not confirmed enabled: %v", h.order)
	}
}

// TestPolicyEdit: an edited policy replaces the units pinned to the old
// hash and restarts the socket whose own unit changed.
func TestPolicyEdit(t *testing.T) {
	h := newHost(corePolicy(hashA))
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatal(r.out)
	}
	h.pol = corePolicy(hashB)
	r := install(t, h, "--accept", hashB)
	if r.code != 0 || !inOrder(h.order, []string{"systemctl daemon-reload", "systemctl enable --now shell-mcp-privd.socket", "systemctl restart shell-mcp-privd.socket"}) {
		t.Fatalf("%d %v:\n%s", r.code, h.order, r.out)
	}
	if got, _ := h.Get(svc); !strings.Contains(got, hashB) {
		t.Fatal("the unit is not on the new hash")
	}
}

// TestBroadPairRemoved: a policy that stops using the broad unit disables
// its socket and removes the pair it generated.
func TestBroadPairRemoved(t *testing.T) {
	h := newHost(broadPolicy())
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatal(r.out)
	}
	h.pol = corePolicy(hashB)
	r := install(t, h, "--accept", hashB)
	if r.code != 0 || !inOrder(h.order, []string{"systemctl disable --now shell-mcp-privd-broad.socket", "systemctl daemon-reload"}) {
		t.Fatalf("%d %v:\n%s", r.code, h.order, r.out)
	}
	for _, p := range []string{bsock, bsvc} {
		if _, ok := h.Get(p); ok {
			t.Errorf("%s left in place", p)
		}
	}
	if !strings.Contains(r.audit, `"action":"remove","object":"unit","path":"`+bsock) {
		t.Fatalf("audit:\n%s", r.audit)
	}
	// systemd keeps a stopped socket's node (RemoveOnStop= is off); install
	// leaves it, and says that nothing listens on it.
	if !strings.Contains(r.out, "NOTE "+units.BroadSocketPath+" stays as a file node") {
		t.Fatalf("no NOTE about the stopped socket's node:\n%s", r.out)
	}
}

// TestRollbackOnVerify: when systemd-analyze verify fails, the previous
// units are restored exactly and no temp file is left.
func TestRollbackOnVerify(t *testing.T) {
	h := newHost(corePolicy(hashA))
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatal(r.out)
	}
	h.pol = corePolicy(hashB)
	h.verifyErr = true
	r := install(t, h, "--accept", hashB)
	if r.code != 1 || !strings.Contains(r.out, "Unknown key name") || !strings.Contains(r.out, "every file this run changed was restored") {
		t.Fatalf("%d:\n%s", r.code, r.out)
	}
	if !reflect.DeepEqual(h.Snapshot(), r.before) {
		t.Fatal("the previous units were not restored")
	}
	if slices.Contains(h.order, "systemctl daemon-reload") {
		t.Fatal("reloaded after a failed verify")
	}
}

// TestDryRun: the plan, the files' content, and nothing changed or run but
// what reads.
func TestDryRun(t *testing.T) {
	h := newHost(broadPolicy())
	r := install(t, h, "--accept", hashA, "--dry-run")
	if r.code != 0 || !reflect.DeepEqual(h.Snapshot(), r.before) || len(h.order) != 0 || r.audit != "" {
		t.Fatalf("%d, ran %v:\n%s", r.code, h.order, r.out)
	}
	for _, s := range []string{"file " + sock + " root:root 0644: create", "     | # Generated by shell-mcp-privd units", "directory /var/lib/shell-mcp/backups root:root 0700: create",
		"would run /usr/bin/systemctl enable --now shell-mcp-privd-broad.socket"} {
		if !strings.Contains(r.out, s) {
			t.Errorf("dry run lacks %q:\n%s", s, r.out)
		}
	}
	if r := install(t, h, "--accept", hashA); r.code != 0 {
		t.Fatal(r.out)
	}
	h.order = nil
	if r := install(t, h, "--accept", hashA, "--dry-run"); r.code != 0 || !slices.Contains(h.order, "systemd-analyze verify --man=no "+sock+" "+svc) {
		t.Fatalf("a dry run over installed units verifies them in place: %v\n%s", h.order, r.out)
	}
}

// TestNoStart: --no-start writes and verifies, and runs no systemctl.
func TestNoStart(t *testing.T) {
	h := newHost(corePolicy(hashA))
	h.Systemd = false
	r := install(t, h, "--accept", hashA, "--no-start")
	if r.code != 0 {
		t.Fatalf("%d:\n%s", r.code, r.out)
	}
	for _, o := range h.order {
		if strings.HasPrefix(o, "systemctl") {
			t.Fatalf("ran %q", o)
		}
	}
	if _, ok := h.Get(sock); !ok {
		t.Fatal("no units written")
	}
}

func TestGatePolicyCrossCheck(t *testing.T) {
	ok := &gpolicy.Policy{Privileged: gpolicy.Privileged{Enabled: true, Socket: units.SocketPath}}
	for _, c := range []struct {
		name string
		p    *policy.Policy
		gate *gpolicy.Policy
		want string
	}{
		{"agrees", corePolicy(hashA), ok, ""},
		{"broad agrees", broadPolicy(), &gpolicy.Policy{Privileged: gpolicy.Privileged{Enabled: true, Socket: units.SocketPath, BroadSocket: units.BroadSocketPath}}, ""},
		{"not enabled", corePolicy(hashA), &gpolicy.Policy{}, "does not have privileged.enabled"},
		{"another socket", corePolicy(hashA), &gpolicy.Policy{Privileged: gpolicy.Privileged{Enabled: true, Socket: "/run/other.sock"}}, "privileged.socket"},
		{"a broad socket without the broad pair", corePolicy(hashA), &gpolicy.Policy{Privileged: gpolicy.Privileged{Enabled: true, Socket: units.SocketPath, BroadSocket: units.BroadSocketPath}}, "broad_socket"},
		{"no broad socket with the broad pair", broadPolicy(), ok, "broad_socket"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(c.p)
			h.gate[gatePath] = c.gate
			r := install(t, h, "--accept", hashA, "--gate-policy", gatePath)
			if (c.want == "") != (r.code == 0) || !strings.Contains(r.out, c.want) {
				t.Fatalf("%d:\n%s", r.code, r.out)
			}
		})
	}
}

// TestRefusals: every refusal of TARGET-SETUP §12.3, nothing written.
func TestRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*host)
		args []string
		want string
	}{
		{"not root", func(h *host) { h.EUID = 60123 }, nil, "runs as root only"},
		{"forced command", func(h *host) { h.Env["SSH_ORIGINAL_COMMAND"] = "x" }, nil, "never runs as an SSH forced command"},
		{"another binary", func(h *host) { h.Exe = "/tmp/shell-mcp-privd" }, nil, "not /usr/local/libexec/shell-mcp-privd"},
		{"policy 0644", func(h *host) { h.Put(polPath, "x", 0o644, 0, 0) }, nil, "it must be root:root with no group or other bits"},
		{"policy owned by the account", func(h *host) { h.Put(polPath, "x", 0o600, 60123, 0) }, nil, "it must be root:root"},
		{"check-policy FAIL", func(h *host) { h.fails = 2 }, nil, "check-policy reports 2 problem(s)"},
		{"policy does not load", func(h *host) { h.pol = nil }, nil, "check-policy reports 1 problem(s)"},
		{"no client account", func(h *host) { h.Put("/etc/passwd", "root:x:0:0::/root:/bin/bash\n", 0o644, 0, 0) }, nil, "client_uid 60123 is 0 local accounts"},
		{"not in the socket group", func(h *host) { h.Put("/etc/group", "root:x:0:\nsvc-shell-priv:x:60124:\n", 0o644, 0, 0) }, nil, "is not a member of socket_group"},
		{"socket group with another gid", func(h *host) { h.Put("/etc/group", "root:x:0:\nsvc-shell-priv:x:60200:svc-shell\n", 0o644, 0, 0) }, nil, "has gid 60200"},
		{"backup store mode", func(h *host) { h.Dir(setup.StateDir, 0o755, 0, 0) }, nil, "/var/lib/shell-mcp exists but is not a root:root directory without group or other bits"},
		{"a hand-written unit", func(h *host) { h.Put(sock, "[Socket]\nListenStream=/run/x\n", 0o644, 0, 0) }, nil, "without the \"# Generated by shell-mcp-privd units\" header"},
		{"a hand-written broad unit to remove", func(h *host) { h.Put(bsvc, "[Service]\n", 0o644, 0, 0) }, nil, "without the"},
		{"no systemd", func(h *host) { h.Systemd = false }, nil, "systemd is not running as PID 1"},
		{"insecure helper", func(h *host) { h.ChainErr[units.HelperPath] = errors.New("group-writable") }, nil, "group-writable"},
		{"an unknown gate policy", nil, []string{"--gate-policy", "/etc/shell-mcp/none.yaml"}, "does not load"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(corePolicy(hashA))
			if c.mod != nil {
				c.mod(h)
			}
			r := install(t, h, append([]string{"--accept", hashA}, c.args...)...)
			if r.code != 1 || !strings.Contains(r.out, c.want) {
				t.Fatalf("exit %d, want 1 with %q:\n%s", r.code, c.want, r.out)
			}
			if !reflect.DeepEqual(h.Snapshot(), r.before) || len(h.order) != 0 {
				t.Fatalf("a refused run changed or ran something: %v", h.order)
			}
			if !strings.Contains(r.audit, `"action":"refuse"`) {
				t.Fatalf("not audited: %s", r.audit)
			}
		})
	}
}

// TestSocketModesAfterActivation: sockets with another mode after
// activation are refused, with the units left in place.
func TestSocketModesAfterActivation(t *testing.T) {
	h := newHost(corePolicy(hashA))
	h.sockMode = 0o666
	r := install(t, h, "--accept", hashA)
	if r.code != 1 || !strings.Contains(r.out, "is not a root:60124 0660 socket after activation") {
		t.Fatalf("%d:\n%s", r.code, r.out)
	}
	if _, ok := h.Get(sock); !ok {
		t.Fatal("the units were not left in place")
	}
}

func TestParseFlags(t *testing.T) {
	o, err := setup.ParseFlags([]string{"--policy", polPath, "--accept", hashA, "--gate-policy", "/a", "--gate-policy", "/b", "--no-start"})
	if err != nil || !slices.Equal(o.GatePolicies, []string{"/a", "/b"}) || !o.NoStart || o.Accept != hashA {
		t.Fatalf("%+v %v", o, err)
	}
	for _, args := range [][]string{{}, {"--policy", polPath, "--accept", "ABC"}, {"--policy", polPath, "extra"}, {"--bogus"}} {
		if _, err := setup.ParseFlags(args); err == nil {
			t.Errorf("%q: accepted", args)
		}
	}
}

// TestScoreDiagnostics: when systemd-analyze security gives no exposure
// level, the WARN says why: its exit code and the first lines it printed.
func TestScoreDiagnostics(t *testing.T) {
	h := newHost(corePolicy(hashA))
	h.security = &setupx.Output{Exit: 1, Stderr: []byte("Failed to connect to bus: invented reason\n")}
	r := install(t, h, "--accept", hashA)
	if r.code != 0 || !strings.Contains(r.out, "WARN systemd-analyze security shell-mcp-privd@.service gave no exposure level (exit 1: Failed to connect to bus: invented reason)") {
		t.Fatalf("%d:\n%s", r.code, r.out)
	}
}

// TestScoreColored: the exposure level is read also when systemd-analyze
// colours it (an escape sequence between ": " and the digits), and a miss
// shows the output's last lines, where the level is printed.
func TestScoreColored(t *testing.T) {
	h := newHost(corePolicy(hashA))
	h.security = &setupx.Output{Stdout: []byte("NAME DESCRIPTION EXPOSURE\n\n\u2192 \x1b[0;1;39mOverall exposure level for shell-mcp-privd@test_instance.service\x1b[0m: \x1b[0;32m1.3 OK\x1b[0m \U0001F642\n")}
	r := install(t, h, "--accept", hashA)
	if r.code != 0 || !strings.Contains(r.out, "ok   systemd-analyze security shell-mcp-privd@.service: 1.3 (expected 1.3)") {
		t.Fatalf("%d:\n%s", r.code, r.out)
	}
	h2 := newHost(corePolicy(hashA))
	h2.security = &setupx.Output{Stdout: []byte("row 1\nrow 2\nrow 3\nrow 4\nthe last line\n")}
	if r := install(t, h2, "--accept", hashA); !strings.Contains(r.out, "the last line") || strings.Contains(r.out, "row 1") {
		t.Fatalf("a miss must show the last lines:\n%s", r.out)
	}
}
