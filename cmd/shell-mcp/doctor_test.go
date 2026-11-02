package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/sshx/sshtest"
)

// `shell-mcp doctor` (handoff §4.E). Every host, address, name, key and
// policy value below is an invented test fixture.

const helloPriv = `{"gate_version":"0.1.0","protocol":2,"principal":"admin-key","policy_sha256":"ab12","max_tier":"operator",` +
	`"ops":["hello","policy"],"sandbox":{"mode":"required","kernel_abi":7,"effective_abi":7,"required_min_abi":4,"applied":true,` +
	`"no_new_privs":true,"enforced":{"fs":true,"net":true,"unix_socket":false,"scope":false},"not_enforced":["unix_socket","scope"],` +
	`"unix_socket_control":"file permissions","tcp_connect_ports":[],"extra_files":["/dev/null","/dev/urandom"],"mptcp":"unavailable"},` +
	`"privileged":{"enabled":true,"max_tier":"operator"}}`

// privSummary is a priv_policy answer; packages and power are the
// policy's broad uses, and broadCommand adds a unit: broad command.
func privSummary(sha string, updateIndex bool, power []string, broadCommand bool) string {
	cmds := `{"id":"app-check","tier":"read","unit":"core","description":"Check the application","templates":[["--check"]],"root_equivalent":false,"capabilities":[],"reads_private_keys":false}`
	if broadCommand {
		cmds += `,{"id":"app-renew","tier":"operator","unit":"broad","description":"Renew","templates":[["--all"]],"root_equivalent":false,"capabilities":[],"reads_private_keys":false}`
	}
	pw, _ := json.Marshal(power)
	if power == nil {
		pw = []byte("[]")
	}
	return `{"policy_sha256":"` + sha + `","max_tier":"operator",` +
		`"limits":{"max_read_bytes":1048576,"max_write_bytes":1048576,"max_output_bytes":1048576,"default_timeout_s":60,"max_timeout_s":900,"max_delete_entries":1000,"max_memory_mb":1024},` +
		`"roots":{"read":["/etc/example-app"],"write":["/etc/example-app"],"persistence":[]},"deny_patterns":1,` +
		`"owners":{"users":["root"],"groups":["root"]},"modes_max":"0755","backups_keep":10,"backups_max_store_bytes":1073741824,` +
		`"commands":[` + cmds + `],` +
		fmt.Sprintf(`"packages":{"enabled":%t,"install":[],"remove":[],"allow_update_index":%t,"allow_upgrade":false,"allow_recover":false},`, updateIndex, updateIndex) +
		`"power":{"allowed":` + string(pw) + `},"ops":[{"op":"priv_policy","tier":"read","unit":"core"}],"findings":[]}`
}

// doctorGate is a gate with privileged forwarding: priv_policy answers from
// the core unit, the broad previews from the broad unit. codes makes an op
// answer with that error code instead; helper self-check codes carry no id
// and no helper block, as the real helper's do.
type doctorGate struct {
	mu      sync.Mutex
	summary string
	codes   map[string]string
	reqs    []protocol.Request
}

func (g *doctorGate) exec(_ context.Context, s *sshtest.Session) uint32 {
	req, err := protocol.DecodeRequest(s.Stdin)
	if err != nil {
		return 1
	}
	g.mu.Lock()
	g.reqs = append(g.reqs, *req)
	code, summary := g.codes[req.Op], g.summary
	g.mu.Unlock()
	gate := `"gate":{"version":"0.1.0","principal":"admin-key","policy_sha256":"ab12","max_tier":"operator","duration_ms":1}`
	unit := "core"
	if req.Op != protocol.OpPrivPolicy {
		unit = "broad"
	}
	helper := `,"helper":{"version":"0.1.0","principal":"shell-mcp-privd","policy_sha256":"cafe","max_tier":"operator","unit":"` + unit + `","duration_ms":1}`
	if code != "" {
		id := req.ID
		if strings.HasPrefix(code, "helper_") || code == protocol.CodeProtocolMismatch {
			id, helper = "", ""
		}
		_, _ = fmt.Fprintf(s.Stdout, `{"v":2,"id":%q,"ok":false,"error":{"code":%q,"message":"refused by the fixture"},"warnings":[],%s%s}`+"\n", id, code, gate, helper)
		return 0
	}
	data := helloPriv
	switch req.Op {
	case protocol.OpHello:
		helper = ""
	case protocol.OpPrivPolicy:
		data = summary
	case protocol.OpPrivPkgUpdateIndexPreview:
		data = `{"argv":["/usr/bin/apt-get","update"],"policy_sha256":"cafe","preview_sha256":"` + strings.Repeat("a", 64) + `"}`
	case protocol.OpPrivPowerPreview:
		data = `{"action":"reboot","target":"reboot.target","delay_s":60,"policy_sha256":"cafe","preview_sha256":"` + strings.Repeat("b", 64) + `"}`
	default:
		data = `{}`
	}
	_, _ = fmt.Fprintf(s.Stdout, `{"v":2,"id":%q,"ok":true,"data":%s,"warnings":[],%s%s}`+"\n", req.ID, data, gate, helper)
	return 0
}

func (g *doctorGate) requests() []protocol.Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.reqs)
}

// routeFixture is a /proc/net/route with a default route through gw on
// eth0 (172.30.80.1 is the line 01501EAC on a little-endian machine).
const routeFixture = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t01501EAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
	"eth0\t00501EAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"

// route6Fixture is a /proc/net/ipv6_route with a default route through
// fd00:30::1 and the connected fd00:30::/64.
const route6Fixture = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000030000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" +
	"fd000030000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"

// fixtureEnv is a container on 172.30.80.0/24 and fd00:30::/64 whose
// gateways are 172.30.80.1 and fd00:30::1.
func fixtureEnv(t *testing.T) doctorEnv {
	t.Helper()
	dir := t.TempDir()
	r4, r6 := filepath.Join(dir, "route"), filepath.Join(dir, "ipv6_route")
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the route fixture is little-endian")
	}
	if err := os.WriteFile(r4, []byte(routeFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r6, []byte(route6Fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return doctorEnv{
		routeFile: r4, route6File: r6, now: time.Now,
		interfaceAddrs: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8"), netip.MustParsePrefix("172.30.80.10/24"), netip.MustParsePrefix("fd00:30::10/64")}, nil
		},
	}
}

type doctorRowOut struct {
	Status    string `json:"status"`
	Component string `json:"component"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix"`
}

type doctorOut struct {
	OK   bool           `json:"ok"`
	Rows []doctorRowOut `json:"rows"`
}

func (o *doctorOut) row(t *testing.T, component string) doctorRowOut {
	t.Helper()
	for _, r := range o.Rows {
		if r.Component == component {
			return r
		}
	}
	t.Fatalf("no row %q in %+v", component, o.Rows)
	return doctorRowOut{}
}

func (o *doctorOut) has(component string) bool {
	return slices.ContainsFunc(o.Rows, func(r doctorRowOut) bool { return r.Component == component })
}

// runDoctorJSON runs doctor with --json and returns its exit code, the
// parsed report, and stdout and stderr.
func runDoctorJSON(t *testing.T, env map[string]string, de doctorEnv, args ...string) (code int, rep doctorOut, out string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code = runDoctor(t.Context(), append([]string{"--json"}, args...), lookup(env), &stdout, &stderr, de)
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("doctor --json output is not one JSON object: %v\n%s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), testToken) {
		t.Fatal("doctor printed the token")
	}
	return code, rep, stdout.String() + stderr.String()
}

func doctorEnvWithGate(t *testing.T, g *doctorGate) (map[string]string, string) {
	t.Helper()
	env, hk := gateEnv(t, g.exec)
	env["SHELL_MCP_TRUSTED_PROXIES"] = "172.30.80.5"
	return env, sshtest.Pin(hk)
}

func wantRow(t *testing.T, r doctorRowOut, status string, detail ...string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("%s: status %s, want %s: %+v", r.Component, r.Status, status, r)
	}
	for _, d := range detail {
		if !strings.Contains(r.Detail+" "+r.Fix, d) {
			t.Fatalf("%s: %q not in %+v", r.Component, d, r)
		}
	}
}

func TestUsageListsDoctor(t *testing.T) {
	if !strings.Contains(usage, "\n  doctor ") {
		t.Fatal("usage does not list doctor")
	}
}

// TestDoctorHealthy: everything check reports, then the core socket
// (priv_policy) and the broad socket (the index update's preview), each a
// read request; the trusted proxy is a single connected address that is
// not the gateway. Approvals off and no --mcp-url are notes, not failures.
func TestDoctorHealthy(t *testing.T) {
	g := &doctorGate{summary: privSummary("cafe", true, []string{"reboot"}, true)}
	env, pin := doctorEnvWithGate(t, g)
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 0 || !rep.OK {
		t.Fatalf("exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "configuration"), "ok")
	wantRow(t, rep.row(t, "target app-host"), "ok", pin, "0.1.0", "protocol 2", "admin-key", "ab12", "max_tier operator", "required", "applied")
	wantRow(t, rep.row(t, "helper app-host core"), "ok", "0.1.0", "cafe", "core")
	wantRow(t, rep.row(t, "helper app-host broad"), "ok", protocol.OpPrivPkgUpdateIndexPreview, "broad", "WARN")
	wantRow(t, rep.row(t, "trusted proxy 172.30.80.5"), "ok")
	wantRow(t, rep.row(t, "trusted proxies"), "NOTE", "docs/CLIENTS.md §1")
	wantRow(t, rep.row(t, "approval page"), "NOTE")
	wantRow(t, rep.row(t, "mcp endpoint"), "NOTE", "--mcp-url")
	ops := []string{}
	for _, r := range g.requests() {
		if r.Ceiling != "read" {
			t.Fatalf("%s sent at ceiling %q", r.Op, r.Ceiling)
		}
		ops = append(ops, r.Op)
	}
	if strings.Join(ops, ",") != "hello,priv_policy,priv_pkg_update_index_preview" {
		t.Fatalf("gate requests %v", ops)
	}

	// The same as human lines, then one result line.
	var stdout, stderr bytes.Buffer
	if c := runDoctor(t.Context(), nil, lookup(env), &stdout, &stderr, fixtureEnv(t)); c != 0 {
		t.Fatalf("exit %d: %s%s", c, stdout.String(), stderr.String())
	}
	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if !strings.HasPrefix(lines[0], "ok   configuration") || lines[len(lines)-1] != "doctor: ok" {
		t.Fatalf("human output:\n%s", stdout.String())
	}
}

// TestDoctorHelperRemedies: each helper code names the component and the
// step that fixes it (handoff §4.E), and fails the run.
func TestDoctorHelperRemedies(t *testing.T) {
	for _, c := range []struct{ code, fix string }{
		{protocol.CodeHelperUnavailable, "shell-mcp-privd install"},
		{protocol.CodeHelperRefused, "client_uid"},
		{protocol.CodeHelperPolicyMismatch, "--accept"},
		{protocol.CodeProtocolMismatch, "README.md, Upgrading"},
	} {
		g := &doctorGate{summary: privSummary("cafe", true, nil, false), codes: map[string]string{protocol.OpPrivPolicy: c.code}}
		env, _ := doctorEnvWithGate(t, g)
		code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
		if code != 1 || rep.OK {
			t.Fatalf("%s: exit %d: %s", c.code, code, out)
		}
		wantRow(t, rep.row(t, "helper app-host core"), "FAIL", c.code, c.fix, "docs/TARGET-SETUP.md §12.3")
		// Without the summary the broad socket's operation is unknown.
		wantRow(t, rep.row(t, "helper app-host broad"), "NOTE", "not probed")
	}
}

// TestDoctorBroadProbes: the index update's preview, else the power
// preview, else not probed, with what to run on the target; a helper code
// on the broad socket fails with its remedy.
func TestDoctorBroadProbes(t *testing.T) {
	g := &doctorGate{summary: privSummary("cafe", false, []string{"poweroff"}, false)}
	env, _ := doctorEnvWithGate(t, g)
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 0 {
		t.Fatalf("power: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "helper app-host broad"), "ok", protocol.OpPrivPowerPreview, "poweroff")
	if last := g.requests()[len(g.requests())-1]; last.Op != protocol.OpPrivPowerPreview || !strings.Contains(string(last.Args), `"poweroff"`) {
		t.Fatalf("last request %s %s", last.Op, last.Args)
	}

	g = &doctorGate{summary: privSummary("cafe", false, nil, true)}
	env, _ = doctorEnvWithGate(t, g)
	code, rep, out = runDoctorJSON(t, env, fixtureEnv(t))
	if code != 0 {
		t.Fatalf("broad commands only: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "helper app-host broad"), "NOTE", "not probed", "systemctl status shell-mcp-privd-broad.socket")
	if n := len(g.requests()); n != 2 {
		t.Fatalf("broad commands only: %d requests, want hello and priv_policy", n)
	}

	g = &doctorGate{summary: privSummary("cafe", false, nil, false)}
	env, _ = doctorEnvWithGate(t, g)
	if code, rep, out = runDoctorJSON(t, env, fixtureEnv(t)); code != 0 {
		t.Fatalf("no broad unit: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "helper app-host broad"), "NOTE", "no broad unit")

	g = &doctorGate{summary: privSummary("cafe", true, nil, false), codes: map[string]string{protocol.OpPrivPkgUpdateIndexPreview: protocol.CodeHelperUnavailable}}
	env, _ = doctorEnvWithGate(t, g)
	code, rep, out = runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 {
		t.Fatalf("broad socket down: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "helper app-host broad"), "FAIL", protocol.CodeHelperUnavailable, "shell-mcp-privd install")
}

// TestDoctorNoForwarding: a gate policy without privileged forwarding gets
// no helper probe.
func TestDoctorNoForwarding(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "helper app-host"), "NOTE", "privileged forwarding is off")
	if rep.has("helper app-host core") {
		t.Fatalf("probed a helper the gate does not forward to: %s", out)
	}
}

// TestDoctorTargetFailures: the failing component and the step that
// fixes it, for a wrong pin, a key the target does not accept, and a gate
// that is not installed (the forced command exits without an answer).
func TestDoctorTargetFailures(t *testing.T) {
	g := &doctorGate{summary: privSummary("cafe", true, nil, false)}
	env, _ := doctorEnvWithGate(t, g)
	env["SHELL_MCP_TARGET_HOST_KEYS"] = sshtest.Pin(sshtest.Ed25519(t))
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 {
		t.Fatalf("wrong pin: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "target app-host"), "FAIL", "host_key_mismatch", "shell-mcp-gate host-key", "docs/TARGET-SETUP.md §12.2")
	if rep.has("helper app-host core") {
		t.Fatal("probed the helper of a target that failed")
	}

	other, _ := testEnv(t)
	env, _ = doctorEnvWithGate(t, g)
	env["SHELL_MCP_SSH_KEY"] = other["SHELL_MCP_SSH_KEY"]
	code, rep, out = runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 {
		t.Fatalf("key not accepted: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "target app-host"), "FAIL", "auth_failed_ssh", "shell-mcp-gate install", "docs/TARGET-SETUP.md §12.1")

	env, _ = gateEnv(t, func(context.Context, *sshtest.Session) uint32 { return 127 })
	code, rep, out = runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 {
		t.Fatalf("gate missing: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "target app-host"), "FAIL", "gate_unavailable", "/usr/local/bin/shell-mcp-gate", "docs/TARGET-SETUP.md §3")
}

// TestDoctorTrustedProxies: the static check (handoff §4.E, CLIENTS §1):
// the gateway, or a prefix holding it, fails; a prefix or an address on no
// connected network warns; a single connected address is ok.
func TestDoctorTrustedProxies(t *testing.T) {
	for _, c := range []struct {
		list   string
		rows   map[string]string
		code   int
		detail string
	}{
		{"172.30.80.5", map[string]string{"trusted proxy 172.30.80.5": "ok"}, 0, ""},
		{"172.30.80.1", map[string]string{"trusted proxy 172.30.80.1": "FAIL"}, 1, "gateway"},
		{"172.30.80.0/24", map[string]string{"trusted proxy 172.30.80.0/24": "FAIL"}, 1, "gateway"},
		{"172.30.80.4/30", map[string]string{"trusted proxy 172.30.80.4/30": "WARN"}, 0, "single address"},
		{"198.51.100.7", map[string]string{"trusted proxy 198.51.100.7": "WARN"}, 0, "not on a network"},
		{"fd00:30::1", map[string]string{"trusted proxy fd00:30::1": "FAIL"}, 1, "gateway"},
		{"172.30.80.5,172.30.80.1", map[string]string{"trusted proxy 172.30.80.5": "ok", "trusted proxy 172.30.80.1": "FAIL"}, 1, "gateway"},
	} {
		g := &doctorGate{summary: privSummary("cafe", true, nil, false)}
		env, _ := doctorEnvWithGate(t, g)
		env["SHELL_MCP_TRUSTED_PROXIES"] = c.list
		code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
		if code != c.code {
			t.Fatalf("%s: exit %d, want %d: %s", c.list, code, c.code, out)
		}
		for comp, status := range c.rows {
			r := rep.row(t, comp)
			wantRow(t, r, status)
			if status != "ok" && (!strings.Contains(r.Detail, c.detail) || !strings.Contains(r.Fix, "docs/CLIENTS.md §1")) {
				t.Fatalf("%s: %+v", c.list, r)
			}
		}
	}

	env, _ := doctorEnvWithGate(t, &doctorGate{summary: privSummary("cafe", false, nil, false)})
	delete(env, "SHELL_MCP_TRUSTED_PROXIES")
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 0 {
		t.Fatalf("no trusted proxy: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "trusted proxies"), "NOTE", "never believed")

	// The routing table cannot be read: the gateway is unknown, which is
	// said, not guessed.
	de := fixtureEnv(t)
	de.routeFile = filepath.Join(t.TempDir(), "absent")
	env, _ = doctorEnvWithGate(t, &doctorGate{summary: privSummary("cafe", false, nil, false)})
	if code, rep, out = runDoctorJSON(t, env, de); code != 1 {
		t.Fatalf("no routing table: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "trusted proxy 172.30.80.5"), "FAIL", "routing table")
}

func TestParseRoute(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the fixture is little-endian")
	}
	got, err := parseRoute([]byte(routeFixture))
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("172.30.80.1") {
		t.Fatalf("gateways %v, error %v", got, err)
	}
	for _, bad := range []string{
		"",
		"Iface\tDestination\tGateway\tFlags\neth0\t00000000\tXYZ\t0003\n",
		"Iface\tDestination\tGateway\tFlags\neth0\t00000000\t01501EAC\n",
		"Iface\tDestination\tGateway\tFlags\neth0\t00000000\t01501EAC\tzz\n",
	} {
		if _, err := parseRoute([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// A header alone: no route, no gateway, no error.
	if got, err := parseRoute([]byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n")); err != nil || len(got) != 0 {
		t.Fatalf("header only: %v %v", got, err)
	}
}

func TestParseIPv6Route(t *testing.T) {
	got, err := parseIPv6Route([]byte(route6Fixture))
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("fd00:30::1") {
		t.Fatalf("gateways %v, error %v", got, err)
	}
	for _, bad := range []string{
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd00003000000000000000000000000 00000400 00000001 00000000 00000003 eth0\n",
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000030000000000000000000000001 00000400 00000001 00000000 0000000g eth0\n",
		"short line\n",
	} {
		if _, err := parseIPv6Route([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if got, err := parseIPv6Route(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func FuzzParseRoute(f *testing.F) {
	f.Add([]byte(routeFixture))
	f.Add([]byte("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t01501EAC\t0003\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseRoute(b)
		for _, a := range got {
			if err != nil || !a.Is4() {
				t.Fatalf("gateway %v with error %v", a, err)
			}
		}
	})
}

func FuzzParseIPv6Route(f *testing.F) {
	f.Add([]byte(route6Fixture))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseIPv6Route(b)
		for _, a := range got {
			if err != nil || !a.Is6() || a.IsUnspecified() {
				t.Fatalf("gateway %v with error %v", a, err)
			}
		}
	})
}

// --- HTTP probes --------------------------------------------------------------

// pageHeaders are the approval page's own (internal/approval/page).
func pageHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
}

// httpProbe is a TLS server recording each request; caFile holds its
// certificate.
type httpProbe struct {
	srv    *httptest.Server
	caFile string
	mu     sync.Mutex
	reqs   []*http.Request
}

func newHTTPProbe(t *testing.T, h http.HandlerFunc) *httpProbe {
	t.Helper()
	p := &httpProbe{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.reqs = append(p.reqs, r.Clone(context.Background()))
		p.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(p.srv.Close)
	p.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *httpProbe) requests() []*http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reqs)
}

// approvalEnv turns on web approvals with the page at origin.
func approvalEnv(t *testing.T, env map[string]string, origin string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "approvers")
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	if err := approvers.Add(file, "alice", seed, false); err != nil {
		t.Fatal(err)
	}
	env["SHELL_MCP_APPROVAL_METHOD"] = "web"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = origin
	env["SHELL_MCP_APPROVERS_FILE"] = file
}

// TestDoctorApprovalPage: GET of the public URL, no redirect followed, the
// certificate checked against --ca-file, and the page told from another
// service by its own headers (handoff §4.E; a 403 without them is the
// proxy refusing this container, decided in S8-4).
func TestDoctorApprovalPage(t *testing.T) {
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		noCA    bool
		status  string
		detail  []string
	}{
		{"the page", func(w http.ResponseWriter, _ *http.Request) { pageHeaders(w.Header()); _, _ = io.WriteString(w, "page") }, false, "ok", []string{"certificate", "days"}},
		{"another service", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello") }, false, "FAIL", []string{"another service"}},
		{"the proxy refuses this container", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }, false, "WARN", []string{"refused this container", "LAN or VPN"}},
		{"the page refuses the proxy", func(w http.ResponseWriter, _ *http.Request) {
			pageHeaders(w.Header())
			w.WriteHeader(http.StatusForbidden)
		}, false, "FAIL", []string{"SHELL_MCP_TRUSTED_PROXIES"}},
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				t.Error("doctor followed a redirect")
			}
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, false, "FAIL", []string{"redirect", "/elsewhere"}},
		{"an untrusted certificate", func(w http.ResponseWriter, _ *http.Request) { pageHeaders(w.Header()) }, true, "FAIL", []string{"certificate"}},
	} {
		p := newHTTPProbe(t, c.handler)
		env, _ := gateEnv(t, fakeGate)
		approvalEnv(t, env, p.srv.URL)
		args := []string{"--ca-file", p.caFile}
		if c.noCA {
			args = nil
		}
		code, rep, out := runDoctorJSON(t, env, fixtureEnv(t), args...)
		wantRow(t, rep.row(t, "approval page"), c.status, c.detail...)
		if (code == 1) != (c.status == "FAIL") {
			t.Fatalf("%s: exit %d: %s", c.name, code, out)
		}
		for _, r := range p.requests() {
			if r.Method != http.MethodGet || r.URL.Path != "/" || r.Header.Get("Authorization") != "" {
				t.Fatalf("%s: request %s %s auth %q", c.name, r.Method, r.URL.Path, r.Header.Get("Authorization"))
			}
		}
		if rep.row(t, "approval page reach").Status != "NOTE" {
			t.Fatalf("%s: no note that reachability from outside is not shown", c.name)
		}
	}

	// Unreachable.
	env, _ := gateEnv(t, fakeGate)
	approvalEnv(t, env, fmt.Sprintf("https://127.0.0.1:%d", closedPort(t)))
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 {
		t.Fatalf("unreachable: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "approval page"), "FAIL", "unreachable", "deploy/caddy/README.md")
}

// TestDoctorMCPEndpoint: one POST without a token must answer 401 with the
// server's challenge (ARCHITECTURE §3: it does not count toward the
// lockout); 421 names SHELL_MCP_ALLOWED_HOSTS.
func TestDoctorMCPEndpoint(t *testing.T) {
	challenge := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="shell-mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
	}
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		status  string
		detail  []string
	}{
		{"401", challenge, "ok", []string{"401"}},
		{"401 without the challenge", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, "FAIL", []string{"WWW-Authenticate"}},
		{"421", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMisdirectedRequest) }, "FAIL", []string{"SHELL_MCP_ALLOWED_HOSTS"}},
		{"403", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }, "WARN", []string{"refused this container"}},
		{"200", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }, "FAIL", []string{"without a token"}},
	} {
		p := newHTTPProbe(t, c.handler)
		env, _ := gateEnv(t, fakeGate)
		code, rep, out := runDoctorJSON(t, env, fixtureEnv(t), "--mcp-url", p.srv.URL+"/mcp", "--ca-file", p.caFile)
		wantRow(t, rep.row(t, "mcp endpoint"), c.status, c.detail...)
		if (code == 1) != (c.status == "FAIL") {
			t.Fatalf("%s: exit %d: %s", c.name, code, out)
		}
		reqs := p.requests()
		if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].URL.Path != "/mcp" || reqs[0].Header.Get("Authorization") != "" {
			t.Fatalf("%s: requests %v", c.name, reqs)
		}
	}
	for _, bad := range []string{"ftp://mcp.example.test/mcp", "https://user:pw@mcp.example.test/mcp", "mcp.example.test/mcp", "https:///mcp"} {
		env, _ := gateEnv(t, fakeGate)
		var stdout, stderr bytes.Buffer
		if code := runDoctor(t.Context(), []string{"--mcp-url", bad}, lookup(env), &stdout, &stderr, fixtureEnv(t)); code != 2 {
			t.Fatalf("--mcp-url %q: exit %d", bad, code)
		}
	}
	env, _ := gateEnv(t, fakeGate)
	var stdout, stderr bytes.Buffer
	if code := runDoctor(t.Context(), []string{"--ca-file", filepath.Join(t.TempDir(), "absent.pem")}, lookup(env), &stdout, &stderr, fixtureEnv(t)); code != 2 {
		t.Fatalf("unreadable --ca-file: exit %d", code)
	}
}

// TestDoctorSecretFiles: a secret file with group or other access fails
// here (the server only warns at start), and its owner is reported.
func TestDoctorSecretFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file modes")
	}
	env, _ := gateEnv(t, fakeGate)
	file := filepath.Join(t.TempDir(), "mcp_token")
	if err := os.WriteFile(file, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	delete(env, "SHELL_MCP_TOKEN")
	env["SHELL_MCP_TOKEN_FILE"] = file
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "secret SHELL_MCP_TOKEN_FILE"), "ok", "0600", fmt.Sprint(os.Geteuid()))

	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	code, rep, out = runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 {
		t.Fatalf("0644: exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "secret SHELL_MCP_TOKEN_FILE"), "FAIL", "0644", "chmod 0600", "deploy/README.md")
}

// TestDoctorConfigInvalid: what serve would refuse is a FAIL naming the
// variable, and nothing else runs.
func TestDoctorConfigInvalid(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	delete(env, "SHELL_MCP_TOKEN")
	env["SHELL_MCP_TOKEN_FILE"] = filepath.Join(t.TempDir(), "absent")
	code, rep, out := runDoctorJSON(t, env, fixtureEnv(t))
	if code != 1 || rep.OK {
		t.Fatalf("exit %d: %s", code, out)
	}
	wantRow(t, rep.row(t, "configuration"), "FAIL", "SHELL_MCP_TOKEN_FILE", "deploy/README.md", "docs/ARCHITECTURE.md §5")
	if len(rep.Rows) != 1 {
		t.Fatalf("rows after a refused configuration: %+v", rep.Rows)
	}
}

func TestDoctorUsage(t *testing.T) {
	env, _ := gateEnv(t, fakeGate)
	for _, args := range [][]string{{"extra"}, {"--unknown"}} {
		var stdout, stderr bytes.Buffer
		if code := runDoctor(t.Context(), args, lookup(env), &stdout, &stderr, fixtureEnv(t)); code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}
