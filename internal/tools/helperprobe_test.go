package tools

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/gateclient"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The helper probes of `shell-mcp doctor` (handoff §4.E). Every value
// below is an invented fixture.

func probeDeps(t *testing.T, g *recordingGate) *Deps {
	t.Helper()
	tg, c := sshTarget(t, g.exec)
	return &Deps{
		Targets: []config.Target{tg},
		Opener:  func(string) (gateclient.Opener, bool) { return c, true },
		Gate:    gateclient.New(gateclient.Options{}), DefaultTimeout: 10 * time.Second,
	}
}

// TestProbeHelperCore: one priv_policy request at ceiling read, reported
// with the helper block's version, policy hash and unit, and the summary.
func TestProbeHelperCore(t *testing.T) {
	g := newRecordingGate(map[string]gateReply{"priv_policy": {data: fakePrivPolicy("cafe")}})
	p, e := ProbeHelper(t.Context(), probeDeps(t, g), "app-host")
	if e != nil || p == nil {
		t.Fatalf("probe %+v, error %v", p, e)
	}
	if p.Op != protocol.OpPrivPolicy || p.Version != "0.1.0" || p.PolicySHA256 != "cafe" || p.Unit != "core" ||
		p.Summary == nil || !p.Summary.Packages.AllowUpdateIndex || p.Refusal != nil {
		t.Fatalf("probe %+v", p)
	}
	reqs := g.requests()
	if len(reqs) != 1 || reqs[0].Op != protocol.OpPrivPolicy || reqs[0].Ceiling != "read" {
		t.Fatalf("requests %+v", reqs)
	}
}

// TestProbeHelperRefusals: every refusal comes back with its code, also
// the helper's self-check codes, which carry no request id.
func TestProbeHelperRefusals(t *testing.T) {
	for _, r := range []gateReply{
		{code: protocol.CodeHelperUnavailable, msg: "the privileged helper's socket is not listening"},
		{code: protocol.CodeHelperRefused, msg: "the helper refused the peer"},
		{code: protocol.CodeHelperPolicyMismatch, msg: "the policy's SHA-256 is not the units'", noID: true, noHelper: true},
		{code: protocol.CodeProtocolMismatch, msg: "the helper speaks protocol 1", noHelper: true},
		{code: protocol.CodePrivilegedDisabled, msg: "privileged operations are disabled", noHelper: true},
	} {
		g := newRecordingGate(map[string]gateReply{"priv_policy": r})
		p, e := ProbeHelper(t.Context(), probeDeps(t, g), "app-host")
		if e == nil || e.Code != r.code || p != nil {
			t.Fatalf("%s: probe %+v, error %v", r.code, p, e)
		}
	}
}

// TestProbeHelperHashMismatch: a summary whose hash is not the helper
// block's is not reported as the helper's.
func TestProbeHelperHashMismatch(t *testing.T) {
	g := newRecordingGate(map[string]gateReply{"priv_policy": {data: fakePrivPolicy("beef")}})
	if p, e := ProbeHelper(t.Context(), probeDeps(t, g), "app-host"); e == nil || p != nil {
		t.Fatalf("probe %+v, error %v", p, e)
	}
}

func summaryWith(f func(*PrivPolicy)) *PrivPolicy {
	p := &PrivPolicy{Commands: []PrivCommand{{ID: "app-check", Tier: "read", Unit: "core"}}}
	f(p)
	return p
}

// TestBroadProbeOp: the index update's preview first, then a power
// action's, else not probed (handoff §7 Q9, as decided in S8-4: the text
// says which two operations doctor uses), or no broad unit at all.
func TestBroadProbeOp(t *testing.T) {
	for _, c := range []struct {
		name, op, args, reason string
		p                      *PrivPolicy
	}{
		{"update index", protocol.OpPrivPkgUpdateIndexPreview, `{}`, "", summaryWith(func(p *PrivPolicy) {
			p.Packages = PrivPackages{Enabled: true, Install: []string{"example-hello"}, AllowUpdateIndex: true}
			p.Power.Allowed = []string{"reboot"}
		})},
		{"power", protocol.OpPrivPowerPreview, `{"action":"poweroff"}`, "", summaryWith(func(p *PrivPolicy) {
			p.Power.Allowed = []string{"poweroff"}
		})},
		{"broad commands only", "", "", "not probed: doctor uses only the index-update or power preview on it, and this policy allows neither", summaryWith(func(p *PrivPolicy) {
			p.Commands = append(p.Commands, PrivCommand{ID: "app-renew", Tier: "operator", Unit: "broad"})
		})},
		{"packages without the index update", "", "", "not probed: doctor uses only the index-update or power preview on it, and this policy allows neither", summaryWith(func(p *PrivPolicy) {
			p.Packages = PrivPackages{Enabled: true, Install: []string{"example-hello"}}
		})},
		{"no broad unit", "", "", "this policy uses no broad unit", summaryWith(func(*PrivPolicy) {})},
	} {
		op, args, reason := BroadProbeOp(c.p)
		got := ""
		if args != nil {
			b, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			got = string(b)
		}
		if op != c.op || got != c.args || !strings.Contains(reason, c.reason) || (c.reason == "") != (reason == "") {
			t.Fatalf("%s: op %q args %s reason %q", c.name, op, got, reason)
		}
	}
}

// TestProbeHelperBroad: the broad socket's answer must come from the broad
// unit; the helper's own refusal of the preview still shows the socket
// works; a helper code or the core unit's answer is an error.
func TestProbeHelperBroad(t *testing.T) {
	op := protocol.OpPrivPkgUpdateIndexPreview
	ok := `{"argv":["/usr/bin/apt-get","update"],"policy_sha256":"cafe","preview_sha256":"` + strings.Repeat("a", 64) + `"}`
	g := newRecordingGate(map[string]gateReply{op: {data: ok, unit: "broad"}})
	p, e := ProbeHelperBroad(t.Context(), probeDeps(t, g), "app-host", op, noArgsWire{})
	if e != nil || p == nil || p.Op != op || p.Unit != "broad" || p.PolicySHA256 != "cafe" || p.Refusal != nil {
		t.Fatalf("probe %+v, error %v", p, e)
	}
	if reqs := g.requests(); len(reqs) != 1 || reqs[0].Op != op || reqs[0].Ceiling != "read" {
		t.Fatalf("requests %+v", reqs)
	}

	g = newRecordingGate(map[string]gateReply{op: {code: "exec_failed", msg: "the dpkg frontend lock is held", unit: "broad"}})
	p, e = ProbeHelperBroad(t.Context(), probeDeps(t, g), "app-host", op, noArgsWire{})
	if e != nil || p == nil || p.Unit != "broad" || p.Refusal == nil || p.Refusal.Code != "exec_failed" {
		t.Fatalf("refused by the broad helper: probe %+v, error %v", p, e)
	}

	for _, r := range []gateReply{
		{code: protocol.CodeHelperUnavailable, msg: "the broad socket is not listening", noHelper: true},
		{code: protocol.CodeHelperPolicyMismatch, msg: "units not regenerated", noID: true, noHelper: true},
		{data: ok, unit: "core"},
		{data: ok, noHelper: true},
	} {
		g = newRecordingGate(map[string]gateReply{op: r})
		if p, e = ProbeHelperBroad(t.Context(), probeDeps(t, g), "app-host", op, noArgsWire{}); e == nil || p != nil {
			t.Fatalf("%+v: probe %+v, error %v", r, p, e)
		}
		if r.code != "" && e.Code != r.code {
			t.Fatalf("%+v: code %s", r, e.Code)
		}
	}
}
