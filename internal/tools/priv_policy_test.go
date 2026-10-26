package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/sshx"
)

// shell_get_policy's privileged.policy (handoff P-8, S4c-9): the helper's
// priv_policy summary, requested in the admin profile only, when the gate
// forwards privileged operations. Every value below is an invented fixture.

const fakeHelloPriv = `{"gate_version":"0.1.0","protocol":1,"principal":"readonly-key","policy_sha256":"ab12","max_tier":"destructive",
"ops":["hello","policy","read_file"],"sandbox":{"mode":"required","kernel_abi":7,"effective_abi":7,"required_min_abi":4,"applied":true,
"no_new_privs":true,"enforced":{"fs":true,"net":true,"unix_socket":false,"scope":false},"not_enforced":["unix_socket","scope"],
"unix_socket_control":"file permissions","tcp_connect_ports":[],"extra_files":["/dev/null","/dev/urandom"],"mptcp":"unavailable (seccomp)"},
"privileged":{"enabled":true,"max_tier":"destructive"}}`

func fakePrivPolicy(sha string) string {
	return `{"policy_sha256":"` + sha + `","max_tier":"destructive",
"limits":{"max_read_bytes":1048576,"max_write_bytes":1048576,"max_output_bytes":1048576,"default_timeout_s":60,"max_timeout_s":900,"max_delete_entries":1000,"max_memory_mb":1024},
"roots":{"read":["/var/log/example-app"],"write":["/etc/example-app"],"persistence":["/etc/systemd/system/example-app.service.d"]},
"deny_patterns":2,"owners":{"users":["root","example-app"],"groups":["root","example-app"]},"modes_max":"0755","backups_keep":10,
"backups_max_store_bytes":1073741824,
"commands":[{"id":"app-check","tier":"read","unit":"core","description":"Check the application","templates":[["--check"]],"root_equivalent":false,"capabilities":[]},
{"id":"app-renew","tier":"operator","unit":"broad","description":"Renew the application's certificates","templates":[["--all"]],"root_equivalent":false,"capabilities":[]},
{"id":"pkg-recover","tier":"operator","unit":"broad","description":"","templates":[["--configure","-a"]],"root_equivalent":false,"capabilities":[]}],
"packages":{"enabled":true,"install":["example-hello"],"remove":[],"allow_update_index":true,"allow_upgrade":false},
"power":{"allowed":["reboot"]},
"ops":[{"op":"priv_policy","tier":"read","unit":"core"},{"op":"priv_write_file","tier":"operator","unit":"core"},
{"op":"priv_delete","tier":"destructive","unit":"core"},{"op":"priv_exec","tier":"command","unit":"command"},
{"op":"priv_power_cancel","tier":"read","unit":"broad"}],
"findings":[{"command_id":"pkg-recover","category":"package","program":"dpkg","match":"written"}]}`
}

func privPolicyHarness(t *testing.T, profile string, replies map[string]gateReply) (*harness, *recordingGate) {
	t.Helper()
	g := newRecordingGate(replies)
	tg, c := sshTarget(t, g.exec)
	h := newHarnessWith(t, []config.Target{tg}, map[string]*sshx.Client{"app-host": c}, "", func(d *Deps) { d.Principal.Profile = profile })
	return h, g
}

func privPolicyReplies() map[string]gateReply {
	return map[string]gateReply{
		"hello":       {data: fakeHelloPriv},
		"policy":      {data: fakePolicyCommands},
		"priv_policy": {data: fakePrivPolicy("cafe")},
	}
}

func policyData(t *testing.T, env map[string]any) PolicyData {
	t.Helper()
	if env["ok"] != true {
		t.Fatalf("envelope %v", env)
	}
	b, _ := json.Marshal(env["data"])
	var d PolicyData
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestGetPolicyPrivilegedSummary: in the admin profile, with forwarding on,
// shell_get_policy sends priv_policy once at ceiling read and reports the
// summary, both policies' hashes, and which operations and commands need
// approval (D-006: privileged operator and destructive always do).
func TestGetPolicyPrivilegedSummary(t *testing.T) {
	h, g := privPolicyHarness(t, "admin", privPolicyReplies())
	env, _ := h.call("shell_get_policy", map[string]any{"target": "app-host"})
	d := policyData(t, env)
	p := d.Privileged.Policy
	if p == nil {
		t.Fatalf("no privileged.policy: %v", env)
	}
	if !d.Privileged.Enabled || d.Gate.PolicySHA256 != "ab12" || p.PolicySHA256 != "cafe" || p.MaxTier != "destructive" ||
		p.DenyPatterns != 2 || len(p.Roots.Persistence) != 1 || p.ModesMax != "0755" || p.BackupsMaxStoreBytes != 1073741824 || !p.Packages.Enabled ||
		p.Limits.MaxMemoryMB != 1024 {
		t.Fatalf("summary %+v", p)
	}
	approval := map[string]bool{}
	for _, o := range p.Ops {
		approval[o.Op] = o.Approval
	}
	if approval["priv_policy"] || !approval["priv_write_file"] || !approval["priv_delete"] || approval["priv_power_cancel"] || approval["priv_exec"] {
		t.Fatalf("op approvals %v", approval)
	}
	units := map[string]string{}
	for _, c := range p.Commands {
		units[c.ID] = c.Unit
		if c.Approval != (c.Tier != "read") {
			t.Fatalf("command %+v: approval %v", c, c.Approval)
		}
	}
	if units["app-check"] != "core" || units["app-renew"] != "broad" || len(p.Findings) != 1 || p.Findings[0].Program != "dpkg" {
		t.Fatalf("commands %v findings %+v", units, p.Findings)
	}
	n := 0
	for _, q := range g.requests() {
		if q.Op == "priv_policy" {
			n++
			if q.Ceiling != "read" {
				t.Fatalf("priv_policy at ceiling %s", q.Ceiling)
			}
		}
	}
	if n != 1 {
		t.Fatalf("priv_policy sent %d times", n)
	}
}

// TestGetPolicyNoPrivilegedSummary: outside the admin profile, or when the
// gate does not forward privileged operations, nothing is asked of the
// helper and privileged.policy is absent.
func TestGetPolicyNoPrivilegedSummary(t *testing.T) {
	for _, c := range []struct {
		name, profile string
		hello         string
	}{
		{"read-only", "read-only", fakeHelloPriv},
		{"operator", "operator", fakeHelloPriv},
		{"forwarding off", "admin", fakeHello},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := privPolicyReplies()
			r["hello"] = gateReply{data: c.hello}
			h, g := privPolicyHarness(t, c.profile, r)
			env, _ := h.call("shell_get_policy", map[string]any{"target": "app-host"})
			d := policyData(t, env)
			if d.Privileged.Policy != nil || strings.Contains(jsonOf(t, env), `"policy_sha256":"cafe"`) {
				t.Fatalf("privileged.policy present: %v", env)
			}
			for _, op := range g.ops() {
				if strings.HasPrefix(op, "priv_") {
					t.Fatalf("sent %s", op)
				}
			}
		})
	}
}

// TestGetPolicyPrivilegedSummaryFailures: a helper refusal, an answer
// without a helper block, a summary whose hash is not the helper block's,
// or data this server does not know leave the gate policy reported, without
// privileged.policy and with a warning naming why.
func TestGetPolicyPrivilegedSummaryFailures(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply gateReply
		want  string
	}{
		{"helper unavailable", gateReply{code: "helper_unavailable", msg: "the helper socket is not reachable"}, "helper_unavailable"},
		{"no helper block", gateReply{data: fakePrivPolicy("cafe"), noHelper: true}, "helper block"},
		{"hash differs", gateReply{data: fakePrivPolicy("beef")}, "hash"},
		{"unknown field", gateReply{data: strings.Replace(fakePrivPolicy("cafe"), `"max_tier"`, `"surprise":1,"max_tier"`, 1)}, "protocol_mismatch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := privPolicyReplies()
			r["priv_policy"] = c.reply
			h, _ := privPolicyHarness(t, "admin", r)
			env, _ := h.call("shell_get_policy", map[string]any{"target": "app-host"})
			d := policyData(t, env)
			if d.Privileged.Policy != nil || d.Policy.MaxTier != "operator" || !d.Privileged.Enabled {
				t.Fatalf("data %+v", d)
			}
			w, _ := env["warnings"].([]any)
			found := false
			for _, x := range w {
				s, _ := x.(string)
				if strings.Contains(s, "privileged policy summary") && strings.Contains(s, c.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("warnings %v, want one naming %q", w, c.want)
			}
		})
	}
}
