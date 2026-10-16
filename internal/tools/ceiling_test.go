package tools

import (
	"slices"
	"strings"
	"testing"
)

// Every gate request carries the calling tool's registered tier as its
// ceiling (ARCHITECTURE §4.1), so the gate and the helper refuse anything
// above it in the same check that applies their max_tier.

// ceilingCallArgs are valid arguments for every registered tool. A tool
// registered without an entry fails TestEveryToolSendsItsTierAsCeiling, so
// a new tool cannot skip it.
var ceilingCallArgs = map[string]map[string]any{
	"shell_get_policy":          {},
	"shell_get_system_info":     {},
	"shell_get_disk_usage":      {},
	"shell_list_processes":      {},
	"shell_get_service_status":  {"unit": "example-app.service"},
	"shell_list_services":       {},
	"shell_get_journal":         {"unit": "example-app.service"},
	"shell_list_directory":      {"path": "/srv/app"},
	"shell_stat_path":           {"path": "/srv/app/current"},
	"shell_read_file":           {"path": "/srv/app/config.yaml"},
	"shell_find_files":          {"root": "/srv/app"},
	"shell_inspect_certificate": {"path": "/srv/app/tls/cert.pem"},
	"shell_get_git_status":      {"repo": "/srv/app/deploy"},
	"shell_get_git_log":         {"repo": "/srv/app/deploy"},
	"shell_get_git_diff":        {"repo": "/srv/app/deploy"},
	"shell_run_read_command":    {"command_id": "app-status", "args": []string{"status", "--json"}},
}

// serverOnly are tools that never call a gate.
var serverOnly = []string{"shell_list_targets", "shell_diag_elicit"}

// TestEveryToolSendsItsTierAsCeiling: a table over the registry. Each
// tool's every gate request names exactly the tier it is registered with.
func TestEveryToolSendsItsTierAsCeiling(t *testing.T) {
	replies := allReplies()
	replies["hello"] = gateReply{data: fakeHello}
	g := newRecordingGate(replies)
	h := readHarness(t, g)
	reg, err := Catalogue(h.deps)
	if err != nil {
		t.Fatal(err)
	}
	regs := reg.ToolsForProfile(ProfileAdmin, nil)
	if len(regs) == 0 {
		t.Fatal("empty catalogue")
	}
	for _, r := range regs {
		name := r.Tool.Def.Name
		t.Run(name, func(t *testing.T) {
			before := len(g.requests())
			if slices.Contains(serverOnly, name) {
				return
			}
			args, ok := ceilingCallArgs[name]
			if !ok {
				t.Fatalf("%s has no entry in ceilingCallArgs", name)
			}
			env, _ := h.call(name, args)
			if env["ok"] != true {
				t.Fatalf("envelope %v", env)
			}
			sent := g.requests()[before:]
			if len(sent) == 0 {
				t.Fatal("no gate request was sent")
			}
			for _, q := range sent {
				if q.Ceiling != r.Tier.String() {
					t.Fatalf("%s request carries ceiling %q; the tool is registered at %s", q.Op, q.Ceiling, r.Tier)
				}
			}
		})
	}
}

// TestProbeCeiling: shell-mcp check's hello is a read request.
func TestProbeCeiling(t *testing.T) {
	g := newRecordingGate(map[string]gateReply{"hello": {data: fakeHello}})
	h := readHarness(t, g)
	if _, e := Probe(t.Context(), h.deps, "app-host"); e != nil {
		t.Fatalf("probe: %+v", e)
	}
	reqs := g.requests()
	if len(reqs) != 1 || reqs[0].Op != "hello" || reqs[0].Ceiling != "read" {
		t.Fatalf("probe requests %+v", reqs)
	}
}

// TestRunReadCommandCeiling: the read command sends one exec request with
// ceiling read, and the gate's refusal of an operator command is the
// result. No policy request is made, so there is nothing for a policy edit
// to race.
func TestRunReadCommandCeiling(t *testing.T) {
	replies := allReplies()
	replies["exec"] = gateReply{code: "tier_denied", msg: "command tier operator exceeds the request's ceiling read"}
	g := newRecordingGate(replies)
	h := readHarness(t, g)
	env, _ := h.call("shell_run_read_command", map[string]any{"command_id": "app-restart", "args": []string{"restart"}})
	if errCode(env) != "tier_denied" || !strings.Contains(jsonOf(t, env["error"]), "ceiling read") {
		t.Fatalf("operator command: %v", env)
	}
	reqs := g.requests()
	if len(reqs) != 1 || reqs[0].Op != "exec" || reqs[0].Ceiling != "read" {
		t.Fatalf("requests %+v, want one exec at ceiling read", reqs)
	}
}
