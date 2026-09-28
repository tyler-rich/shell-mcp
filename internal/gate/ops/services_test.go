//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/systemd"
)

// servicesPolicy configures every service feature for invented units.
const servicesPolicy = `version: 1
max_tier: {TIER}
sandbox:
  landlock: best-effort
  system_read_exec: [{BIN}]
limits:
  max_output_bytes: 65536
paths:
  read: [{R}]
services:
  status: ["example-*.service"]
  control:
    units: [example-app.service, example-denied.service, example-challenge.service, example-challenge2.service, example-broken.service]
    verbs: [restart, reload]
journal:
  units: ["example-*.service"]
  max_lines: 100
redact:
  patterns: ['api_key=\S+']
`

// fakeSystemd installs the fake systemctl and journalctl through the test
// constructor and returns a function that reads (and clears) the argv log.
func (f *fixture) fakeSystemd(t *testing.T, tier string) func() [][]string {
	t.Helper()
	logp := filepath.Join(f.dir, "fakesys.log")
	f.opts.Systemctl = gatetest.BuildFakeSys(t, f.bin, "systemctl", logp)
	f.opts.Journalctl = gatetest.BuildFakeSys(t, f.bin, "journalctl", logp)
	f.rawPolicy(strings.Replace(servicesPolicy, "{TIER}", tier, 1))
	return func() [][]string {
		t.Helper()
		b, _ := os.ReadFile(logp) //nolint:gosec // G304: the test's own log
		_ = os.Remove(logp)
		var out [][]string
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l == "" {
				continue
			}
			var argv []string
			if err := json.Unmarshal([]byte(l), &argv); err != nil {
				t.Fatalf("log line %q", l)
			}
			out = append(out, argv)
		}
		return out
	}
}

type statusData struct {
	Unit          string  `json:"unit"`
	Description   string  `json:"description"`
	LoadState     string  `json:"load_state"`
	ActiveState   string  `json:"active_state"`
	SubState      string  `json:"sub_state"`
	UnitFileState string  `json:"unit_file_state"`
	MainPID       *int64  `json:"main_pid"`
	MemoryBytes   *uint64 `json:"memory_bytes"`
	NRestarts     *int64  `json:"n_restarts"`
	ActiveSince   string  `json:"active_since"`
	Result        string  `json:"result"`
}

func TestServiceStatus(t *testing.T) {
	f := newFixture(t, "read")
	argv := f.fakeSystemd(t, "read")
	var d statusData
	f.ok("service_status", m{"unit": "example-app.service"}, &d)
	want := []string{"show", "--no-pager", "-p", strings.Join(systemd.ShowProperties, ","), "--", "example-app.service"}
	if got := argv(); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("argv %q, want %q", got, want)
	}
	if d.Unit != "example-app.service" || d.LoadState != "loaded" || d.ActiveState != "active" || d.SubState != "running" ||
		d.UnitFileState != "enabled" || d.MainPID == nil || *d.MainPID != 4242 || d.NRestarts == nil || *d.NRestarts != 3 ||
		d.MemoryBytes != nil || d.ActiveSince == "" || d.Result != "success" {
		t.Fatalf("status %+v", d)
	}
	if strings.Contains(d.Description, "abc123") {
		t.Fatalf("description not redacted: %q", d.Description)
	}
	f.ok("service_status", m{"unit": "example-missing.service"}, &d)
	if d.LoadState != "not-found" {
		t.Fatalf("missing unit %+v", d)
	}
	f.fail("service_status", m{"unit": "other.service"}, "policy_denied")
	for _, u := range []string{"example-*.service", "-p.service", "example-app", "", "4242", "example-app.service\n"} {
		f.fail("service_status", m{"unit": u}, "bad_request")
	}
	argv()
	f.fail("service_status", m{"unit": "example-badout.service"}, "exec_failed")
	f.fail("service_status", m{"unit": "example-extra.service"}, "exec_failed")
	// Without services.status nothing is visible.
	f.rawPolicy("version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\n")
	f.fail("service_status", m{"unit": "example-app.service"}, "policy_denied")
	f.fail("service_list", m{}, "policy_denied")
}

func TestServiceList(t *testing.T) {
	f := newFixture(t, "read")
	argv := f.fakeSystemd(t, "read")
	var d struct {
		Units []struct {
			Unit   string `json:"unit"`
			Active string `json:"active"`
		} `json:"units"`
		Truncated bool `json:"truncated"`
	}
	f.ok("service_list", m{}, &d)
	if got := argv(); len(got) != 1 || !slices.Equal(got[0], []string{"list-units", "--no-pager", "--plain", "--output=json", "--type=service"}) {
		t.Fatalf("argv %q", got)
	}
	if len(d.Units) != 2 || d.Units[0].Unit != "example-app.service" || d.Units[1].Unit != "example-worker.service" {
		t.Fatalf("units outside services.status listed, or order changed: %+v", d)
	}
	f.ok("service_list", m{"failed_only": true}, &d)
	if got := argv(); len(got) != 1 || !slices.Equal(got[0], []string{"list-units", "--no-pager", "--plain", "--output=json", "--type=service", "--state=failed"}) {
		t.Fatalf("argv %q", got)
	}
	if len(d.Units) != 1 || d.Units[0].Active != "failed" {
		t.Fatalf("failed_only %+v", d)
	}
	f.ok("service_list", m{"name_contains": "worker"}, &d)
	if len(d.Units) != 1 {
		t.Fatalf("name_contains %+v", d)
	}
	f.ok("service_list", m{"limit": 1}, &d)
	if len(d.Units) != 1 || !d.Truncated {
		t.Fatalf("limit %+v", d)
	}
	f.fail("service_list", m{"limit": 5001}, "bad_request")
	f.fail("service_list", m{"limit": -1}, "bad_request")
}

var epochArg = regexp.MustCompile(`^@[0-9]{10}$`)

func TestJournal(t *testing.T) {
	f := newFixture(t, "read")
	argv := f.fakeSystemd(t, "read")
	var d struct {
		Unit      string `json:"unit"`
		Output    string `json:"output"`
		Truncated bool   `json:"truncated"`
		Stderr    string `json:"stderr"`
	}
	r := f.ok("journal", m{"unit": "example-app.service", "lines": 5, "since": "-15m", "until": "2099-01-01T00:00:00Z", "priority": "err"}, &d)
	got := argv()
	if len(got) != 1 || len(got[0]) != 13 {
		t.Fatalf("argv %q", got)
	}
	a := got[0]
	if !slices.Equal(a[:5], []string{"--no-pager", "-o", "short-iso", "-n", "5"}) || a[5] != "--since" || !epochArg.MatchString(a[6]) ||
		!slices.Equal(a[7:], []string{"--until", "@4070908800", "-p", "err", "-u", "example-app.service"}) {
		t.Fatalf("argv %q", a)
	}
	if strings.Count(d.Output, "\n") != 5 || strings.Contains(d.Output, "abc123") || d.Unit != "example-app.service" {
		t.Fatalf("journal %+v", d)
	}
	if len(r.Warnings) == 0 || !strings.Contains(strings.Join(r.Warnings, " "), "systemd-journal") {
		t.Fatalf("limited-access hint not reported: %q", r.Warnings)
	}
	// Defaults: lines = min(200, max_lines); no optional flags.
	f.ok("journal", m{"unit": "example-app.service"}, &d)
	if got := argv(); len(got) != 1 || !slices.Equal(got[0], []string{"--no-pager", "-o", "short-iso", "-n", "100", "-u", "example-app.service"}) {
		t.Fatalf("argv %q", got)
	}
	f.fail("journal", m{"unit": "example-app.service", "lines": 101}, "bad_request")
	f.fail("journal", m{"unit": "example-app.service", "lines": -1}, "bad_request")
	f.fail("journal", m{"unit": "other.service"}, "policy_denied")
	f.fail("journal", m{"unit": "example-*.service"}, "bad_request")
	f.fail("journal", m{"unit": "example-app.service", "since": "yesterday"}, "bad_request")
	f.fail("journal", m{"unit": "example-app.service", "since": "-1h", "until": "-2h"}, "bad_request")
	f.fail("journal", m{"unit": "example-app.service", "priority": "error"}, "bad_request")
	f.fail("journal", m{}, "bad_request")
	f.fail("journal", m{"unit": "example-noperm.service"}, "exec_failed")
	if got := argv(); len(got) != 1 {
		t.Fatalf("refused requests must not run journalctl: %q", got)
	}
	f.rawPolicy("version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\n")
	f.fail("journal", m{"unit": "example-app.service"}, "policy_denied")
}

func TestServiceControl(t *testing.T) {
	f := newFixture(t, "operator")
	argv := f.fakeSystemd(t, "operator")
	var d struct {
		Unit   string     `json:"unit"`
		Action string     `json:"action"`
		Status statusData `json:"status"`
	}
	f.ok("service_control", m{"unit": "example-app.service", "action": "restart"}, &d)
	got := argv()
	if len(got) != 2 || !slices.Equal(got[0], []string{"--no-ask-password", "restart", "--", "example-app.service"}) || got[1][0] != "show" {
		t.Fatalf("argv %q", got)
	}
	if d.Unit != "example-app.service" || d.Action != "restart" || d.Status.ActiveState != "active" {
		t.Fatalf("control %+v", d)
	}
	// polkit denials: AccessDenied (exit 4) and a challenge without
	// interaction (exit 1, both systemd wordings).
	for _, u := range []string{"example-denied.service", "example-challenge.service", "example-challenge2.service"} {
		r := f.call("service_control", m{"unit": u, "action": "reload"})
		if r.OK || r.Error.Code != "not_authorized" || !strings.Contains(r.Error.Message, "exit status") || !strings.Contains(r.Error.Message, "polkit") {
			t.Fatalf("%s: %+v", u, r.Error)
		}
	}
	f.fail("service_control", m{"unit": "example-broken.service", "action": "restart"}, "exec_failed")
	argv()
	f.fail("service_control", m{"unit": "example-app.service", "action": "stop"}, "policy_denied")
	f.fail("service_control", m{"unit": "example-worker.service", "action": "restart"}, "policy_denied")
	f.fail("service_control", m{"unit": "example-app.service", "action": "enable"}, "bad_request")
	f.fail("service_control", m{"unit": "example-*.service", "action": "restart"}, "bad_request")
	if got := argv(); len(got) != 0 {
		t.Fatalf("refused requests ran systemctl: %q", got)
	}
	f.fakeSystemd(t, "read")
	f.fail("service_control", m{"unit": "example-app.service", "action": "restart"}, "tier_denied")
}
