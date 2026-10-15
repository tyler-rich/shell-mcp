//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each instance knows its unit (SHELL_MCP_PRIVD_UNIT) and is authoritative
// for routing: an operation meant for the other unit is refused with
// helper_wrong_unit — never executed — whatever the gate sent where. The
// broad unit takes the package operations, priv_power and the unit: broad
// commands; the core unit takes everything else.
func TestWrongUnitRefusedByCore(t *testing.T) {
	f := newFixture(t, broadUsers())
	f.ok("priv_stat", m{"path": f.read}, nil) // control: a core op in the core unit
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "core"}}, nil)
	f.ok("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "core"}, "unit": "core"}, nil)
	marker := filepath.Join(f.write, "ran")
	for op, args := range map[string]m{
		"priv_pkg_update_index":    {},
		"priv_pkg_install":         {"packages": []string{"example-hello"}},
		"priv_pkg_install_preview": {"packages": []string{"example-hello"}},
		"priv_pkg_upgrade":         {},
		"priv_pkg_upgrade_preview": {},
		"priv_pkg_remove":          {"packages": []string{"example-hello"}},
		"priv_pkg_remove_preview":  {"packages": []string{"example-hello"}},
		"priv_power":               {"action": "reboot"},
		// A broad command, however the request labels it.
		"priv_exec": {"command_id": "probe-broad", "args": []string{"write", marker, "broad"}},
	} {
		f.fail(op, args, "helper_wrong_unit")
	}
	f.fail("priv_exec", m{"command_id": "probe-broad", "args": []string{"write", marker, "broad"}, "unit": "broad"}, "helper_wrong_unit")
	// A core command labelled broad was routed to the broad socket; this
	// instance refuses it too rather than guess.
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "core"}, "unit": "broad"}, "helper_wrong_unit")
	f.fail("priv_exec", m{"command_id": "probe-echo", "args": []string{"echo", "core"}, "unit": "sideways"}, "bad_request")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a broad command ran in the core unit")
	}
	if l := f.lastAudit(); !strings.HasPrefix(l, "<5>") || !strings.Contains(l, `"outcome":"bad_request"`) {
		t.Fatalf("audit %q", l)
	}
}

func TestWrongUnitRefusedByBroad(t *testing.T) {
	f := newFixture(t, broadUsers(), asBroad())
	marker := filepath.Join(f.write, "ran")
	var ex struct {
		Stdout string `json:"stdout"`
	}
	// Control: a broad command runs in the broad unit, and no Landlock
	// sandbox is applied there (PRIVILEGED §5.2, §7).
	f.ok("priv_exec", m{"command_id": "probe-broad", "args": []string{"echo", "broad"}}, &ex)
	f.ok("priv_exec", m{"command_id": "probe-broad", "args": []string{"echo", "broad"}, "unit": "broad"}, nil)
	if ex.Stdout != "broad\n" || f.sandboxCalls != 0 {
		t.Fatalf("broad exec %+v, sandbox calls %d", ex, f.sandboxCalls)
	}
	for op, args := range map[string]m{
		"priv_stat":         {"path": f.read},
		"priv_read_file":    {"path": filepath.Join(f.read, "hello.txt")},
		"priv_write_file":   {"path": marker, "content_b64": b64("x")},
		"priv_list_backups": {},
		"priv_delete":       {"path": filepath.Join(f.write, "app.conf")},
		"priv_exec":         {"command_id": "probe-echo", "args": []string{"write", marker, "core"}},
	} {
		f.fail(op, args, "helper_wrong_unit")
	}
	f.fail("priv_exec", m{"command_id": "probe-broad", "args": []string{"write", marker, "broad"}, "unit": "core"}, "helper_wrong_unit")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a core operation ran in the broad unit")
	}
	if readFile(t, filepath.Join(f.write, "app.conf")) != "key: value\n" {
		t.Fatal("a refused operation changed something")
	}
}

// The unit's SHELL_MCP_PRIVD_UNIT is checked after the peer (it is not
// needed to authenticate it) and before the request is read: missing,
// malformed, or broad for a policy that uses no broad unit, it is answered
// as helper_install_insecure without an id.
func TestUnitEnvironment(t *testing.T) {
	for name, c := range map[string]struct {
		opts []opt
		unit string
	}{
		"missing":                   {nil, ""},
		"malformed":                 {nil, "Core"},
		"unknown":                   {nil, "sideways"},
		"broad without broad users": {nil, "broad"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, c.opts...)
			f.opts.Unit = c.unit
			in := request("priv_stat", m{"path": f.read})
			out, code := f.serveRaw(in)
			var r response
			if err := json.Unmarshal([]byte(out), &r); err != nil || code != 1 || r.ID != "" || r.Error == nil || f.unread != len(in) {
				t.Fatalf("exit %d response %q unread %d of %d", code, out, f.unread, len(in))
			}
			want, check := "helper_install_insecure", "unit"
			if r.Error.Code != want || !strings.Contains(f.lastAudit(), `"check":"`+check+`"`) {
				t.Fatalf("got %s, audit %q; want %s for check %s", r.Error.Code, f.lastAudit(), want, check)
			}
		})
	}
}

// The broad unit runs with root's full bounding set minus what its
// directives drop: CAP_SYS_MODULE (ProtectKernelModules=yes) and, unless a
// broad command declares CAP_SYS_TIME, CAP_SYS_TIME and CAP_WAKE_ALARM
// (ProtectClock=yes). A broader set is a hand-edited unit.
func TestBroadCapabilitySet(t *testing.T) {
	f := newFixture(t, broadUsers(), asBroad())
	f.ok("priv_exec", m{"command_id": "probe-broad", "args": []string{"echo", "ok"}}, nil) // control
	for name, capBnd := range map[string]string{
		"CAP_SYS_MODULE kept": "000001f7fdffffff",
		"CAP_SYS_TIME kept":   "000001fffffeffff",
		"everything":          "000001ffffffffff",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, broadUsers(), asBroad())
			f.status = statusFor("0", "1", capBnd)
			out, code := f.serveRaw(request("priv_exec", m{"command_id": "probe-broad", "args": []string{"echo", "x"}}))
			var r response
			if err := json.Unmarshal([]byte(out), &r); err != nil || code != 1 || r.Error == nil || r.Error.Code != "helper_capabilities_broad" {
				t.Fatalf("exit %d response %q", code, out)
			}
		})
	}
}

// With a broad command that declares CAP_SYS_TIME the broad unit has no
// ProtectClock=, so CAP_SYS_TIME and CAP_WAKE_ALARM are expected there.
func TestBroadCapabilitySetWithSysTime(t *testing.T) {
	sysTime := func(_ *fixture, s *string) {
		*s = strings.Replace(*s, "    unit: broad\n", "    unit: broad\n    capabilities: [CAP_SYS_TIME]\n", 1)
	}
	f := newFixture(t, broadUsers(), sysTime, asBroad())
	f.status = statusFor("0", "1", "000001fffffeffff")
	f.ok("priv_exec", m{"command_id": "probe-broad", "args": []string{"echo", "ok"}}, nil)
	f.status = statusFor("0", "1", "000001ffffffffff") // CAP_SYS_MODULE is still dropped
	out, code := f.serveRaw(request("priv_exec", m{"command_id": "probe-broad", "args": []string{"echo", "x"}}))
	if code != 1 || !strings.Contains(out, `"helper_capabilities_broad"`) {
		t.Fatalf("exit %d response %q", code, out)
	}
}
