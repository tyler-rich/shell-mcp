//go:build linux

package ops_test

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus/dbustest"
)

// powerFixture is the broad unit's helper, power allowed for reboot, with
// a fake system bus answering StartUnit as told.
func powerFixture(t *testing.T, answer func(m *dbus.Message) []byte, opts ...opt) (*fixture, *dbustest.Bus) {
	t.Helper()
	f := newFixture(t, append([]opt{broadUsers(), asBroad()}, opts...)...)
	b := dbustest.Start(t, answer)
	f.opts.SystemBus = b.Path
	return f, b
}

func jobReply(m *dbus.Message) []byte {
	return dbustest.Reply(binary.LittleEndian, m.Serial, "o", "/org/freedesktop/systemd1/job/42")
}

// priv_power asks systemd, over the system bus, to start reboot.target (or
// poweroff.target) with job mode replace-irreversibly — what systemctl
// reboot does when it talks to PID 1 — for an action the policy's power
// section allows.
func TestPower(t *testing.T) {
	f, b := powerFixture(t, jobReply)
	var d struct {
		Action, Target, Job string
	}
	f.ok("priv_power", m{"action": "reboot"}, &d)
	if d.Action != "reboot" || d.Target != "reboot.target" || d.Job != "/org/freedesktop/systemd1/job/42" {
		t.Fatalf("power %+v", d)
	}
	calls := b.Calls()
	if len(calls) != 2 {
		t.Fatalf("bus calls %+v", calls)
	}
	c := calls[1]
	args, err := c.Strings()
	if err != nil || c.Destination != "org.freedesktop.systemd1" || c.Path != "/org/freedesktop/systemd1" || c.Interface != "org.freedesktop.systemd1.Manager" ||
		c.Member != "StartUnit" || !slices.Equal(args, []string{"reboot.target", "replace-irreversibly"}) {
		t.Fatalf("StartUnit call %+v %q", c, args)
	}
	if l := f.lastAudit(); !strings.HasPrefix(l, "<4>") || !strings.Contains(l, `"action":"reboot"`) || !strings.Contains(l, `"outcome":"ok"`) {
		t.Fatalf("audit %q", l)
	}
}

// Nothing reaches the bus for an action the policy does not allow, an
// unknown action, a policy without power, or below max_tier destructive.
func TestPowerRefusals(t *testing.T) {
	f, b := powerFixture(t, jobReply)
	f.fail("priv_power", m{"action": "poweroff"}, "policy_denied")
	f.fail("priv_power", m{"action": "halt"}, "bad_request")
	f.fail("priv_power", m{"action": "reboot", "force": true}, "bad_request")
	f.fail("priv_power", m{}, "bad_request")
	noPower, b2 := powerFixture(t, jobReply, replace("power:\n  allowed: [reboot]\n  acknowledge: \"invented test policy\"\n", ""))
	noPower.fail("priv_power", m{"action": "reboot"}, "policy_denied")
	low, b3 := powerFixture(t, jobReply, maxTier("operator"))
	low.fail("priv_power", m{"action": "reboot"}, "tier_denied")
	if b.Conns()+b2.Conns()+b3.Conns() != 0 {
		t.Fatal("a refused request reached the bus")
	}
}

// systemd's refusals map to closed-set codes: an authorization refusal is
// not_authorized; anything else, a masked target among them, is
// exec_failed naming the D-Bus error. An unreachable bus is exec_failed.
func TestPowerSystemdRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		errName, code, want string
	}{
		"masked":        {"org.freedesktop.systemd1.UnitMasked", "exec_failed", "org.freedesktop.systemd1.UnitMasked"},
		"access denied": {"org.freedesktop.DBus.Error.AccessDenied", "not_authorized", "AccessDenied"},
		"interactive":   {"org.freedesktop.DBus.Error.InteractiveAuthorizationRequired", "not_authorized", "InteractiveAuthorizationRequired"},
		"odd name":      {"bad name\nwith a newline", "exec_failed", "systemd refused"},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := powerFixture(t, func(m *dbus.Message) []byte {
				return dbustest.ErrorReply(binary.LittleEndian, m.Serial, c.errName, "Unit reboot.target is masked.")
			})
			r := f.serve("priv_power", m{"action": "reboot"})
			if r.OK || r.Error == nil || r.Error.Code != c.code || !strings.Contains(r.Error.Message, c.want) || strings.ContainsAny(r.Error.Message, "\r\n") {
				t.Fatalf("got %+v, want %s containing %q", r.Error, c.code, c.want)
			}
		})
	}
	f, _ := powerFixture(t, jobReply)
	f.opts.SystemBus = f.d + "/no-bus"
	f.fail("priv_power", m{"action": "reboot"}, "exec_failed")
}
