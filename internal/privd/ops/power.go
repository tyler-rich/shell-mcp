//go:build linux

package ops

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// priv_power (PRIVILEGED §6): ask systemd to reboot or power off the host,
// from the broad unit. It does what `systemctl reboot` falls back to when it
// talks to PID 1: StartUnit("reboot.target" | "poweroff.target",
// "replace-irreversibly") over the system bus — an orderly shutdown that
// stops every unit, never the reboot(2) system call and never
// Manager.Reboot() (systemctl --force: services are not stopped). systemd
// authorizes it because the caller is uid 0 (sd_bus_query_sender_privilege
// in bus_verify_polkit_async_full, systemd 257 and 259); no capability is
// involved. The core unit can never do this: its /run, and so the bus
// socket, is an empty tmpfs.

// powerTimeout bounds the whole exchange with the bus.
const powerTimeout = 10 * time.Second

type powerArgs struct {
	Action string `json:"action"`
}

type powerData struct {
	Action string `json:"action"`
	Target string `json:"target"`
	Job    string `json:"job"`
}

// errorNameRE is a D-Bus error name safe to put in a message.
var errorNameRE = regexp.MustCompile(`^[A-Za-z0-9_.]{1,255}$`)

func (s *server) power(raw jsontext.Value) (any, []string, error) {
	var a powerArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if !slices.Contains(policy.PowerActions, a.Action) {
		return nil, nil, errf(protocol.CodeBadRequest, "action must be reboot or poweroff")
	}
	if !slices.Contains(s.p.Power.Allowed, a.Action) {
		return nil, nil, errf(protocol.CodePolicyDenied, "the privileged policy's power section does not allow %s", a.Action)
	}
	target := a.Action + ".target"
	bus := s.o.SystemBus
	if bus == "" {
		bus = dbus.SystemBus
	}
	ctx, cancel := context.WithTimeout(context.Background(), powerTimeout)
	defer cancel()
	c, err := dbus.Dial(ctx, bus, os.Getuid())
	if err != nil {
		return nil, nil, errf(protocol.CodeExecFailed, "the system bus cannot be reached, so systemd was not asked to start %s", target)
	}
	defer func() { _ = c.Close() }()
	r, err := c.Call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit", target, "replace-irreversibly")
	var de *dbus.Error
	switch {
	case errors.As(err, &de):
		name := de.Name
		if !errorNameRE.MatchString(name) {
			name = "an unreadable error"
		}
		switch name {
		case "org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired":
			return nil, nil, errf(protocol.CodeNotAuthorized, "systemd did not authorize starting %s (%s)", target, name)
		}
		return nil, nil, errf(protocol.CodeExecFailed, "systemd refused to start %s (%s)", target, name)
	case err != nil:
		return nil, nil, errf(protocol.CodeExecFailed, "systemd's answer to starting %s could not be read", target)
	}
	job, err := r.Strings()
	if err != nil || len(job) != 1 {
		return nil, nil, errf(protocol.CodeExecFailed, "systemd's answer to starting %s could not be read", target)
	}
	return powerData{Action: a.Action, Target: target, Job: job[0]}, nil, nil
}
