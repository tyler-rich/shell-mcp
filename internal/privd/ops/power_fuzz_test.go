//go:build linux

package ops

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus/dbustest"
)

// FuzzShutdownJobs: systemd's ListJobs answer comes from the bus. Deciding
// on it never panics; an answer it lets pass holds no job other than a stop
// job for a shutdown-family target, and one it cannot read is refused.
func FuzzShutdownJobs(f *testing.F) {
	o := binary.LittleEndian
	for _, b := range [][]byte{
		dbustest.Jobs(o, 1, nil),
		dbustest.Jobs(o, 2, []dbustest.Job{{ID: 7, Unit: "reboot.target", Type: "start", State: "waiting", Path: "/org/freedesktop/systemd1/job/7", UPath: "/org/freedesktop/systemd1/unit/reboot_2etarget"}}),
		dbustest.Jobs(o, 3, []dbustest.Job{{ID: 8, Unit: "example-app.service", Type: "restart", State: "running", Path: "/org/freedesktop/systemd1/job/8", UPath: "/x"}}),
		dbustest.Jobs(binary.BigEndian, 4, []dbustest.Job{{ID: 9, Unit: "poweroff.target", Type: "stop", State: "waiting", Path: "/j", UPath: "/u"}}),
	} {
		m, err := dbus.ReadMessage(bytes.NewReader(b))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(m.Signature, m.Body, b[0] == 'B')
	}
	f.Fuzz(func(t *testing.T, sig string, body []byte, big bool) {
		var ord dbustest.Order = binary.LittleEndian
		if big {
			ord = binary.BigEndian
		}
		if len(sig) > 255 || len(body) > dbus.MaxMessageBytes-512 || strings.IndexByte(sig, 0) >= 0 {
			return
		}
		m, err := dbus.ReadMessage(bytes.NewReader(dbustest.Raw(ord, 9, sig, body)))
		if err != nil {
			return
		}
		refused := shutdownJobErr(m, "nothing was scheduled") != nil
		v, verr := m.Values()
		if verr != nil || m.Signature != "a(usssoo)" {
			if !refused {
				t.Fatalf("an unreadable answer (%q) was let pass", m.Signature)
			}
			return
		}
		blocking := false
		for _, e := range v[0].([]any) {
			f := e.([]any)
			if f[2] != "stop" && slices.Contains(shutdownTargets, f[1].(string)) {
				blocking = true
			}
		}
		if blocking != refused {
			t.Fatalf("jobs %v: refused %v, want %v", v, refused, blocking)
		}
	})
}
