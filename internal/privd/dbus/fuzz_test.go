package dbus_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus/dbustest"
)

// FuzzReadMessage: messages come from the bus; the reader never panics,
// never allocates past MaxMessageBytes, and a message it accepts has a
// known type and, for string bodies, one string per signature character.
func FuzzReadMessage(f *testing.F) {
	f.Add(dbustest.Reply(binary.LittleEndian, 1, "s", ":1.42"))
	f.Add(dbustest.Reply(binary.BigEndian, 2, "o", "/org/freedesktop/systemd1/job/7"))
	f.Add(dbustest.ErrorReply(binary.LittleEndian, 3, "org.freedesktop.systemd1.UnitMasked", "masked"))
	f.Add(dbustest.Signal("org.freedesktop.DBus", "NameAcquired"))
	f.Add([]byte("l\x02\x00\x01"))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := dbus.ReadMessage(bytes.NewReader(b))
		if err != nil {
			return
		}
		if m.Type < dbus.TypeMethodCall || m.Type > dbus.TypeSignal || len(m.Body) > dbus.MaxMessageBytes {
			t.Fatalf("accepted %+v", m)
		}
		if s, err := m.Strings(); err == nil && len(s) != len(m.Signature) {
			t.Fatalf("signature %q gave %d strings", m.Signature, len(s))
		}
	})
}
