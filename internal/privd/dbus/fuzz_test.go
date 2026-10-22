package dbus_test

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
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

// FuzzValues: a body comes from the bus with a signature it chose; Values never
// panics, and a body it accepts decodes the same twice and, for a
// signature of basic types only, to one value per type.
func FuzzValues(f *testing.F) {
	o := binary.LittleEndian
	for _, b := range [][]byte{
		dbustest.Inhibitors(o, 1, []dbustest.Inhibitor{{What: "shutdown", Who: "example", Why: "x", Mode: "block", UID: 1, PID: 2}}),
		dbustest.Property(o, 2, "(st)", dbustest.ST(o, "reboot", 42)),
		dbustest.Property(binary.BigEndian, 3, "b", dbustest.Bool(binary.BigEndian, false)),
		dbustest.Empty(o, 4),
		dbustest.Raw(o, 5, "av", []byte{8, 0, 0, 0, 1, 'y', 0, 7, 1, 'y', 0, 8}),
	} {
		m, err := dbus.ReadMessage(bytes.NewReader(b))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(m.Signature, m.Body, b[0] == 'B')
	}
	// Found by the fuzzer: a double (NaN), which the decoder no longer accepts.
	f.Add("d", append([]byte{0xff, 0xff}, "000000"...), true)
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
		v, err := m.Values()
		if err != nil {
			return
		}
		again, err := m.Values()
		if err != nil || !reflect.DeepEqual(v, again) {
			t.Fatalf("decoded %#v, then %#v %v", v, again, err)
		}
		if strings.Trim(sig, "ybnqiuxtsog") == "" && len(v) != len(sig) {
			t.Fatalf("signature %q gave %d values", sig, len(v))
		}
	})
}
