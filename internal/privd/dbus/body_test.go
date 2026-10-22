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

// The power operations (PRIVILEGED §6, "Power") call logind with a uint64
// flags argument (RebootWithFlags, PowerOffWithFlags; signature "t") and
// read its answers: ListInhibitors' a(ssssuu) and the variants of
// org.freedesktop.DBus.Properties.Get ((st) and b). Every value here is
// invented.

func read(t *testing.T, b []byte) *dbus.Message {
	t.Helper()
	m, err := dbus.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	return m
}

// A uint64 argument is marshalled as "t", 8-byte aligned and little
// endian, after any string arguments.
func TestCallUint64(t *testing.T) {
	b := dbustest.Start(t, func(m *dbus.Message) []byte { return dbustest.Empty(binary.LittleEndian, m.Serial) })
	c := dial(t, b)
	r, err := c.Call("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "RebootWithFlags", uint64(1))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Values(); err != nil || len(got) != 0 {
		t.Fatalf("empty reply body %v %v", got, err)
	}
	if _, err := c.Call("org.example.Test", "/org/example/Test", "org.example.Test", "Mixed", "reboot", uint64(0x0102030405060708)); err != nil {
		t.Fatal(err)
	}
	calls := b.Calls()
	if len(calls) != 3 {
		t.Fatalf("calls %+v", calls)
	}
	if c := calls[1]; c.Signature != "t" || !bytes.Equal(c.Body, []byte{1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("RebootWithFlags call: signature %q body %x", c.Signature, c.Body)
	}
	want := []byte{6, 0, 0, 0, 'r', 'e', 'b', 'o', 'o', 't', 0, 0, 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1}
	if c := calls[2]; c.Signature != "st" || !bytes.Equal(c.Body, want) {
		t.Fatalf("mixed call: signature %q body %x", c.Signature, c.Body)
	}
	if got, err := calls[2].Values(); err != nil || !reflect.DeepEqual(got, []any{"reboot", uint64(0x0102030405060708)}) {
		t.Fatalf("decoded call %v %v", got, err)
	}
	for _, bad := range []any{int64(1), 1, true, []string{"x"}, nil} {
		if _, err := c.Call("org.example.Test", "/org/example/Test", "org.example.Test", "Bad", bad); err == nil {
			t.Fatalf("argument %T was marshalled", bad)
		}
	}
}

// ListInhibitors' answer decodes to one []any per inhibitor, in both byte
// orders.
func TestBodyInhibitors(t *testing.T) {
	list := []dbustest.Inhibitor{
		{What: "shutdown:sleep", Who: "example-backup", Why: "nightly copy", Mode: "block", UID: 1001, PID: 4242},
		{What: "shutdown", Who: "example-updater", Why: "", Mode: "delay", UID: 0, PID: 77},
	}
	for _, o := range []dbustest.Order{binary.LittleEndian, binary.BigEndian} {
		got, err := read(t, dbustest.Inhibitors(o, 3, list)).Values()
		if err != nil {
			t.Fatalf("%s: %v", o, err)
		}
		want := []any{[]any{
			[]any{"shutdown:sleep", "example-backup", "nightly copy", "block", uint32(1001), uint32(4242)},
			[]any{"shutdown", "example-updater", "", "delay", uint32(0), uint32(77)},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %#v", o, got)
		}
		if got, err := read(t, dbustest.Inhibitors(o, 3, nil)).Values(); err != nil || !reflect.DeepEqual(got, []any{[]any{}}) {
			t.Fatalf("%s: no inhibitors: %#v %v", o, got, err)
		}
	}
}

// A property answer is one variant: ScheduledShutdown's (st) and
// PreparingForShutdown's b.
func TestBodyVariants(t *testing.T) {
	for _, o := range []dbustest.Order{binary.LittleEndian, binary.BigEndian} {
		got, err := read(t, dbustest.Property(o, 4, "(st)", dbustest.ST(o, "reboot", 1_790_000_000_000_000))).Values()
		if err != nil || !reflect.DeepEqual(got, []any{dbus.Variant{Signature: "(st)", Value: []any{"reboot", uint64(1_790_000_000_000_000)}}}) {
			t.Fatalf("%s: (st) %#v %v", o, got, err)
		}
		got, err = read(t, dbustest.Property(o, 5, "b", dbustest.Bool(o, true))).Values()
		if err != nil || !reflect.DeepEqual(got, []any{dbus.Variant{Signature: "b", Value: true}}) {
			t.Fatalf("%s: b %#v %v", o, got, err)
		}
	}
}

// The decoder is strict: anything the specification forbids, or that this
// client does not support, is an error, never a partial value.
func TestBodyStrict(t *testing.T) {
	le := binary.LittleEndian
	u32 := func(v uint32) []byte { return le.AppendUint32(nil, v) }
	str := func(s string) []byte { return append(append(u32(uint32(len(s))), s...), 0) } //nolint:gosec // G115: short
	cat := func(bs ...[]byte) []byte { return bytes.Join(bs, nil) }
	for name, c := range map[string]struct {
		sig  string
		body []byte
	}{
		"bool not 0 or 1":        {"b", u32(2)},
		"trailing bytes":         {"u", cat(u32(1), []byte{0})},
		"short":                  {"t", []byte{1, 2, 3}},
		"non-zero padding":       {"yu", cat([]byte{1, 0, 9, 0}, u32(1))},
		"string without nul":     {"s", cat(u32(3), []byte("abcd"))},
		"string with a nul":      {"s", cat(u32(3), []byte("a\x00c\x00"))},
		"invalid utf-8":          {"s", cat(u32(2), []byte{0xff, 0xfe, 0})},
		"array past the body":    {"au", cat(u32(64), u32(1))},
		"array not on a value":   {"au", cat(u32(3), u32(1))},
		"bad object path":        {"o", str("not/absolute")},
		"object path double /":   {"o", str("/a//b")},
		"unix fd":                {"h", u32(0)},
		"double":                 {"d", make([]byte, 8)},
		"dict entry":             {"a{su}", cat(u32(0), make([]byte, 4))},
		"empty struct":           {"()", nil},
		"unclosed struct":        {"(su", cat(str("x"), u32(1))},
		"array without element":  {"a", u32(0)},
		"variant of two types":   {"v", cat([]byte{2, 's', 'u', 0}, str("x"), u32(1))},
		"variant bad signature":  {"v", cat([]byte{1, '!', 0}, u32(1))},
		"variant nested too far": {"v", cat(bytes.Repeat([]byte{1, 'v', 0}, 40), []byte{1, 'y', 0, 5})},
		"array nested too far":   {strings.Repeat("a", 40) + "y", u32(0)},
	} {
		m := read(t, dbustest.Raw(le, 6, c.sig, c.body))
		if got, err := m.Values(); err == nil {
			t.Errorf("%s: accepted %#v", name, got)
		}
	}
	// Controls: the same shapes, well formed.
	for name, c := range map[string]struct {
		sig  string
		body []byte
		want []any
	}{
		"bool":        {"b", u32(1), []any{true}},
		"padding":     {"yu", cat([]byte{1, 0, 0, 0}, u32(7)), []any{byte(1), uint32(7)}},
		"object path": {"o", str("/org/freedesktop/login1"), []any{"/org/freedesktop/login1"}},
		"root path":   {"o", str("/"), []any{"/"}},
		"array":       {"au", cat(u32(8), u32(1), u32(2)), []any{[]any{uint32(1), uint32(2)}}},
		"empty array": {"at", cat(u32(0), make([]byte, 4)), []any{[]any{}}},
		"nested":      {strings.Repeat("a", 10) + "y", u32(0), []any{[]any{}}},
		"variants":    {"v", cat(bytes.Repeat([]byte{1, 'v', 0}, 3), []byte{1, 'y', 0, 5}), []any{dbus.Variant{Signature: "v", Value: dbus.Variant{Signature: "v", Value: dbus.Variant{Signature: "v", Value: dbus.Variant{Signature: "y", Value: byte(5)}}}}}},
	} {
		got, err := read(t, dbustest.Raw(le, 6, c.sig, c.body)).Values()
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %#v %v", name, got, err)
		}
	}
}
