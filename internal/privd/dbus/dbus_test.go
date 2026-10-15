package dbus_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
	"github.com/tyler-rich/shell-mcp/internal/privd/dbus/dbustest"
)

func dial(t *testing.T, b *dbustest.Bus) *dbus.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dbus.Dial(ctx, b.Path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The client authenticates with EXTERNAL as its uid (hex of the decimal
// string), says Hello, and sends a method call with the destination, path,
// interface, member, signature and string arguments given; it returns the
// reply with the matching serial, skipping the bus's signals.
func TestCall(t *testing.T) {
	for _, o := range []dbustest.Order{binary.LittleEndian, binary.BigEndian} {
		t.Run(o.String(), func(t *testing.T) {
			b := dbustest.Start(t, func(m *dbus.Message) []byte {
				return dbustest.Reply(o, m.Serial, "o", "/org/freedesktop/systemd1/job/7")
			})
			c := dial(t, b)
			r, err := c.Call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit", "reboot.target", "replace-irreversibly")
			if err != nil {
				t.Fatal(err)
			}
			if got, serr := r.Strings(); serr != nil || !slices.Equal(got, []string{"/org/freedesktop/systemd1/job/7"}) || r.Signature != "o" {
				t.Fatalf("reply %v %v (signature %q)", got, serr, r.Signature)
			}
			if a := b.Auth(); len(a) != 1 || a[0] != "AUTH EXTERNAL 30\r\n" {
				t.Fatalf("auth lines %q", a)
			}
			calls := b.Calls()
			if len(calls) != 2 || calls[0].Member != "Hello" || calls[0].Destination != "org.freedesktop.DBus" {
				t.Fatalf("calls %+v", calls)
			}
			call := calls[1]
			args, err := call.Strings()
			if err != nil || call.Type != dbus.TypeMethodCall || call.Destination != "org.freedesktop.systemd1" || call.Path != "/org/freedesktop/systemd1" ||
				call.Interface != "org.freedesktop.systemd1.Manager" || call.Member != "StartUnit" || call.Signature != "ss" ||
				!slices.Equal(args, []string{"reboot.target", "replace-irreversibly"}) {
				t.Fatalf("call %+v %q %v", call, args, err)
			}
		})
	}
}

// An ERROR reply is returned as *dbus.Error with the error name and the
// first string argument.
func TestCallError(t *testing.T) {
	b := dbustest.Start(t, func(m *dbus.Message) []byte {
		return dbustest.ErrorReply(binary.LittleEndian, m.Serial, "org.freedesktop.systemd1.UnitMasked", "Unit reboot.target is masked.")
	})
	c := dial(t, b)
	_, err := c.Call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit", "reboot.target", "replace-irreversibly")
	var de *dbus.Error
	if !errors.As(err, &de) || de.Name != "org.freedesktop.systemd1.UnitMasked" || de.Message != "Unit reboot.target is masked." {
		t.Fatalf("error %v", err)
	}
}

// Authentication must be accepted: anything but OK fails the dial.
func TestDialRejected(t *testing.T) {
	d, err := os.MkdirTemp("", "b")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(d) }()
	p := filepath.Join(d, "bus")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		c, err := l.Accept()
		if err == nil {
			_, _ = c.Write([]byte("REJECTED EXTERNAL\r\n"))
			time.Sleep(100 * time.Millisecond)
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := dbus.Dial(ctx, p, 0); err == nil {
		_ = c.Close()
		t.Fatal("a rejected authentication dialed")
	}
}

// ReadMessage is strict and bounded: bad endianness, version or type, a
// length past the limit, truncation, or a body that does not match its
// signature are errors.
func TestReadMessageStrict(t *testing.T) {
	good := dbustest.Reply(binary.LittleEndian, 5, "s", "x")
	if m, err := dbus.ReadMessage(bytes.NewReader(good)); err != nil || m.ReplySerial != 5 {
		t.Fatalf("control: %+v %v", m, err)
	}
	mut := func(f func([]byte) []byte) []byte { return f(slices.Clone(good)) }
	for name, b := range map[string][]byte{
		"endianness": mut(func(b []byte) []byte { b[0] = 'x'; return b }),
		"version":    mut(func(b []byte) []byte { b[3] = 2; return b }),
		"type":       mut(func(b []byte) []byte { b[1] = 9; return b }),
		"huge body":  mut(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 1<<30); return b }),
		"huge array": mut(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 1<<30); return b }),
		"truncated":  good[:len(good)-3],
		"empty":      nil,
		"short body": mut(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 2); return b[:len(b)-4] }),
	} {
		if m, err := dbus.ReadMessage(bytes.NewReader(b)); err == nil {
			if _, serr := m.Strings(); serr == nil {
				t.Errorf("%s: accepted %+v", name, m)
			}
		}
	}
	if !strings.HasPrefix(dbus.SystemBus, "/run/dbus/") {
		t.Errorf("system bus %s", dbus.SystemBus)
	}
}
