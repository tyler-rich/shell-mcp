// Package dbustest is a test-only stand-in for the system bus and systemd
// (never imported by a binary): it performs the EXTERNAL authentication
// exchange, answers Hello after a NameAcquired signal (as a bus may), and
// answers every other call as the test says. Its encoders are written
// independently of package dbus, so they check its decoder. Invented
// values; real systemd is exercised by the runner-host e2e job.
package dbustest

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/dbus"
)

// Bus is a running fake bus.
type Bus struct {
	Path  string
	mu    sync.Mutex
	calls []*dbus.Message
	auth  []string
	conns int
}

// Calls returns the messages received so far (Hello included).
func (b *Bus) Calls() []*dbus.Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*dbus.Message(nil), b.calls...)
}

// Auth returns the AUTH lines received.
func (b *Bus) Auth() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.auth...)
}

// Conns returns how many connections were accepted.
func (b *Bus) Conns() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns
}

// Start listens on a Unix socket in a short private directory (sun_path is
// limited to 108 bytes) and serves connections until the test ends.
func Start(t testing.TB, answer func(call *dbus.Message) []byte) *Bus {
	t.Helper()
	d, err := os.MkdirTemp("", "b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	b := &Bus{Path: filepath.Join(d, "bus")}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", b.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns++
			b.mu.Unlock()
			go b.serve(c, answer)
		}
	}()
	return b
}

func (b *Bus) serve(c net.Conn, answer func(call *dbus.Message) []byte) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	if nul, err := r.ReadByte(); err != nil || nul != 0 {
		return
	}
	line, _ := r.ReadString('\n')
	b.mu.Lock()
	b.auth = append(b.auth, line)
	b.mu.Unlock()
	_, _ = c.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
	if line, _ := r.ReadString('\n'); line != "BEGIN\r\n" {
		return
	}
	for {
		m, err := dbus.ReadMessage(r)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.calls = append(b.calls, m)
		b.mu.Unlock()
		if m.Member == "Hello" {
			_, _ = c.Write(Signal("org.freedesktop.DBus", "NameAcquired"))
			_, _ = c.Write(Reply(binary.LittleEndian, m.Serial, "s", ":1.42"))
			continue
		}
		_, _ = c.Write(answer(m))
	}
}

// Order is a byte order that can also append.
type Order interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

func pad(b []byte, n int) []byte {
	for len(b)%n != 0 {
		b = append(b, 0)
	}
	return b
}

func str(o Order, b []byte, s string) []byte {
	b = pad(b, 4)
	b = o.AppendUint32(b, uint32(len(s))) //nolint:gosec // G115: test strings are short
	return append(append(b, s...), 0)
}

func message(o Order, typ byte, fields func([]byte) []byte, sig string, body []byte) []byte {
	endian := byte('l')
	if o == binary.BigEndian {
		endian = 'B'
	}
	h := []byte{endian, typ, 0, 1}
	h = o.AppendUint32(h, uint32(len(body))) //nolint:gosec // G115: test bodies are short
	h = o.AppendUint32(h, 99)
	h = o.AppendUint32(h, 0) // array length, filled below
	start := len(h)
	h = fields(h)
	if sig != "" {
		h = pad(h, 8)
		h = append(h, 8, 1, 'g', 0, byte(len(sig)))
		h = append(append(h, sig...), 0)
	}
	o.PutUint32(h[12:], uint32(len(h)-start)) //nolint:gosec // G115: test headers are short
	return append(pad(h, 8), body...)
}

func field(o Order, h []byte, code, typ byte, v string) []byte {
	h = pad(h, 8)
	h = append(h, code, 1, typ, 0)
	return str(o, h, v)
}

func replySerial(o Order, h []byte, serial uint32) []byte {
	h = pad(h, 8)
	h = append(h, 5, 1, 'u', 0)
	return o.AppendUint32(h, serial)
}

// Reply is a METHOD_RETURN to serial with one string-like argument.
func Reply(o Order, serial uint32, sig, v string) []byte {
	return message(o, 2, func(h []byte) []byte { return replySerial(o, h, serial) }, sig, str(o, nil, v))
}

// ErrorReply is an ERROR reply to serial.
func ErrorReply(o Order, serial uint32, name, msg string) []byte {
	return message(o, 3, func(h []byte) []byte {
		return field(o, replySerial(o, h, serial), 4, 's', name)
	}, "s", str(o, nil, msg))
}

// Signal is a SIGNAL from the bus.
func Signal(iface, member string) []byte {
	o := binary.LittleEndian
	return message(o, 4, func(h []byte) []byte {
		h = field(o, h, 1, 'o', "/org/freedesktop/DBus")
		h = field(o, h, 2, 's', iface)
		return field(o, h, 3, 's', member)
	}, "s", str(o, nil, ":1.42"))
}
