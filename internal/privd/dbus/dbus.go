// Package dbus (stub).
package dbus

import (
	"context"
	"errors"
	"io"
)

// Stubs.
const (
	TypeMethodCall  = 1
	TypeSignal      = 4
	MaxMessageBytes = 1 << 16
	SystemBus       = "/run/dbus/system_bus_socket"
)

// Message (stub).
type Message struct {
	Type                                                               byte
	Serial, ReplySerial                                                uint32
	Path, Interface, Member, ErrorName, Destination, Sender, Signature string
	Body                                                               []byte
}

// Strings (stub).
func (m *Message) Strings() ([]string, error) { return nil, errors.New("stub") }

// Error (stub).
type Error struct{ Name, Message string }

func (e *Error) Error() string { return e.Name }

// Conn (stub).
type Conn struct{}

// Dial (stub).
func Dial(context.Context, string, int) (*Conn, error) { return nil, errors.New("stub") }

// Close (stub).
func (c *Conn) Close() error { return nil }

// Call (stub).
func (c *Conn) Call(string, string, string, string, ...string) (*Message, error) {
	return nil, errors.New("stub")
}

// ReadMessage (stub).
func ReadMessage(io.Reader) (*Message, error) { return nil, errors.New("stub") }
