// Package dbus is the smallest D-Bus client the privileged helper needs
// (docs/PRIVILEGED.md §6, "Power"): connect to the system bus socket,
// authenticate with EXTERNAL as the process's uid, say Hello, send method
// calls with string and uint64 arguments, and read their replies. It
// implements the D-Bus specification's wire format for exactly that —
// little-endian output, either byte order on input, header fields of basic
// types, and bodies of basic types, arrays, structs and variants — with
// every length and nesting bounded and every message strictly checked.
// Nothing else: no dict entries, no signals, no file descriptors, no
// introspection. The standard library only.
package dbus

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// SystemBus is the system bus socket (D-Bus specification: the well-known
// system bus address unix:path=/run/dbus/system_bus_socket on current
// systems).
const SystemBus = "/run/dbus/system_bus_socket"

// Message types.
const (
	TypeMethodCall   = 1
	TypeMethodReturn = 2
	TypeError        = 3
	TypeSignal       = 4
)

// MaxMessageBytes bounds a message the client accepts (the specification's
// own limit is 128 MiB; nothing the helper reads comes near 64 KiB).
const MaxMessageBytes = 64 << 10

// maxReplies bounds the messages read while waiting for one reply (the bus
// may send signals such as NameAcquired first).
const maxReplies = 32

// Header field codes (D-Bus specification, "Header Fields").
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSender      = 7
	fieldSignature   = 8
	fieldUnixFDs     = 9
)

// Message is one decoded message. Body is kept raw; Strings decodes it.
type Message struct {
	Type                   byte
	Serial, ReplySerial    uint32
	Path, Interface        string
	Member, ErrorName      string
	Destination, Sender    string
	Signature              string
	Body                   []byte
	order                  binary.ByteOrder
	hasReplySerial, hasSig bool
}

// Error is an ERROR reply: its error name and first string argument.
type Error struct {
	Name, Message string
}

func (e *Error) Error() string { return "dbus: " + e.Name + ": " + e.Message }

// ReadMessage reads and strictly decodes one message.
func ReadMessage(r io.Reader) (*Message, error) {
	var fixed [16]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, fmt.Errorf("dbus: message header: %w", err)
	}
	var o binary.ByteOrder
	switch fixed[0] {
	case 'l':
		o = binary.LittleEndian
	case 'B':
		o = binary.BigEndian
	default:
		return nil, errors.New("dbus: unknown endianness")
	}
	m := &Message{Type: fixed[1], order: o}
	if m.Type < TypeMethodCall || m.Type > TypeSignal {
		return nil, errors.New("dbus: unknown message type")
	}
	if fixed[3] != 1 {
		return nil, errors.New("dbus: unsupported protocol version")
	}
	bodyLen, fieldsLen := o.Uint32(fixed[4:]), o.Uint32(fixed[12:])
	m.Serial = o.Uint32(fixed[8:])
	if m.Serial == 0 {
		return nil, errors.New("dbus: serial 0")
	}
	headerLen := 16 + uint64(fieldsLen)
	padded := (headerLen + 7) &^ 7
	if padded+uint64(bodyLen) > MaxMessageBytes {
		return nil, errors.New("dbus: message too large")
	}
	rest := make([]byte, padded-16+uint64(bodyLen))
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("dbus: message: %w", err)
	}
	buf := append(fixed[:], rest...)
	if err := m.fields(buf[:headerLen]); err != nil {
		return nil, err
	}
	for _, b := range buf[headerLen:padded] {
		if b != 0 {
			return nil, errors.New("dbus: non-zero header padding")
		}
	}
	m.Body = buf[padded:]
	if err := m.required(); err != nil {
		return nil, err
	}
	return m, nil
}

// decoder reads basic values from a message at absolute offsets (alignment
// is relative to the start of the message, or of the body, which starts on
// an 8-byte boundary).
type decoder struct {
	b   []byte
	pos int
	o   binary.ByteOrder
}

var errShort = errors.New("dbus: truncated value")

func (d *decoder) align(n int) error {
	for d.pos%n != 0 {
		if d.pos >= len(d.b) {
			return errShort
		}
		if d.b[d.pos] != 0 {
			return errors.New("dbus: non-zero alignment padding")
		}
		d.pos++
	}
	return nil
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(d.b)-d.pos {
		return nil, errShort
	}
	v := d.b[d.pos : d.pos+n]
	d.pos += n
	return v, nil
}

func (d *decoder) uint32() (uint32, error) {
	if err := d.align(4); err != nil {
		return 0, err
	}
	v, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return d.o.Uint32(v), nil
}

// text reads the bytes and terminating nul of a string, object path or
// signature of length n: valid UTF-8, no nul inside.
func (d *decoder) text(n int) (string, error) {
	v, err := d.take(n + 1)
	if err != nil {
		return "", err
	}
	s := string(v[:n])
	if v[n] != 0 || strings.IndexByte(s, 0) >= 0 || !utf8.ValidString(s) {
		return "", errors.New("dbus: malformed string")
	}
	return s, nil
}

func (d *decoder) str() (string, error) {
	n, err := d.uint32()
	if err != nil {
		return "", err
	}
	if n > MaxMessageBytes {
		return "", errShort
	}
	return d.text(int(n))
}

func (d *decoder) sig() (string, error) {
	n, err := d.take(1)
	if err != nil {
		return "", err
	}
	return d.text(int(n[0]))
}

// basic skips or reads one value of a basic type (header fields may carry
// only basic types; the client needs s, o, g and u).
func (d *decoder) basic(t byte) (s string, u uint32, err error) {
	switch t {
	case 's', 'o':
		s, err = d.str()
	case 'g':
		s, err = d.sig()
	case 'u', 'i', 'b', 'h':
		u, err = d.uint32()
	case 'y':
		_, err = d.take(1)
	case 'n', 'q':
		if err = d.align(2); err == nil {
			_, err = d.take(2)
		}
	case 'x', 't', 'd':
		if err = d.align(8); err == nil {
			_, err = d.take(8)
		}
	default:
		err = errors.New("dbus: header field of a non-basic type")
	}
	return s, u, err
}

// fieldTypes are the types the specification gives each known field.
var fieldTypes = map[byte]byte{
	fieldPath: 'o', fieldInterface: 's', fieldMember: 's', fieldErrorName: 's', fieldReplySerial: 'u',
	fieldDestination: 's', fieldSender: 's', fieldSignature: 'g', fieldUnixFDs: 'u',
}

func (m *Message) fields(h []byte) error {
	d := &decoder{b: h, pos: 16, o: m.order}
	for d.pos < len(h) {
		if err := d.align(8); err != nil {
			return err
		}
		code, err := d.take(1)
		if err != nil {
			return err
		}
		sig, err := d.sig()
		if err != nil {
			return err
		}
		if len(sig) != 1 {
			return errors.New("dbus: header field variant is not a single basic type")
		}
		if want, known := fieldTypes[code[0]]; known && sig[0] != want {
			return fmt.Errorf("dbus: header field %d has type %q", code[0], sig)
		}
		s, u, err := d.basic(sig[0])
		if err != nil {
			return err
		}
		switch code[0] {
		case fieldPath:
			m.Path = s
		case fieldInterface:
			m.Interface = s
		case fieldMember:
			m.Member = s
		case fieldErrorName:
			m.ErrorName = s
		case fieldReplySerial:
			m.ReplySerial, m.hasReplySerial = u, true
		case fieldDestination:
			m.Destination = s
		case fieldSender:
			m.Sender = s
		case fieldSignature:
			m.Signature, m.hasSig = s, true
		case fieldUnixFDs:
			if u != 0 {
				return errors.New("dbus: file descriptors are not accepted")
			}
		}
	}
	return nil
}

// required checks the fields the specification requires per type.
func (m *Message) required() error {
	switch {
	case m.Type == TypeMethodCall && (m.Path == "" || m.Member == ""),
		m.Type == TypeSignal && (m.Path == "" || m.Interface == "" || m.Member == ""),
		(m.Type == TypeMethodReturn || m.Type == TypeError) && !m.hasReplySerial,
		m.Type == TypeError && m.ErrorName == "":
		return errors.New("dbus: a required header field is missing")
	case len(m.Body) > 0 && !m.hasSig:
		return errors.New("dbus: a body without a signature")
	}
	return nil
}

// Variant is a decoded variant: its signature and its value.
type Variant struct {
	Signature string
	Value     any
}

// maxDepth bounds the nesting of arrays, structs and variants in a
// signature, and of variants in a body. The specification allows 32 arrays
// and 32 structs; nothing the helper reads nests more than three deep.
const maxDepth = 32

var errUnsupported = errors.New("dbus: unsupported or malformed signature")

// nextType splits the first complete type off sig: a basic type, a
// variant, an array of a complete type, or a non-empty struct. Doubles,
// dict entries and file descriptors are not supported (nothing the helper
// reads uses them).
func nextType(sig string, depth int) (typ, rest string, err error) {
	if sig == "" || depth > maxDepth {
		return "", "", errUnsupported
	}
	switch sig[0] {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 's', 'o', 'g', 'v':
		return sig[:1], sig[1:], nil
	case 'a':
		elem, rest, err := nextType(sig[1:], depth+1)
		if err != nil {
			return "", "", err
		}
		return "a" + elem, rest, nil
	case '(':
		n := 1
		for {
			if n >= len(sig) {
				return "", "", errUnsupported
			}
			if sig[n] == ')' {
				if n == 1 {
					return "", "", errUnsupported // an empty struct
				}
				return sig[:n+1], sig[n+1:], nil
			}
			field, _, err := nextType(sig[n:], depth+1)
			if err != nil {
				return "", "", err
			}
			n += len(field)
		}
	}
	return "", "", errUnsupported
}

// splitTypes splits a signature into its complete types.
func splitTypes(sig string, depth int) ([]string, error) {
	var out []string
	for sig != "" {
		t, rest, err := nextType(sig, depth)
		if err != nil {
			return nil, err
		}
		out, sig = append(out, t), rest
	}
	return out, nil
}

// alignOf is a type's alignment in the wire format.
func alignOf(t byte) int {
	switch t {
	case 'y', 'g', 'v':
		return 1
	case 'n', 'q':
		return 2
	case 'x', 't', '(':
		return 8
	}
	return 4 // b, i, u, s, o, a
}

// validObjectPath is the specification's object path grammar: "/", or
// "/" followed by non-empty elements of [A-Za-z0-9_] separated by "/".
func validObjectPath(p string) bool {
	if p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, e := range strings.Split(p[1:], "/") {
		if e == "" {
			return false
		}
		for _, c := range e {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

// value decodes one value of the complete type t: strings, object paths and
// signatures as string, b as bool, y as byte, n as int16, q as uint16, i as
// int32, u as uint32, x as int64, t as uint64, an array or a
// struct as []any, a variant as Variant.
func (d *decoder) value(t string, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errUnsupported
	}
	if err := d.align(alignOf(t[0])); err != nil {
		return nil, err
	}
	switch t[0] {
	case 'y':
		v, err := d.take(1)
		if err != nil {
			return nil, err
		}
		return v[0], nil
	case 'b':
		v, err := d.uint32()
		if err != nil {
			return nil, err
		}
		if v > 1 {
			return nil, errors.New("dbus: a boolean that is neither 0 nor 1")
		}
		return v == 1, nil
	case 'n', 'q':
		v, err := d.take(2)
		if err != nil {
			return nil, err
		}
		u := d.o.Uint16(v)
		if t[0] == 'n' {
			return int16(u), nil //nolint:gosec // G115: the wire's two's complement
		}
		return u, nil
	case 'i', 'u':
		v, err := d.uint32()
		if err != nil {
			return nil, err
		}
		if t[0] == 'i' {
			return int32(v), nil //nolint:gosec // G115: the wire's two's complement
		}
		return v, nil
	case 'x', 't':
		v, err := d.take(8)
		if err != nil {
			return nil, err
		}
		u := d.o.Uint64(v)
		if t[0] == 'x' {
			return int64(u), nil //nolint:gosec // G115: the wire's two's complement
		}
		return u, nil
	case 's':
		return d.str()
	case 'o':
		s, err := d.str()
		if err != nil {
			return nil, err
		}
		if !validObjectPath(s) {
			return nil, errors.New("dbus: malformed object path")
		}
		return s, nil
	case 'g':
		s, err := d.sig()
		if err != nil {
			return nil, err
		}
		if _, err := splitTypes(s, depth+1); err != nil {
			return nil, err
		}
		return s, nil
	case 'v':
		s, err := d.sig()
		if err != nil {
			return nil, err
		}
		inner, rest, err := nextType(s, depth+1)
		if err != nil || rest != "" {
			return nil, errors.New("dbus: a variant's signature is not one complete type")
		}
		v, err := d.value(inner, depth+1)
		if err != nil {
			return nil, err
		}
		return Variant{Signature: s, Value: v}, nil
	case 'a':
		n, err := d.uint32()
		if err != nil {
			return nil, err
		}
		elem := t[1:]
		// The padding to the first element is there even when the array is
		// empty, and is not counted in its length.
		if err := d.align(alignOf(elem[0])); err != nil {
			return nil, err
		}
		if uint64(n) > uint64(len(d.b)-d.pos) {
			return nil, errShort
		}
		end := d.pos + int(n)
		out := []any{}
		for d.pos < end {
			v, err := d.value(elem, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		if d.pos != end {
			return nil, errors.New("dbus: an array's length does not end on an element")
		}
		return out, nil
	case '(':
		fields, err := splitTypes(t[1:len(t)-1], depth+1)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(fields))
		for _, f := range fields {
			v, err := d.value(f, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, errUnsupported
}

// Values decodes the whole body by its signature, consuming it exactly
// (value says which Go type each wire type becomes). Any malformed or
// unsupported value is an error, never a partial result.
func (m *Message) Values() ([]any, error) {
	o := m.order
	if o == nil {
		o = binary.LittleEndian
	}
	types, err := splitTypes(m.Signature, 0)
	if err != nil {
		return nil, err
	}
	d := &decoder{b: m.Body, o: o}
	out := make([]any, 0, len(types))
	for _, t := range types {
		v, err := d.value(t, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if d.pos != len(m.Body) {
		return nil, errors.New("dbus: body longer than its signature")
	}
	return out, nil
}

// Strings decodes a body whose signature holds only strings and object
// paths, consuming it exactly.
func (m *Message) Strings() ([]string, error) {
	d := &decoder{b: m.Body, o: m.order}
	out := make([]string, 0, len(m.Signature))
	for _, t := range []byte(m.Signature) {
		if t != 's' && t != 'o' {
			return nil, fmt.Errorf("dbus: body type %q is not a string", t)
		}
		s, err := d.str()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if d.pos != len(m.Body) {
		return nil, errors.New("dbus: body longer than its signature")
	}
	return out, nil
}

// encoder writes a little-endian message.
type encoder struct{ b []byte }

func (e *encoder) align(n int) {
	for len(e.b)%n != 0 {
		e.b = append(e.b, 0)
	}
}

func (e *encoder) str(s string) {
	e.align(4)
	e.b = binary.LittleEndian.AppendUint32(e.b, uint32(len(s))) //nolint:gosec // G115: bounded by marshal's checks
	e.b = append(append(e.b, s...), 0)
}

func (e *encoder) field(code, typ byte, s string) {
	e.align(8)
	e.b = append(e.b, code, 1, typ, 0)
	if typ == 'g' {
		e.b = append(append(append(e.b, byte(len(s))), s...), 0) //nolint:gosec // G115: marshal bounds every string to 255 bytes
		return
	}
	e.str(s)
}

// marshal encodes a METHOD_CALL whose arguments are strings (signature s)
// or uint64s (t); anything else is refused.
func marshal(serial uint32, dest, path, iface, member string, args []any) ([]byte, error) {
	for _, s := range []string{dest, path, iface, member} {
		if len(s) > 255 || strings.IndexByte(s, 0) >= 0 || !utf8.ValidString(s) {
			return nil, errors.New("dbus: argument is not a short valid string")
		}
	}
	var body encoder
	var sig strings.Builder
	for _, a := range args {
		switch v := a.(type) {
		case string:
			if len(v) > 255 || strings.IndexByte(v, 0) >= 0 || !utf8.ValidString(v) {
				return nil, errors.New("dbus: argument is not a short valid string")
			}
			body.str(v)
			sig.WriteByte('s')
		case uint64:
			body.align(8)
			body.b = binary.LittleEndian.AppendUint64(body.b, v)
			sig.WriteByte('t')
		default:
			return nil, fmt.Errorf("dbus: argument of type %T is not supported", a)
		}
	}
	if sig.Len() > 255 {
		return nil, errors.New("dbus: too many arguments")
	}
	h := encoder{b: []byte{'l', TypeMethodCall, 0, 1}}
	h.b = binary.LittleEndian.AppendUint32(h.b, uint32(len(body.b))) //nolint:gosec // G115: bounded above
	h.b = binary.LittleEndian.AppendUint32(h.b, serial)
	h.b = binary.LittleEndian.AppendUint32(h.b, 0) // field array length, below
	h.field(fieldPath, 'o', path)
	if iface != "" {
		h.field(fieldInterface, 's', iface)
	}
	h.field(fieldMember, 's', member)
	h.field(fieldDestination, 's', dest)
	if sig.Len() > 0 {
		h.field(fieldSignature, 'g', sig.String())
	}
	binary.LittleEndian.PutUint32(h.b[12:], uint32(len(h.b)-16)) //nolint:gosec // G115: bounded above
	h.align(8)
	return append(h.b, body.b...), nil
}

// Conn is one authenticated connection to a bus.
type Conn struct {
	c      net.Conn
	r      *bufio.Reader
	serial uint32
}

// maxAuthLine bounds a line of the authentication exchange.
const maxAuthLine = 512

// Dial connects to the bus socket at path, authenticates with EXTERNAL as
// uid and says Hello, all within ctx's deadline (which stays on the
// connection for later calls).
func Dial(ctx context.Context, path string, uid int) (*Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("dbus: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	conn := &Conn{c: c, r: bufio.NewReaderSize(c, 4096)}
	if aerr := conn.auth(uid); aerr != nil {
		_ = c.Close()
		return nil, aerr
	}
	r, err := conn.Call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello")
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if s, serr := r.Strings(); serr != nil || len(s) != 1 {
		_ = c.Close()
		return nil, errors.New("dbus: malformed Hello reply")
	}
	return conn, nil
}

// auth is the EXTERNAL exchange: a nul byte, "AUTH EXTERNAL <hex of the
// decimal uid>", "OK <guid>" from the bus, then "BEGIN".
func (c *Conn) auth(uid int) error {
	id := hex.EncodeToString([]byte(strconv.Itoa(uid)))
	if _, err := c.c.Write([]byte("\x00AUTH EXTERNAL " + id + "\r\n")); err != nil {
		return fmt.Errorf("dbus: auth: %w", err)
	}
	line, err := c.line()
	if err != nil {
		return err
	}
	guid, ok := strings.CutPrefix(line, "OK ")
	if _, herr := hex.DecodeString(guid); !ok || herr != nil || len(guid) != 32 {
		return errors.New("dbus: authentication was not accepted")
	}
	if _, err := c.c.Write([]byte("BEGIN\r\n")); err != nil {
		return fmt.Errorf("dbus: auth: %w", err)
	}
	return nil
}

func (c *Conn) line() (string, error) {
	var b []byte
	for len(b) < maxAuthLine {
		ch, err := c.r.ReadByte()
		if err != nil {
			return "", fmt.Errorf("dbus: auth: %w", err)
		}
		if ch == '\n' {
			return strings.TrimSuffix(string(b), "\r"), nil
		}
		b = append(b, ch)
	}
	return "", errors.New("dbus: auth line too long")
}

// Call sends a method call with string and uint64 arguments (marshal) and
// returns its reply;
// an ERROR reply is returned as *Error. Other messages (signals) read
// meanwhile are skipped, at most maxReplies of them.
func (c *Conn) Call(dest, path, iface, member string, args ...any) (*Message, error) {
	c.serial++
	msg, err := marshal(c.serial, dest, path, iface, member, args)
	if err != nil {
		return nil, err
	}
	if _, err := c.c.Write(msg); err != nil {
		return nil, fmt.Errorf("dbus: %w", err)
	}
	for range maxReplies {
		m, err := ReadMessage(c.r)
		if err != nil {
			return nil, err
		}
		if (m.Type != TypeMethodReturn && m.Type != TypeError) || m.ReplySerial != c.serial {
			continue
		}
		if m.Type == TypeError {
			e := &Error{Name: m.ErrorName}
			if s, err := m.Strings(); err == nil && len(s) > 0 {
				e.Message = s[0]
			}
			return nil, e
		}
		return m, nil
	}
	return nil, errors.New("dbus: no reply")
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }
