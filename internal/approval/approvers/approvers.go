// Package approvers reads and writes the approvers secret file
// (SHELL_MCP_APPROVERS_FILE): one "<name> <base32 seed>" per line
// (docs/handoff/S4B-APPROVAL.md §6.4, §6.7).
//
// A seed is an approval, so the rules are strict and fail closed: names
// match ^[a-z][a-z0-9-]{0,31}$, seeds are canonical unpadded base32 of
// 160..512 bits, there are no duplicates, at least one approver and at most
// the configured maximum, and a file accessible by group or other is refused.
// Refusals name a line number, never the line's text, so no seed (or
// anything that might be one) is ever repeated in an error. On Windows the
// file mode is never strict enough, so loading fails closed there.
package approvers

import (
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Bounds of the file.
const (
	// MaxApprovers is the upper bound of SHELL_MCP_APPROVAL_MAX_APPROVERS.
	MaxApprovers = 8
	// DefaultMaxApprovers is its default: exactly one approver.
	DefaultMaxApprovers = 1
	// MinSeedBytes is the shortest seed: 160 bits.
	MinSeedBytes = 20
	// MaxSeedBytes is the longest seed: 512 bits.
	MaxSeedBytes = 64

	maxFileBytes = 64 << 10
	maxEnvVar    = "SHELL_MCP_APPROVAL_MAX_APPROVERS"
)

// Refusals of Add and Remove that are about the request, not the file.
var (
	ErrDuplicate = errors.New("approvers: an approver with this name is already enrolled")
	ErrMultiple  = errors.New("approvers: the file already holds an approver")
	ErrFull      = errors.New("approvers: the file already holds the most approvers allowed (8)")
	ErrUnknown   = errors.New("approvers: no approver with this name is enrolled")
)

// Error is a refusal of the file or of a setting. Reason is one line and
// never contains a seed or any other text read from the file.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

func errorf(format string, args ...any) *Error {
	return &Error{Reason: fmt.Sprintf(format, args...)}
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidName reports whether name is a valid approver name.
func ValidName(name string) bool { return namePattern.MatchString(name) }

var seedEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Approver is one enrolled approver. Every formatting, JSON and slog path
// renders only its name.
type Approver struct {
	Name string
	seed []byte
}

// Seed returns a copy of the approver's seed.
func (a Approver) Seed() []byte { return append([]byte(nil), a.seed...) }

func (a Approver) String() string { return "approver " + a.Name }

// GoString implements fmt.GoStringer.
func (a Approver) GoString() string { return a.String() }

// Format implements fmt.Formatter so that no verb prints the seed.
func (a Approver) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// MarshalJSON implements json.Marshaler.
func (a Approver) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(a.Name)), nil }

// MarshalText implements encoding.TextMarshaler.
func (a Approver) MarshalText() ([]byte, error) { return []byte(a.Name), nil }

// LogValue implements slog.LogValuer.
func (a Approver) LogValue() slog.Value { return slog.StringValue(a.Name) }

// Seeds returns each approver's seed by name, for totp.New.
func Seeds(list []Approver) map[string][]byte {
	m := make(map[string][]byte, len(list))
	for _, a := range list {
		m[a.Name] = a.Seed()
	}
	return m
}

// ParseMaxApprovers reads SHELL_MCP_APPROVAL_MAX_APPROVERS: unset is 1;
// otherwise a decimal integer 1..8.
func ParseMaxApprovers(raw string, set bool) (int, error) {
	if !set {
		return DefaultMaxApprovers, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxApprovers || raw != strconv.Itoa(n) {
		return 0, errorf("%s must be an integer between 1 and %d (got %q)", maxEnvVar, MaxApprovers, raw)
	}
	return n, nil
}

// Parse parses the file's content: at least one and at most maxApprovers
// approvers (maxApprovers itself 1..8).
func Parse(data []byte, maxApprovers int) ([]Approver, error) {
	if maxApprovers < 1 || maxApprovers > MaxApprovers {
		return nil, errorf("%s must be between 1 and %d", maxEnvVar, MaxApprovers)
	}
	list, _, err := parse(data)
	if err != nil {
		return nil, err
	}
	switch {
	case len(list) == 0:
		return nil, errorf("the file holds no approver")
	case len(list) > maxApprovers:
		return nil, errorf("the file holds %d approvers, more than %s (%d)", len(list), maxEnvVar, maxApprovers)
	}
	return list, nil
}

// parse reads every line, allowing zero approvers, and returns the lines as
// written (without their endings) next to the approvers.
func parse(data []byte) ([]Approver, []string, error) {
	if len(data) == 0 {
		return nil, nil, nil
	}
	text := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > MaxApprovers {
		return nil, nil, errorf("the file holds more than %d lines, and %s allows at most %d approvers", MaxApprovers, maxEnvVar, MaxApprovers)
	}
	list := make([]Approver, 0, len(lines))
	seen := map[string]int{}
	for i, line := range lines {
		n := i + 1
		line = strings.TrimSuffix(line, "\r")
		lines[i] = line
		a, err := parseLine(line)
		if err != nil {
			return nil, nil, errorf("line %d: %s", n, err.Reason)
		}
		if first, dup := seen[a.Name]; dup {
			return nil, nil, errorf("line %d: duplicate approver name (also on line %d)", n, first)
		}
		seen[a.Name] = n
		list = append(list, a)
	}
	return list, lines, nil
}

func parseLine(line string) (Approver, *Error) {
	if line == "" {
		return Approver{}, errorf("empty line")
	}
	name, enc, ok := strings.Cut(line, " ")
	if !ok || strings.Contains(enc, " ") {
		return Approver{}, errorf(`expected "<name> <base32 seed>" separated by one space`)
	}
	if !ValidName(name) {
		return Approver{}, errorf("name must match %s", namePattern)
	}
	seed, err := decodeSeed(enc)
	if err != nil {
		return Approver{}, err
	}
	return Approver{Name: name, seed: seed}, nil
}

func decodeSeed(enc string) ([]byte, *Error) {
	if len(enc) > seedEncoding.EncodedLen(MaxSeedBytes) {
		return nil, errorf("seed is longer than %d bits", MaxSeedBytes*8)
	}
	upper := strings.ToUpper(enc)
	seed, err := seedEncoding.DecodeString(upper)
	// Canonical only: re-encoding must give the input back, so padding,
	// stray characters and set trailing bits are all refused.
	if err != nil || seedEncoding.EncodeToString(seed) != upper {
		return nil, errorf("seed is not canonical unpadded base32")
	}
	if len(seed) < MinSeedBytes {
		return nil, errorf("seed is shorter than %d bits", MinSeedBytes*8)
	}
	if len(seed) > MaxSeedBytes {
		return nil, errorf("seed is longer than %d bits", MaxSeedBytes*8)
	}
	return seed, nil
}

// Load reads and parses the file at path for the server: a regular file,
// not accessible by group or other, of at least one and at most maxApprovers
// approvers.
func Load(path string, maxApprovers int) ([]Approver, error) {
	data, err := readChecked(path)
	if err != nil {
		return nil, err
	}
	list, err := Parse(data, maxApprovers)
	if err != nil {
		return nil, prefixed(err)
	}
	return list, nil
}

// errMissing is readChecked's refusal of a missing file, which Add treats as
// empty.
var errMissing = &Error{Reason: "approvers file: cannot read file (it does not exist)"}

func prefixed(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return &Error{Reason: "approvers file: " + e.Reason}
	}
	return err
}

// readChecked reads path after checking, on the open file, that it is a
// regular file with no group or other access. It returns errors already
// prefixed with the source.
func readChecked(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errMissing
	}
	if err != nil {
		return nil, errorf("approvers file: cannot read file")
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, errorf("approvers file: cannot read file")
	}
	if !fi.Mode().IsRegular() {
		return nil, errorf("approvers file: not a regular file")
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, errorf("approvers file: accessible by group or other (mode %04o); it must be 0600 or stricter", perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, errorf("approvers file: cannot read file")
	}
	if len(data) > maxFileBytes {
		return nil, errorf("approvers file: exceeds %d bytes", maxFileBytes)
	}
	return data, nil
}

// EncodeSeed returns seed as unpadded upper-case base32, as the file and
// the otpauth URI carry it.
func EncodeSeed(seed []byte) string { return seedEncoding.EncodeToString(seed) }

// URI returns the otpauth URI an authenticator enrols from. Names are
// [a-z0-9-] and seeds base32, so nothing needs escaping.
func URI(name string, seed []byte) string {
	return "otpauth://totp/shell-mcp:" + name + "?secret=" + EncodeSeed(seed) +
		"&issuer=shell-mcp&algorithm=SHA1&digits=6&period=30"
}
