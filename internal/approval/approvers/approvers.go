// Package approvers reads and writes the approvers secret file: one
// "<name> <base32 seed>" per line (docs/handoff/S4B-APPROVAL.md §6.4, §6.7).
package approvers

import "errors"

// Bounds of the file.
const (
	MaxApprovers        = 8
	DefaultMaxApprovers = 1
	MinSeedBytes        = 20
	MaxSeedBytes        = 64
)

// Refusals of Add and Remove.
var (
	ErrDuplicate = errors.New("approvers: an approver with this name is already enrolled")
	ErrMultiple  = errors.New("approvers: the file already holds an approver")
	ErrFull      = errors.New("approvers: the file already holds the most approvers allowed")
	ErrUnknown   = errors.New("approvers: no approver with this name is enrolled")
)

// Error is a refusal of the file. Reason is one line and never contains a
// seed or any other text read from the file.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

// Approver is one enrolled approver.
type Approver struct {
	Name string
	seed []byte
}

// Seed returns a copy of the approver's seed.
func (Approver) Seed() []byte { return nil }

// ValidName reports whether name is a valid approver name.
func ValidName(string) bool { return false }

// ParseMaxApprovers reads SHELL_MCP_APPROVAL_MAX_APPROVERS.
func ParseMaxApprovers(string, bool) (int, error) { return 0, nil }

// Parse parses the file's content.
func Parse([]byte, int) ([]Approver, error) { return nil, nil }

// Load reads and parses the file at path.
func Load(string, int) ([]Approver, error) { return nil, nil }

// Seeds returns each approver's seed by name.
func Seeds([]Approver) map[string][]byte { return nil }

// EncodeSeed returns seed in base32.
func EncodeSeed([]byte) string { return "" }

// URI returns the otpauth URI.
func URI(string, []byte) string { return "" }

// Add enrols an approver.
func Add(string, string, []byte, bool) error { return nil }

// Remove removes an approver.
func Remove(string, string) error { return nil }

// List returns the enrolled names.
func List(string) ([]string, error) { return nil, nil }
