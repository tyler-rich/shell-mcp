// Package template is the argv-template engine shared by the gate and the
// helper (docs/POLICY.md §4). It is pure Go: paths and unit names are
// resolved through a caller-supplied Resolver so each binary applies its own
// roots and patterns.
package template

import "errors"

// Limits.
const (
	MaxTokens        = 64   // tokens per template, and args per request
	MaxValueBytes    = 1024 // placeholder values and literals
	MaxRegexParam    = 256  // characters in a {regex:…} parameter
	MaxEnumOptions   = 64
	MaxTemplateCount = 64 // templates per command
)

// Kind is a token kind.
type Kind int

// Token kinds.
const (
	Literal Kind = iota
	PathRead
	PathWrite
	Unit
	Int
	Enum
	Regex
)

// Token is one parsed template token.
type Token struct {
	Kind    Kind
	Literal string // Literal only
	raw     string
}

// Template is a parsed argv template.
type Template struct {
	Tokens []Token
}

// Resolver resolves typed placeholder values.
type Resolver interface {
	// ResolvePath returns the path to pass to the command for an absolute
	// clean value, resolved under the caller's read (write=false) or write
	// roots, or an error (typically a path-denied error).
	ResolvePath(value string, write bool) (string, error)
	// MatchUnit reports whether a unit name is allowed.
	MatchUnit(value string) bool
}

// Errors.
var (
	ErrNoMatch = errors.New("arguments match no template")
)

// ValueError reports a placeholder value that violates a universal rule.
type ValueError struct{ Reason string }

func (e *ValueError) Error() string { return "placeholder value " + e.Reason }

// PathError wraps a Resolver path failure; Err is the resolver's error.
type PathError struct{ Err error }

func (e *PathError) Error() string { return "path placeholder: " + e.Err.Error() }
func (e *PathError) Unwrap() error { return e.Err }

// Parse parses one template.
func Parse(tokens []string) (Template, error) {
	return Template{}, errors.New("not implemented")
}

// String renders the template as written.
func (t Template) String() []string { return nil }

// UsesPathWrite reports whether the template has a {path:write} placeholder.
func (t Template) UsesPathWrite() bool { return false }

// UsesUnit reports whether the template has a {unit} placeholder.
func (t Template) UsesUnit() bool { return false }

// CheckValue applies the universal placeholder rules: no leading "-", no
// NUL, no newline or carriage return, at most MaxValueBytes.
func CheckValue(v string) error { return errors.New("not implemented") }

// Match returns the resolved arguments (without argv[0]) for the first
// template that args match exactly. If none matches it returns ErrNoMatch,
// a *ValueError, or a *PathError, preferring the most specific failure of a
// template whose literals and token count matched.
func Match(templates []Template, args []string, r Resolver) ([]string, error) {
	return nil, errors.New("not implemented")
}
