// Package pathx holds the path rules shared by the gate and the helper
// (docs/POLICY.md §3): clean absolute path validation, component-boundary
// containment, longest-root selection and the deny/protected glob matcher.
// It is pure Go and has no Linux dependencies.
package pathx

import (
	"errors"
)

// MaxPathBytes is the longest path the gate and helper accept.
const MaxPathBytes = 4096

// Path validation errors.
var (
	ErrEmpty       = errors.New("path is empty")
	ErrTooLong     = errors.New("path is longer than 4096 bytes")
	ErrNUL         = errors.New("path contains NUL")
	ErrNotAbsolute = errors.New("path is not absolute")
	ErrNotClean    = errors.New("path is not clean")
)

// CheckClean reports whether p is an absolute, already-clean path: no "." or
// ".." components, no repeated or trailing slash (except "/" itself), no NUL,
// at most MaxPathBytes. Unclean input is rejected, never cleaned.
func CheckClean(p string) error {
	return errors.New("not implemented")
}

// Within reports whether p equals root or lies beneath it on a component
// boundary. Both must be clean absolute paths.
func Within(root, p string) bool {
	return false
}

// Rel returns p relative to root ("." for root itself). p must be Within root.
func Rel(root, p string) string {
	return ""
}

// Longest returns the longest root that p is Within.
func Longest(roots []string, p string) (string, bool) {
	return "", false
}
