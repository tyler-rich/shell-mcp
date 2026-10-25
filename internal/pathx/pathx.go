// Package pathx holds the path rules shared by the gate and the helper
// (docs/POLICY.md §3): clean absolute path validation, component-boundary
// containment, longest-root selection and the deny/protected glob matcher.
// It is pure Go and has no Linux dependencies.
package pathx

import (
	"errors"
	"path"
	"strings"
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
	switch {
	case p == "":
		return ErrEmpty
	case len(p) > MaxPathBytes:
		return ErrTooLong
	case strings.IndexByte(p, 0) >= 0:
		return ErrNUL
	case p[0] != '/':
		return ErrNotAbsolute
	case path.Clean(p) != p:
		return ErrNotClean
	}
	return nil
}

// Within reports whether p equals root or lies beneath it on a component
// boundary. Both must be clean absolute paths.
func Within(root, p string) bool {
	if p == root || root == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, root) && len(p) > len(root) && p[len(root)] == '/'
}

// Rel returns p relative to root ("." for root itself). p must be Within root.
func Rel(root, p string) string {
	if p == root {
		return "."
	}
	if root == "/" {
		return p[1:]
	}
	return p[len(root)+1:]
}

// Longest returns the longest root that p is Within.
func Longest(roots []string, p string) (string, bool) {
	best, found := "", false
	for _, r := range roots {
		if Within(r, p) && (!found || len(r) > len(best)) {
			best, found = r, true
		}
	}
	return best, found
}

// split returns the components of a clean absolute path ("/" has none).
func split(p string) []string {
	if p == "/" {
		return nil
	}
	return strings.Split(p[1:], "/")
}
