package pathx

import "errors"

// Glob is a compiled deny/protected pattern (docs/POLICY.md §3).
//
// Semantics, component-wise over "/"-separated paths:
//   - A pattern starts with "/" or with "**/"; "**/x" means "/**/x".
//   - "**" as a whole component matches zero or more path components.
//   - "*" inside a component matches any run of characters within that one
//     component, including a leading dot (unlike a shell).
//   - Every other character is literal. "?", "[", "]", "{", "}" and "\" are
//     rejected so that no pattern means something other than it appears to.
//   - Empty, "." and ".." components are rejected.
type Glob struct {
	raw   string
	comps []string
}

// CompileGlob parses a deny or protected pattern.
func CompileGlob(s string) (Glob, error) {
	return Glob{}, errors.New("not implemented")
}

// String returns the pattern as written.
func (g Glob) String() string { return g.raw }

// Anchored reports whether the pattern starts with a literal component
// (its position in the tree is fixed) rather than "**".
func (g Glob) Anchored() bool { return false }

// Match reports whether the clean absolute path p matches the pattern exactly.
func (g Glob) Match(p string) bool { return false }

// MayContain reports whether some path strictly beneath the clean absolute
// directory dir could match the pattern.
func (g Glob) MayContain(dir string) bool { return false }

// Matcher is a set of globs.
type Matcher struct {
	globs []Glob
}

// NewMatcher compiles every pattern; the first error is returned.
func NewMatcher(patterns []string) (*Matcher, error) {
	return nil, errors.New("not implemented")
}

// Add appends compiled globs to the matcher.
func (m *Matcher) Add(g ...Glob) { m.globs = append(m.globs, g...) }

// Patterns returns the patterns as written, in order.
func (m *Matcher) Patterns() []string { return nil }

// Covers reports whether p, or any ancestor of p, matches a pattern: a
// pattern that matches a directory also covers everything beneath it.
func (m *Matcher) Covers(p string) bool { return false }

// MayContain reports whether some path strictly beneath dir could match a
// pattern. When anchoredOnly is set, patterns starting with "**" are
// ignored (they can match beneath any directory).
func (m *Matcher) MayContain(dir string, anchoredOnly bool) bool { return false }
