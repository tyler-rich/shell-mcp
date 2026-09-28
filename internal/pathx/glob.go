package pathx

import (
	"errors"
	"fmt"
	"strings"
)

// maxGlobComponents bounds pattern length (and so matching cost).
const maxGlobComponents = 128

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
	raw     string
	comps   []string
	literal bool // every component matches by equality (LiteralGlob)
}

// LiteralGlob returns a Glob matching exactly the clean absolute path p,
// with no metacharacters: a host path such as the service account's home
// may legitimately contain "*" or "[".
func LiteralGlob(p string) (Glob, error) {
	if err := CheckClean(p); err != nil {
		return Glob{}, err
	}
	return Glob{raw: p, comps: split(p), literal: true}, nil
}

// CompileGlob parses a deny or protected pattern.
func CompileGlob(s string) (Glob, error) {
	if s == "" || len(s) > MaxPathBytes {
		return Glob{}, errors.New("pattern is empty or longer than 4096 bytes")
	}
	if strings.ContainsAny(s, "?[]{}\\\x00") {
		return Glob{}, fmt.Errorf("pattern %q: only * and ** are supported", s)
	}
	body := s
	switch {
	case strings.HasPrefix(s, "**/"):
		// "**/x" is "/**/x".
	case s == "/":
		return Glob{raw: s}, nil
	case strings.HasPrefix(s, "/"):
		body = s[1:]
	default:
		return Glob{}, fmt.Errorf("pattern %q must start with / or **/", s)
	}
	comps := strings.Split(body, "/")
	if len(comps) > maxGlobComponents {
		return Glob{}, fmt.Errorf("pattern %q has more than %d components", s, maxGlobComponents)
	}
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		switch {
		case c == "" || c == "." || c == "..":
			return Glob{}, fmt.Errorf("pattern %q has an empty, . or .. component", s)
		case strings.Contains(c, "**") && c != "**":
			return Glob{}, fmt.Errorf("pattern %q: ** must be a whole component", s)
		case c == "**" && len(out) > 0 && out[len(out)-1] == "**":
			continue // "**/**" is "**"
		}
		out = append(out, c)
	}
	return Glob{raw: s, comps: out}, nil
}

// String returns the pattern as written.
func (g Glob) String() string { return g.raw }

// Anchored reports whether the pattern starts with a literal component
// (its position in the tree is fixed) rather than "**".
func (g Glob) Anchored() bool { return g.literal || len(g.comps) == 0 || g.comps[0] != "**" }

// Match reports whether the clean absolute path p matches the pattern exactly.
func (g Glob) Match(p string) bool {
	return g.match(split(p), false)
}

// MayContain reports whether some path strictly beneath the clean absolute
// directory dir could match the pattern.
func (g Glob) MayContain(dir string) bool {
	return g.match(split(dir), true)
}

// match runs the component DP. With prefix set it answers "can some
// non-empty extension of path match", otherwise "does path match".
func (g Glob) match(path []string, prefix bool) bool {
	np, ns := len(g.comps), len(path)
	// seen/memo over (pattern index, path index); sizes are bounded by
	// maxGlobComponents and MaxPathBytes.
	memo := make([]int8, (np+1)*(ns+1)) // 0 unknown, 1 true, 2 false
	var rec func(i, j int) bool
	rec = func(i, j int) bool {
		k := i*(ns+1) + j
		if memo[k] != 0 {
			return memo[k] == 1
		}
		var r bool
		switch {
		case i == np:
			r = j == ns && !prefix
		case j == ns && prefix:
			// Path exhausted: anything beneath can still match the rest.
			r = true
		case !g.literal && g.comps[i] == "**":
			r = rec(i+1, j) || (j < ns && rec(i, j+1))
		case j == ns:
			r = false
		case g.literal:
			r = g.comps[i] == path[j] && rec(i+1, j+1)
		default:
			r = componentMatch(g.comps[i], path[j]) && rec(i+1, j+1)
		}
		if r {
			memo[k] = 1
		} else {
			memo[k] = 2
		}
		return r
	}
	return rec(0, 0)
}

// componentMatch matches one component against a pattern whose only
// metacharacter is "*" (any run, possibly empty). Greedy with backtracking
// to the last star: linear in practice, quadratic worst case on bounded input.
func componentMatch(pat, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pat) && pat[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(pat) && pat[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// Matcher is a set of globs.
type Matcher struct {
	globs []Glob
}

// NewMatcher compiles every pattern; the first error is returned.
func NewMatcher(patterns []string) (*Matcher, error) {
	m := &Matcher{}
	for _, p := range patterns {
		g, err := CompileGlob(p)
		if err != nil {
			return nil, err
		}
		m.globs = append(m.globs, g)
	}
	return m, nil
}

// Add appends compiled globs to the matcher.
func (m *Matcher) Add(g ...Glob) { m.globs = append(m.globs, g...) }

// Patterns returns the patterns as written, in order.
func (m *Matcher) Patterns() []string {
	out := make([]string, 0, len(m.globs))
	for _, g := range m.globs {
		out = append(out, g.raw)
	}
	return out
}

// Covers reports whether p, or any ancestor of p, matches a pattern: a
// pattern that matches a directory also covers everything beneath it.
func (m *Matcher) Covers(p string) bool {
	if m == nil {
		return false
	}
	comps := split(p)
	for n := len(comps); n >= 0; n-- {
		for _, g := range m.globs {
			if g.match(comps[:n], false) {
				return true
			}
		}
	}
	return false
}

// MayContain reports whether some path strictly beneath dir could match a
// pattern. When anchoredOnly is set, patterns starting with "**" are
// ignored (they can match beneath any directory).
func (m *Matcher) MayContain(dir string, anchoredOnly bool) bool {
	if m == nil {
		return false
	}
	comps := split(dir)
	for _, g := range m.globs {
		if anchoredOnly && !g.Anchored() {
			continue
		}
		if g.match(comps, true) {
			return true
		}
	}
	return false
}
