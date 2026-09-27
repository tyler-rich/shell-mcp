// Package template is the argv-template engine shared by the gate and the
// helper (docs/POLICY.md §4). It is pure Go: paths and unit names are
// resolved through a caller-supplied Resolver so each binary applies its own
// roots and patterns.
package template

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
)

// Limits.
const (
	MaxTokens        = 64   // tokens per template, and args per request
	MaxValueBytes    = 1024 // placeholder values and literals
	MaxRegexParam    = 256  // characters in a {regex:…} parameter
	MaxEnumOptions   = 64
	MaxTemplateCount = 64 // templates per command
	maxUnitBytes     = 256
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
	Kind     Kind
	Literal  string // Literal only
	raw      string
	min, max int64
	enum     []string
	re       *regexp.Regexp
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

// unitRE is the character set systemd accepts in unit names (plus the
// escape character), without a leading "-".
var unitRE = regexp.MustCompile(`^[A-Za-z0-9:_.\\@][A-Za-z0-9:_.\\@-]*$`)

// Parse parses one template.
func Parse(tokens []string) (Template, error) {
	if len(tokens) > MaxTokens {
		return Template{}, fmt.Errorf("template has more than %d tokens", MaxTokens)
	}
	out := Template{Tokens: make([]Token, 0, len(tokens))}
	for i, s := range tokens {
		tok, err := parseToken(s)
		if err != nil {
			return Template{}, fmt.Errorf("token %d: %w", i+1, err)
		}
		out.Tokens = append(out.Tokens, tok)
	}
	return out, nil
}

func parseToken(s string) (Token, error) {
	if len(s) > MaxValueBytes {
		return Token{}, fmt.Errorf("longer than %d bytes", MaxValueBytes)
	}
	if strings.IndexByte(s, 0) >= 0 {
		return Token{}, errors.New("contains NUL")
	}
	if !(strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) {
		return Token{Kind: Literal, Literal: s, raw: s}, nil
	}
	// Any {…} token must be a known placeholder: a literal that looks like
	// one would be ambiguous.
	body := s[1 : len(s)-1]
	typ, param, hasParam := strings.Cut(body, ":")
	tok := Token{raw: s}
	switch {
	case typ == "path" && hasParam && param == "read":
		tok.Kind = PathRead
	case typ == "path" && hasParam && param == "write":
		tok.Kind = PathWrite
	case typ == "unit" && !hasParam:
		tok.Kind = Unit
	case typ == "int" && hasParam:
		lo, hi, ok := strings.Cut(param, "-")
		minV, err1 := parseDecimal(lo)
		maxV, err2 := parseDecimal(hi)
		if !ok || err1 != nil || err2 != nil || minV > maxV {
			return Token{}, fmt.Errorf("%s: want {int:MIN-MAX} with 0 <= MIN <= MAX", s)
		}
		tok.Kind, tok.min, tok.max = Int, minV, maxV
	case typ == "enum" && hasParam:
		opts := strings.Split(param, "|")
		if len(opts) > MaxEnumOptions {
			return Token{}, fmt.Errorf("%s: more than %d options", s, MaxEnumOptions)
		}
		seen := map[string]bool{}
		for _, o := range opts {
			if err := CheckValue(o); err != nil || o == "" {
				return Token{}, fmt.Errorf("%s: option %q is empty or breaks the placeholder rules", s, o)
			}
			if seen[o] {
				return Token{}, fmt.Errorf("%s: duplicate option %q", s, o)
			}
			seen[o] = true
		}
		tok.Kind, tok.enum = Enum, opts
	case typ == "regex" && hasParam:
		re, err := compileAnchored(param)
		if err != nil {
			return Token{}, fmt.Errorf("%s: %w", s, err)
		}
		tok.Kind, tok.re = Regex, re
	default:
		return Token{}, fmt.Errorf("%s: unknown placeholder", s)
	}
	return tok, nil
}

// parseDecimal accepts canonical non-negative decimal integers only: no
// sign, no leading zeros (except "0" itself), no spaces.
func parseDecimal(s string) (int64, error) {
	if s == "" || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("not a canonical decimal")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a canonical decimal")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// compileAnchored compiles a {regex:^…$} parameter. The written pattern
// must begin with ^ and end with an unescaped $, and is matched against the
// whole value regardless of alternation inside it.
func compileAnchored(param string) (*regexp.Regexp, error) {
	if len(param) > MaxRegexParam {
		return nil, fmt.Errorf("longer than %d characters", MaxRegexParam)
	}
	if !strings.HasPrefix(param, "^") || !strings.HasSuffix(param, "$") || strings.HasSuffix(param, `\$`) {
		return nil, errors.New("regex must be anchored with ^…$")
	}
	re, err := regexp.Compile(`\A(?:` + param + `)\z`)
	if err != nil {
		return nil, errors.New("regex does not compile")
	}
	return re, nil
}

// String renders the template as written.
func (t Template) String() []string {
	out := make([]string, len(t.Tokens))
	for i, tok := range t.Tokens {
		out[i] = tok.raw
	}
	return out
}

// UsesPathWrite reports whether the template has a {path:write} placeholder.
func (t Template) UsesPathWrite() bool { return t.uses(PathWrite) }

// UsesUnit reports whether the template has a {unit} placeholder.
func (t Template) UsesUnit() bool { return t.uses(Unit) }

func (t Template) uses(k Kind) bool {
	for _, tok := range t.Tokens {
		if tok.Kind == k {
			return true
		}
	}
	return false
}

// CheckValue applies the universal placeholder rules: no leading "-", no
// NUL, no newline or carriage return, at most MaxValueBytes.
func CheckValue(v string) error {
	switch {
	case len(v) > MaxValueBytes:
		return &ValueError{fmt.Sprintf("is longer than %d bytes", MaxValueBytes)}
	case strings.HasPrefix(v, "-"):
		return &ValueError{"begins with '-'"}
	case strings.ContainsAny(v, "\x00\n\r"):
		return &ValueError{"contains NUL or a line break"}
	}
	return nil
}

// Match returns the resolved arguments (without argv[0]) for the first
// template that args match exactly. If none matches it returns ErrNoMatch,
// a *ValueError, or a *PathError, preferring the most specific failure of a
// template whose literals and token count matched.
func Match(templates []Template, args []string, r Resolver) ([]string, error) {
	if len(args) > MaxTokens {
		return nil, fmt.Errorf("more than %d arguments: %w", MaxTokens, ErrNoMatch)
	}
	var best error
	for _, t := range templates {
		out, err := t.match(args, r)
		if err == nil {
			return out, nil
		}
		if rank(err) > rank(best) {
			best = err
		}
	}
	if best == nil {
		best = ErrNoMatch
	}
	return nil, best
}

func rank(err error) int {
	var pe *PathError
	var ve *ValueError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &pe):
		return 3
	case errors.As(err, &ve):
		return 2
	}
	return 1
}

func (t Template) match(args []string, r Resolver) ([]string, error) {
	if len(args) != len(t.Tokens) {
		return nil, ErrNoMatch
	}
	// Literals first, so a structurally different template never reports a
	// placeholder error.
	for i, tok := range t.Tokens {
		if tok.Kind == Literal && args[i] != tok.Literal {
			return nil, ErrNoMatch
		}
	}
	out := make([]string, len(args))
	for i, tok := range t.Tokens {
		v := args[i]
		if tok.Kind == Literal {
			out[i] = v
			continue
		}
		if err := CheckValue(v); err != nil {
			return nil, err
		}
		switch tok.Kind {
		case PathRead, PathWrite:
			if err := pathx.CheckClean(v); err != nil {
				return nil, &ValueError{"is not an absolute clean path"}
			}
			p, err := r.ResolvePath(v, tok.Kind == PathWrite)
			if err != nil {
				return nil, &PathError{err}
			}
			if err := CheckValue(p); err != nil {
				return nil, err
			}
			out[i] = p
		case Unit:
			if len(v) > maxUnitBytes || !unitRE.MatchString(v) || !r.MatchUnit(v) {
				return nil, ErrNoMatch
			}
			out[i] = v
		case Int:
			n, err := parseDecimal(v)
			if err != nil || n < tok.min || n > tok.max {
				return nil, ErrNoMatch
			}
			out[i] = v
		case Enum:
			found := false
			for _, o := range tok.enum {
				if v == o {
					found = true
					break
				}
			}
			if !found {
				return nil, ErrNoMatch
			}
			out[i] = v
		case Regex:
			if !tok.re.MatchString(v) {
				return nil, ErrNoMatch
			}
			out[i] = v
		}
	}
	return out, nil
}
