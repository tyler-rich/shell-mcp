package template

import (
	"strings"
	"testing"
)

type fuzzResolver struct{}

func (fuzzResolver) ResolvePath(v string, write bool) (string, error) {
	if write {
		return "/w" + v, nil
	}
	return "/r" + v, nil
}

func (fuzzResolver) MatchUnit(v string) bool { return strings.HasSuffix(v, ".service") }

// FuzzParseAndMatch: tokens and args are split on \x1f. Parsing and
// matching never panic; a match returns exactly one value per argument;
// every placeholder value passed through obeys the universal rules; literal
// tokens are passed through unchanged; a template never matches a different
// number of arguments.
func FuzzParseAndMatch(f *testing.F) {
	f.Add("status\x1f-x", "status\x1f-x")
	f.Add("show\x1f{path:read}", "show\x1f/srv/app/x")
	f.Add("w\x1f{path:write}", "w\x1f/srv/app/config/y")
	f.Add("{int:1-100}", "7")
	f.Add("{enum:a|b|c}", "b")
	f.Add("{regex:^a|b$}", "xb")
	f.Add("{unit}", "example-app.service")
	f.Add("{regex:^[a-z]+$}", "-rf")
	f.Fuzz(func(t *testing.T, tpl, args string) {
		tokens := strings.Split(tpl, "\x1f")
		parsed, err := Parse(tokens)
		if err != nil {
			return
		}
		if got := parsed.String(); strings.Join(got, "\x1f") != tpl {
			t.Fatalf("String() = %q, want %q", got, tokens)
		}
		in := strings.Split(args, "\x1f")
		out, err := Match([]Template{parsed}, in, fuzzResolver{})
		if err != nil {
			return
		}
		if len(out) != len(in) || len(in) != len(parsed.Tokens) {
			t.Fatalf("matched %d args to %d tokens, returned %d", len(in), len(parsed.Tokens), len(out))
		}
		for i, tok := range parsed.Tokens {
			if tok.Kind == Literal {
				if out[i] != in[i] || in[i] != tok.Literal {
					t.Fatalf("literal %q changed to %q", tok.Literal, out[i])
				}
				continue
			}
			if CheckValue(in[i]) != nil || CheckValue(out[i]) != nil {
				t.Fatalf("placeholder %q accepted value %q -> %q", tok.raw, in[i], out[i])
			}
		}
	})
}
