package template

import (
	"os"
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

// ResolveReadFD opens the null device for any value, so that every
// {path:read:fd} that passes the value rules gets a real descriptor.
func (fuzzResolver) ResolveReadFD(v string) (*os.File, string, error) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		return nil, "", err
	}
	return f, "/r" + v, nil
}

func (fuzzResolver) MatchUnit(v string) bool { return strings.HasSuffix(v, ".service") }

// FuzzParseAndMatch: tokens and args are split on \x1f. Parsing and
// matching never panic; a match returns exactly one value per argument;
// every placeholder value passed through obeys the universal rules; literal
// tokens are passed through unchanged; a template never matches a different
// number of arguments; the k-th {path:read:fd} becomes /dev/fd/(4+k) with
// one descriptor for each, in order, and a template never has more than
// MaxFDTokens of them.
func FuzzParseAndMatch(f *testing.F) {
	f.Add("status\x1f-x", "status\x1f-x")
	f.Add("show\x1f{path:read}", "show\x1f/srv/app/x")
	f.Add("w\x1f{path:write}", "w\x1f/srv/app/config/y")
	f.Add("{int:1-100}", "7")
	f.Add("{enum:a|b|c}", "b")
	f.Add("{regex:^a|b$}", "xb")
	f.Add("{unit}", "example-app.service")
	f.Add("{regex:^[a-z]+$}", "-rf")
	f.Add("cat\x1f{path:read:fd}", "cat\x1f/srv/app/x")
	f.Add("diff\x1f{path:read:fd}\x1f{path:read:fd}", "diff\x1f/srv/app/a\x1f/srv/app/b")
	f.Add("{path:read:fd}\x1f{int:1-2}", "/srv/app/a\x1f9")
	f.Fuzz(func(t *testing.T, tpl, args string) {
		tokens := strings.Split(tpl, "\x1f")
		parsed, err := Parse(tokens)
		if err != nil {
			return
		}
		if got := parsed.String(); strings.Join(got, "\x1f") != tpl {
			t.Fatalf("String() = %q, want %q", got, tokens)
		}
		fds := 0
		for _, tok := range parsed.Tokens {
			if tok.Kind == PathReadFD {
				fds++
			}
		}
		if fds > MaxFDTokens {
			t.Fatalf("parsed a template with %d {path:read:fd}", fds)
		}
		in := strings.Split(args, "\x1f")
		m, err := MatchFD([]Template{parsed}, in, fuzzResolver{})
		if err != nil {
			return
		}
		defer m.Close()
		out := m.Args
		if len(out) != len(in) || len(in) != len(parsed.Tokens) {
			t.Fatalf("matched %d args to %d tokens, returned %d", len(in), len(parsed.Tokens), len(out))
		}
		if len(m.Descriptors) != fds {
			t.Fatalf("%d descriptors for %d {path:read:fd}", len(m.Descriptors), fds)
		}
		k := 0
		for i, tok := range parsed.Tokens {
			switch tok.Kind {
			case Literal:
				if out[i] != in[i] || in[i] != tok.Literal {
					t.Fatalf("literal %q changed to %q", tok.Literal, out[i])
				}
				continue
			case PathReadFD:
				d := m.Descriptors[k]
				if d.FD != FirstFD+k || out[i] != FDPath(d.FD) || d.Path != "/r"+in[i] || d.File == nil {
					t.Fatalf("{path:read:fd} %d: %q as %+v", k, out[i], d)
				}
				k++
				if CheckValue(in[i]) != nil {
					t.Fatalf("placeholder %q accepted value %q", tok.raw, in[i])
				}
				continue
			}
			if CheckValue(in[i]) != nil || CheckValue(out[i]) != nil {
				t.Fatalf("placeholder %q accepted value %q -> %q", tok.raw, in[i], out[i])
			}
		}
	})
}
