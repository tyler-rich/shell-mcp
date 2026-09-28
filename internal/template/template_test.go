package template

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeResolver struct {
	units []string
}

var errDenied = errors.New("denied")

func (f fakeResolver) ResolvePath(v string, write bool) (string, error) {
	switch {
	case strings.HasPrefix(v, "/srv/app/"):
		if write && !strings.HasPrefix(v, "/srv/app/config/") {
			return "", errDenied
		}
		return "/real" + v, nil
	default:
		return "", errDenied
	}
}

func (f fakeResolver) MatchUnit(v string) bool { return slices.Contains(f.units, v) }

func mustParse(t *testing.T, tokens ...string) Template {
	t.Helper()
	tpl, err := Parse(tokens)
	if err != nil {
		t.Fatalf("Parse(%q): %v", tokens, err)
	}
	return tpl
}

func TestParseRejects(t *testing.T) {
	bad := [][]string{
		{"{path}"}, {"{path:exec}"}, {"{int}"}, {"{int:5-1}"}, {"{int:-1-5}"}, {"{int:a-b}"}, {"{int:1-2-3}"},
		{"{int:1-99999999999999999999}"}, {"{enum:}"}, {"{enum:a||b}"}, {"{enum:a|-b}"}, {"{enum:a|a}"},
		{"{regex:abc}"}, {"{regex:^abc}"}, {"{regex:abc$}"}, {"{regex:^(unclosed$}"}, {"{regex:^" + strings.Repeat("a", 256) + "$}"},
		{"{regex:^a\\$}"}, {"{unknown}"}, {"{unit:x}"}, {"{}"}, {"lit\x00"}, {strings.Repeat("a", MaxValueBytes+1)},
		make([]string, MaxTokens+1),
	}
	for _, tokens := range bad {
		if _, err := Parse(tokens); err == nil {
			t.Errorf("Parse(%q) accepted", tokens)
		}
	}
	good := [][]string{
		{}, {"status"}, {"-x", "--flag=1"}, {"{path:read}"}, {"{path:write}"}, {"{unit}"}, {"{int:0-10}"},
		{"{enum:app.example.test|api.example.test}"}, {"{regex:^[a-z]+$}"}, {"{regex:^a|b$}"}, {""},
	}
	for _, tokens := range good {
		if _, err := Parse(tokens); err != nil {
			t.Errorf("Parse(%q) = %v", tokens, err)
		}
	}
}

func TestMatchExact(t *testing.T) {
	r := fakeResolver{units: []string{"example-app.service"}}
	tpls := []Template{
		mustParse(t, "status"),
		mustParse(t, "status", "-x"),
		mustParse(t, "list", "-H", "-o", "name,size"),
		mustParse(t, "show", "{path:read}"),
		mustParse(t, "write", "{path:write}"),
		mustParse(t, "unit", "{unit}"),
		mustParse(t, "n", "{int:1-100}"),
		mustParse(t, "--domain", "{enum:app.example.test|api.example.test}"),
		mustParse(t, "re", "{regex:^a|b$}"),
	}
	ok := map[string][]string{
		"status":                    {"status"},
		"status -x":                 {"status", "-x"},
		"list -H -o name,size":      {"list", "-H", "-o", "name,size"},
		"show /srv/app/x":           {"show", "/real/srv/app/x"},
		"write /srv/app/config/y":   {"write", "/real/srv/app/config/y"},
		"unit example-app.service":  {"unit", "example-app.service"},
		"n 7":                       {"n", "7"},
		"n 100":                     {"n", "100"},
		"--domain api.example.test": {"--domain", "api.example.test"},
		"re a":                      {"re", "a"},
		"re b":                      {"re", "b"},
	}
	for in, want := range ok {
		got, err := Match(tpls, strings.Fields(in), r)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("Match(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	noMatch := []string{
		"", "status -y", "status -x extra", "statu", "list -H -o name", "unit other.service", "n 0", "n 101", "n 007",
		"n +7", "n 7.0", "--domain evil.example.test", "re ab", "re xb", "re ax", "--domain",
	}
	for _, in := range noMatch {
		if got, err := Match(tpls, strings.Fields(in), r); err == nil {
			t.Errorf("Match(%q) = %q, want error", in, got)
		}
	}
}

func TestMatchUniversalRules(t *testing.T) {
	r := fakeResolver{units: []string{"-evil.service"}}
	tpls := []Template{mustParse(t, "re", "{regex:^.*$}"), mustParse(t, "unit", "{unit}"), mustParse(t, "show", "{path:read}")}
	for _, args := range [][]string{
		{"re", "-rf"}, {"re", "--output=/etc/x"}, {"re", "a\x00b"}, {"re", "a\nb"}, {"re", "a\rb"},
		{"re", strings.Repeat("a", MaxValueBytes+1)}, {"unit", "-evil.service"},
	} {
		_, err := Match(tpls, args, r)
		var ve *ValueError
		if !errors.As(err, &ve) {
			t.Errorf("Match(%q) = %v, want *ValueError", args, err)
		}
	}
	// A path that fails resolution is a *PathError wrapping the resolver's error.
	_, err := Match(tpls, []string{"show", "/etc/shadow"}, r)
	var pe *PathError
	if !errors.As(err, &pe) || !errors.Is(err, errDenied) {
		t.Fatalf("path failure = %v", err)
	}
	// Relative and unclean paths never reach the resolver.
	for _, p := range []string{"srv/app/x", "/srv/app/../x", "/srv/app/x/"} {
		if _, err := Match(tpls, []string{"show", p}, r); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	// Literals may start with "-": they are the policy author's, not the caller's.
	if _, err := Match([]Template{mustParse(t, "-x")}, []string{"-x"}, r); err != nil {
		t.Fatalf("dash literal: %v", err)
	}
}

func TestMatchWriteRequiresWriteRoot(t *testing.T) {
	r := fakeResolver{}
	tpls := []Template{mustParse(t, "w", "{path:write}")}
	if _, err := Match(tpls, []string{"w", "/srv/app/x"}, r); err == nil {
		t.Fatal("read-root path accepted for {path:write}")
	}
}

func TestTooManyArgs(t *testing.T) {
	args := make([]string, MaxTokens+1)
	if _, err := Match([]Template{mustParse(t)}, args, fakeResolver{}); err == nil {
		t.Fatal("accepted")
	}
}

func TestStringRoundTrip(t *testing.T) {
	in := []string{"compose", "-f", "{path:read}", "ps", "{enum:a|b}", "{int:1-5}", "{regex:^x$}", "{unit}"}
	if got := mustParse(t, in...).String(); !slices.Equal(got, in) {
		t.Fatalf("String() = %q", got)
	}
	if !mustParse(t, "{path:write}").UsesPathWrite() || mustParse(t, "{path:read}").UsesPathWrite() {
		t.Fatal("UsesPathWrite")
	}
	if !mustParse(t, "{unit}").UsesUnit() {
		t.Fatal("UsesUnit")
	}
}
