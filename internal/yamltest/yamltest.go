// Package yamltest pins what each of the project's YAML parsers accepts,
// refuses and decodes, so that a change of the YAML module (a new release,
// a new major) shows up as a test failure, never silently.
//
// One corpus covers the behaviours a strict loader depends on (unknown
// keys, duplicate keys, documents, line breaks, anchors and aliases, merge
// keys, scalar resolution, error positions) and every class in which
// go.yaml.in/yaml/v4 v4.0.0 was found to accept input v3 refuses or to read
// it differently (docs/ARCHIVE.md, 2026-11-08). Each parser supplies a
// Schema that places a value in its own fields, and a Run function that
// passes a document through its YAML layer; Pin compares the results with a
// golden file recorded from go.yaml.in/yaml/v3. Only tests import this
// package.
package yamltest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

// Schema places values in one parser's fields. Every builder returns a
// whole document; v is YAML text, inserted as it is.
type Schema struct {
	// Base is a document the YAML layer accepts. Its first line must be a
	// block mapping key with its value ("key: value" or "key:").
	Base string
	// Str is a document with v as the value of a string field.
	Str func(v string) string
	// Int is a document with v as the value of an integer field.
	Int func(v string) string
	// List is a document with v as the value of a list-of-strings field.
	List func(v string) string
	// Bool is a document with v as the value of a boolean field; nil when
	// the parser has none.
	Bool func(v string) string
	// Flow is a document with a flow mapping {inner} as the value of a
	// mapping field (the builder may add required pairs); MapKey is a
	// string field of that mapping.
	Flow   func(inner string) string
	MapKey string
}

// Case is one document of the corpus.
type Case struct {
	Name string
	Doc  string
}

// Corpus returns the documents for s, in a fixed order.
func Corpus(s *Schema) []Case {
	first, rest, _ := strings.Cut(s.Base, "\n")
	key, val, ok := strings.Cut(first, ":")
	if !ok {
		panic("yamltest: Base must start with a block mapping key")
	}
	padded := func(n int) string { // the first key, n spaces, then its colon
		return key + strings.Repeat(" ", n) + ":" + val + "\n" + rest
	}
	laughs := "[&a [x, x, x, x, x, x, x, x, x, x], &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]," +
		" &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b], &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]," +
		" &e [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d], &f [*e, *e, *e, *e, *e, *e, *e, *e, *e, *e]]"
	mk := s.MapKey
	c := []Case{
		// Strict mode, duplicates, wrong types.
		{"base", s.Base},
		{"unknown key", s.Base + "zzz_unknown: 1\n"},
		{"two unknown keys", s.Base + "zzz_one: 1\nzzz_two: 2\n"},
		{"unknown key in a mapping", s.Flow(mk + ": a, zzz_unknown: 1")},
		{"duplicate key", s.Base + first + "\n"},
		{"duplicate key quoted", s.Base + `"` + key + `":` + val + "\n"},
		{"duplicate key in a mapping", s.Flow(mk + ": a, " + mk + ": b")},
		{"string: a list", s.Str("[a]")},
		{"string: a mapping", s.Str("{a: b}")},
		{"list: a string", s.List("a")},
		{"int: text", s.Int("abc")},
		{"top level: a list", "- a\n"},
		{"top level: a string", "hello\n"},
		{"top level: block scalar at column 0", "|\n00000\n"},
		// Documents.
		{"empty", ""},
		{"comment only", "# only a comment\n"},
		{"document start only", "---\n"},
		{"document end only", "...\n"},
		{"two documents", s.Base + "---\n" + s.Base},
		{"empty second document", s.Base + "---\n"},
		{"second document broken", s.Base + "---\n[\n"},
		{"document end", s.Base + "...\n"},
		{"document end then comment", s.Base + "...\n# after\n"},
		{"directive 1.1", "%YAML 1.1\n---\n" + s.Base},
		{"directive 1.2", "%YAML 1.2\n---\n" + s.Base},
		{"directive 2.0", "%YAML 2.0\n---\n" + s.Base},
		// Error positions.
		{"unclosed flow at the end", s.Base + "zzz_unknown: [\n"},
		{"tab indentation", s.Base + "zzz_unknown:\n\tx: a\n"},
		{"bad indentation", s.Base + "  zzz_unknown: a\n"},
		{"depth over 10000", s.List(strings.Repeat("[", 10001) + strings.Repeat("]", 10001))},
		// Line breaks and characters.
		{"CR line breaks", strings.ReplaceAll(s.Base, "\n", "\r")},
		{"CRLF line breaks", strings.ReplaceAll(s.Base, "\n", "\r\n")},
		{"U+2028 in a comment, then a key", s.Base + "# c\u2028zzz_unknown: 1\n"},
		{"U+2028 in a comment, then a known key", "# c\u2028" + s.Base},
		{"U+2029 in a comment, then a known key", "# c\u2029" + s.Base},
		{"U+0085 in a comment, then a known key", "# c\u0085" + s.Base},
		{"CR in a comment, then a known key", "# c\r" + s.Base},
		{"U+2028 in a plain value", s.Str("a\u2028b")},
		{"U+2029 in a plain value", s.Str("a\u2029b")},
		{"U+0085 in a plain value", s.Str("a\u0085b")},
		{"U+2028 in a double-quoted value", s.Str("\"a\u2028b\"")},
		{"U+2028 in a single-quoted value", s.Str("'a\u2028b'")},
		{"escaped U+2028", s.Str(`"a\Lb"`)},
		{"escaped U+0085", s.Str(`"a\Nb"`)},
		{"escaped U+0080", s.Str(`"a\x80b"`)},
		{"U+007F in a plain value", s.Str("a\x7fb")},
		{"U+0080 in a plain value", s.Str("a\u0080b")},
		{"U+0086 in a plain value", s.Str("a\u0086b")},
		{"U+009F in a double-quoted value", s.Str("\"a\u009fb\"")},
		{"U+0085 in a double-quoted value", s.Str("\"a\u0085b\"")},
		{"U+007F in a comment", "# a\x7fb\n" + s.Base},
		{"U+0080 in a comment", "# a\u0080b\n" + s.Base},
		{"U+007F in a key", s.Base + "zzz\x7funknown: 1\n"},
		{"U+0001 in a plain value", s.Str("a\x01b")},
		{"NUL", s.Base + "# a\x00b\n"},
		{"byte-order mark", "\ufeff" + s.Base},
		{"byte-order mark inside a value", s.Str("a\ufeffb")},
		{"invalid UTF-8", s.Str("a\xffb")},
		{"UTF-16LE with U+007F", "\xff\xfe" + utf16le(s.Str("a\x7fb"))},
		{"UTF-16LE", "\xff\xfe" + utf16le(s.Base)},
		// Keys.
		{"empty key", s.Base + ": a\n"},
		{"empty key with a mapping value", s.Base + ":\n  x: a\n"},
		{"colon only", s.Base + ":\n"},
		{"empty key in a flow mapping", s.Flow(": a")},
		{"empty key in a flow list", s.List("[: a]")},
		{"explicit empty key", s.Base + "? \n: a\n"},
		{"explicit empty key in a flow mapping", s.Flow("? : a")},
		{"anchored empty key", s.Base + "&k : a\n"},
		{"null key", s.Base + "~: a\n"},
		{"key and colon 1024 characters apart", padded(1024 - len(key))},
		{"key and colon 1025 characters apart", padded(1025 - len(key))},
		{"key and colon 1100 characters apart", padded(1100)},
		{"long unknown key", s.Base + strings.Repeat("k", 1100) + ": a\n"},
		{"long explicit unknown key", s.Base + "? " + strings.Repeat("k", 1100) + "\n: a\n"},
		{"long key in a flow mapping", s.Flow(mk + strings.Repeat(" ", 1100) + ": a")},
		{"long anchor before a key", s.Base + "&" + strings.Repeat("a", 1100) + " zzz_unknown: a\n"},
		// Anchors, aliases, tags.
		{"anchor and alias", s.List("[&x a, *x]")},
		{"undefined alias", s.Str("*nope")},
		{"recursive alias", s.List("&r [*r]")},
		{"anchor name !", s.Str("&! a")},
		{"anchor name with a dot", s.List("[&a.b a, *a.b]")},
		{"alias expansion", s.List(laughs)},
		{"non-specific tag, empty", s.Str("!")},
		{"non-specific tag, text", s.Str("! a")},
		{"non-specific tag on an int", s.Int("!")},
		{"str tag on an int", s.Int("!!str 5")},
		{"int tag on quoted text", s.Int(`!!int "5"`)},
		{"custom tag", s.Str("!example a")},
		{"binary tag", s.Str("!!binary aGVsbG8=")},
		{"tag ended by a flow indicator", s.Flow(mk + ": !0")},
		{"tag ended by ]", s.List("[!!str]")},
		// Merge keys.
		{"merge", s.Flow("<<: {" + mk + ": a}")},
		{"merge, then the key", s.Flow("<<: {" + mk + ": a}, " + mk + ": b")},
		{"merge of a list", s.Flow("<<: [{" + mk + ": a}]")},
		{"merge with an unknown key", s.Flow("<<: {zzz_unknown: a}")},
		{"merge of a scalar", s.Flow("<<: a")},
		{"merge quoted", s.Flow(`"<<": {` + mk + `: a}`)},
		{"two merges", s.Flow("<<: {" + mk + ": a}, <<: {" + mk + ": b}")},
		{"<< as a string value", s.Str("<<")},
		{"<< in a list", s.List("[<<]")},
		// Flow context.
		{"colon before } in a flow mapping", s.Flow(mk + ":")},
		{"colon before ] in a flow list", s.List("[a:]")},
		{"colon before , in a flow list", s.List("[a:, b]")},
		{"pair in a flow list", s.List("[a: b]")},
		{"trailing comma", s.List("[a, b, ]")},
		{"comment in a flow list", s.List("[a, # c\n  b]")},
		// Scalars into strings.
		{"string 00000000", s.Str("00000000")},
		{"string true", s.Str("true")},
		{"string null", s.Str("null")},
		{"string ~", s.Str("~")},
		{"string empty", s.Str(`""`)},
		{"string -0", s.Str("-0")},
		{"string 0x1F", s.Str("0x1F")},
		{"string 1e3", s.Str("1e3")},
		{"string .inf", s.Str(".inf")},
		{"string yes", s.Str("yes")},
		{"string 2001-12-14", s.Str("2001-12-14")},
		{"string 1:20", s.Str("1:20")},
		{"string a:b", s.Str("a:b")},
		{"string a #b", s.Str("a #b")},
		{"string a#b", s.Str("a#b")},
		{"string literal block", s.Str("|\n  a\n  b")},
		{"string folded block", s.Str(">\n  a\n  b")},
		// Scalars into integers.
		{"int 00000000", s.Int("00000000")},
		{"int 0x10", s.Int("0x10")},
		{"int 0o17", s.Int("0o17")},
		{"int 017", s.Int("017")},
		{"int 0b101", s.Int("0b101")},
		{"int -0", s.Int("-0")},
		{"int -0.0", s.Int("-0.0")},
		{"int 1_000", s.Int("1_000")},
		{"int +5", s.Int("+5")},
		{"int 3.0", s.Int("3.0")},
		{"int 3.5", s.Int("3.5")},
		{"int 1e3", s.Int("1e3")},
		{"int .5", s.Int(".5")},
		{"int 9223372036854775808", s.Int("9223372036854775808")},
		{"int +18446744073709551615", s.Int("+18446744073709551615")},
		{"int quoted", s.Int(`"5"`)},
		{"int true", s.Int("true")},
		{"int null", s.Int("null")},
		{"int empty", s.Int(`""`)},
		{"int .inf", s.Int(".inf")},
	}
	if s.Bool != nil {
		for _, v := range []string{"true", "True", "TRUE", "yes", "on", "Off", "y", "n", "1", `"true"`, "null"} {
			c = append(c, Case{"bool " + v, s.Bool(v)})
		}
	}
	return c
}

// utf16le encodes s as UTF-16LE, without a byte-order mark.
func utf16le(s string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return string(b)
}

// Scalars is the corpus for the renderers' quoting decisions: texts that
// YAML reads as something other than a plain string, or that some reader
// splits, and ordinary policy values as controls. Each case's Doc is the
// text itself.
func Scalars() []Case {
	var c []Case
	for _, s := range []string{
		"a", "svc-shell", "/srv/app", "**/*.key", "{path:read}", "SOURCE,FSTYPE", "60123",
		"00000000", "true", "True", "yes", "on", "null", "Null", "~", "", "-0", "-0.0", "+1",
		"+18446744073709551615", "0x1F", "0o17", "017", "0b101", "1_000", "1e3", ".inf", ".nan",
		"2001-12-14", "1:20", "<<", "!", "! a", "!!str", "&a", "*a", "a:", ":a", "a: b", "a:b",
		"#a", "a #b", "a#b", "- a", "-", "?", "? a", "[a]", "{a}", "a,b", "a]", "a}", "'a'", `"a"`,
		"|", ">", "%a", "@a", "`a", " a", "a ", "a\tb", "a\\b", "...", "---", string(rune(0xe9)),
		"a" + string(rune(0x2028)) + "b", "a" + string(rune(0x2029)) + "b", "a\u0085b", "a\x7fb",
		"a\u0080b", "a\u009fb", string(rune(0xfeff)) + "a", "a\x01b",
	} {
		c = append(c, Case{strconv.Quote(s), s})
	}
	return c
}

// Pin runs every case of the corpus through run and compares the results
// with the golden file. With update set, it rewrites the file instead;
// regenerate it only when the YAML module is meant to change, and review
// every line of the diff.
func Pin(t *testing.T, golden string, update bool, s *Schema, extra []Case, run func(doc []byte) string) {
	t.Helper()
	PinCases(t, golden, update, append(Corpus(s), extra...), run)
}

// PinCases is Pin for a corpus of its own (Scalars, or parser-specific
// cases).
func PinCases(t *testing.T, golden string, update bool, cases []Case, run func(doc []byte) string) {
	t.Helper()
	var out bytes.Buffer
	out.WriteString("# The YAML layer's results for the yamltest corpus, recorded with\n")
	out.WriteString("# go.yaml.in/yaml/v3. Regenerate with -update only when the YAML module is\n")
	out.WriteString("# meant to change, and review every changed line (docs/ARCHIVE.md, 2026-11-08).\n")
	var got []section
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.Name] {
			t.Fatalf("yamltest: two cases named %q", c.Name)
		}
		seen[c.Name] = true
		r := run([]byte(c.Doc))
		if strings.Contains(r, "\n") {
			t.Fatalf("yamltest: %s: a result must be one line (quote it): %q", c.Name, r)
		}
		got = append(got, section{c.Name, r})
		fmt.Fprintf(&out, "\n== %s\n%s\n", c.Name, r)
	}
	if update {
		if err := os.WriteFile(golden, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden) // #nosec G304 -- a testdata path from the test
	if err != nil {
		t.Fatalf("read %s (record it with -update): %v", golden, err)
	}
	if bytes.Equal(out.Bytes(), want) {
		return
	}
	exp := sections(string(want))
	n := 0
	for _, g := range got {
		w, ok := exp[g.name]
		switch {
		case !ok:
			t.Errorf("%s: not in %s:\n  got:  %s", g.name, golden, g.result)
		case w != g.result:
			t.Errorf("%s: the YAML layer's result changed:\n  got:  %s\n  want: %s", g.name, g.result, w)
		default:
			continue
		}
		n++
	}
	if n == 0 {
		t.Errorf("%s differs from the results (cases removed or reordered); regenerate it with -update and review the diff", golden)
	}
}

// Result is a Run function's line: "OK" and v as JSON (null fields left
// out), or "ERR" and the error's text quoted.
func Result(v any, err error) string {
	if err != nil {
		return "ERR " + strconv.Quote(err.Error())
	}
	b, err := json.Marshal(v)
	if err == nil {
		var generic any
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err = dec.Decode(&generic); err == nil {
			b, err = json.Marshal(prune(generic))
		}
	}
	if err != nil {
		return "OK (not JSON: " + strconv.Quote(err.Error()) + ")"
	}
	return "OK " + string(b)
}

// prune drops null fields from JSON objects (an unset pointer, list or
// map), keeping everything else: "" and a nil pointer stay apart, as do []
// and an unset list.
func prune(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if e == nil {
				delete(x, k)
				continue
			}
			x[k] = prune(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = prune(e)
		}
		return x
	}
	return v
}

// Typed renders a value decoded into any with its Go types ("int(0)",
// "float64(-0)", "nil"), map keys sorted, so a change of type shows.
func Typed(v any) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, strconv.Quote(k)+":"+Typed(x[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case map[any]any:
		parts := make([]string, 0, len(x))
		for k, e := range x {
			parts = append(parts, Typed(k)+":"+Typed(e))
		}
		sort.Strings(parts)
		return "map[any]{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, Typed(e))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return strconv.Quote(x)
	case float64:
		if x == 0 && math.Signbit(x) {
			return "float64(-0)"
		}
		return fmt.Sprintf("float64(%v)", x)
	case nil:
		return "nil"
	default:
		return fmt.Sprintf("%T(%v)", v, v)
	}
}

type section struct{ name, result string }

func sections(s string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(s, "\n== ")[1:] {
		name, result, _ := strings.Cut(part, "\n")
		m[name] = strings.TrimSuffix(result, "\n")
	}
	return m
}
