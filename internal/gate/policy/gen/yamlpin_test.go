package gen_test

import (
	"path/filepath"
	"strconv"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/yamltest"
)

// The pins below record, with go.yaml.in/yaml/v3, what the answers file's
// decoder, the renderer's quoting, the comment renderer and the values
// check accept, refuse and read. A new YAML module that changes any of it
// fails here (docs/ARCHIVE.md, 2026-11-08). Regenerate with -update only
// for an intended module change, and review every changed line.

// TestYAMLPinsAnswers pins Decode (strict fields, one document, the carried
// comments) on the yamltest corpus and on comment placements.
func TestYAMLPinsAnswers(t *testing.T) {
	const account = "account: { user: svc-shell, uid: 60123 }\n"
	s := &yamltest.Schema{
		Base: minimal,
		Str: func(v string) string {
			return minimal + "commands:\n  - id: a\n    description: " + v + "\n"
		},
		Int:  func(v string) string { return "preset: read-only\naccount:\n  user: svc-shell\n  uid: " + v + "\n" },
		List: func(v string) string { return "preset: read-only\n" + account + "read: " + v + "\n" },
		Bool: func(v string) string {
			return minimal + "commands:\n  - id: a\n    root_equivalent: " + v + "\n"
		},
		Flow:   func(inner string) string { return "preset: read-only\naccount: { uid: 60123, " + inner + " }\n" },
		MapKey: "user",
	}
	admin := "preset: admin\n" + account
	ls := string(rune(0x2028))
	root := "root:\n  socket_group: { name: svc-shell-priv, gid: 60124 }\n  read: [/etc/example-app]\n"
	extra := []yamltest.Case{
		{Name: "header comment", Doc: "# first\n#\n# third\n\n" + minimal},
		{Name: "header comment, no blank line", Doc: "# first\n" + minimal},
		{Name: "header comment with a tab", Doc: "#\tfirst\n\n" + minimal},
		{Name: "header comment without a space", Doc: "#first\n\n" + minimal},
		{Name: "header comment with U+2028", Doc: "# a" + ls + "b\n\n" + minimal},
		{Name: "header comment with U+2028, then a key", Doc: "# a" + ls + "max_tier: destructive\n\n" + minimal},
		{Name: "header comment with U+2029", Doc: "# a" + string(rune(0x2029)) + "b\n\n" + minimal},
		{Name: "header comment with U+0085", Doc: "# a\u0085b\n\n" + minimal},
		{Name: "header comment with CR", Doc: "# a\rb\n\n" + minimal},
		{Name: "header comment with U+007F", Doc: "# a\x7fb\n\n" + minimal},
		{Name: "header comment with U+0080", Doc: "# a\u0080b\n\n" + minimal},
		{Name: "header comment with U+FEFF", Doc: "# a" + string(rune(0xfeff)) + "b\n\n" + minimal},
		{Name: "comment above a command", Doc: minimal + "commands:\n  # about a\n  # second line\n  - id: a\n  # about b\n  - id: b\n"},
		{Name: "comment above a command, flow entries", Doc: minimal + "commands:\n  # about a\n  - { id: a }\n"},
		{Name: "comment between commands key and list", Doc: minimal + "commands:\n\n  # about a\n\n  - id: a\n"},
		{Name: "comment after the last command", Doc: minimal + "commands:\n  - id: a\n  # trailing\n"},
		{Name: "line comment on a command", Doc: minimal + "commands:\n  - id: a # line\n"},
		{Name: "comment above root", Doc: admin + "# about root\n" + root},
		{Name: "comment above root, blank line between", Doc: admin + "# about root\n\n" + root},
		{Name: "comment above a root command", Doc: admin + root + "  commands:\n    # about r\n    - id: r\n"},
		{Name: "comment at the end", Doc: minimal + "# the end\n"},
	}
	yamltest.Pin(t, "testdata/yaml-pins-answers.golden", *update, s, extra, func(doc []byte) string {
		a, err := gen.Decode(doc)
		if err != nil {
			return yamltest.Result(nil, err)
		}
		return yamltest.Result(a, nil)
	})
}

// TestYAMLPinsQuoting pins the renderer's scalar decisions: Plain keeps a
// value plain only when YAML reads it back as itself, Quoted refuses one
// whose double-quoted form does not.
func TestYAMLPinsQuoting(t *testing.T) {
	yamltest.PinCases(t, "testdata/yaml-pins-quoting.golden", *update, yamltest.Scalars(), func(s []byte) string {
		var p, q gen.Out
		plain := p.Plain(string(s))
		quoted := q.Quoted(string(s))
		return yamltest.Result(map[string]any{"plain": plain, "quoted": quoted, "plain_err": errText(p.Err()), "quoted_err": errText(q.Err())}, nil)
	})
}

// TestYAMLPinsComments pins the comment renderer end to end: the operator
// example rendered with each text as its header comment and as a command's
// comment, each rendering read back and checked against the answers'
// values (RenderGate's CheckValues).
func TestYAMLPinsComments(t *testing.T) {
	a0, err := gen.Decode(readFile(t, filepath.Join(examples, "policies", "operator.answers.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	var cases []yamltest.Case
	seen := map[string]bool{}
	for _, c := range append(slicesOf(injections), yamltest.Scalars()...) {
		if !seen[c.Name] {
			seen[c.Name] = true
			cases = append(cases, c)
		}
	}
	yamltest.PinCases(t, "testdata/yaml-pins-comments.golden", *update, cases, func(c []byte) string {
		var r []string
		for _, slot := range []int{-1, 0} {
			a := *a0
			a.Commands = append([]gen.Command(nil), a0.Commands...)
			if slot < 0 {
				a.Header = string(c)
			} else {
				a.Commands[slot].Comment = string(c)
			}
			if _, err := gen.RenderGate(&a); err != nil {
				r = append(r, "ERR "+err.Error())
			} else {
				r = append(r, "OK")
			}
		}
		return yamltest.Result(r, nil)
	})
}

// TestYAMLPinsValues pins the decoding the values check and the template
// reader use (yaml.Unmarshal into map[string]any), with Go types.
func TestYAMLPinsValues(t *testing.T) {
	s := &yamltest.Schema{
		Base:   "k: a\n",
		Str:    func(v string) string { return "k: " + v + "\n" },
		Int:    func(v string) string { return "n: " + v + "\n" },
		List:   func(v string) string { return "l: " + v + "\n" },
		Flow:   func(inner string) string { return "m: {" + inner + "}\n" },
		MapKey: "x",
	}
	yamltest.Pin(t, "testdata/yaml-pins-values.golden", *update, s, nil, func(doc []byte) string {
		var m map[string]any
		if err := yaml.Unmarshal(doc, &m); err != nil {
			return yamltest.Result(nil, err)
		}
		return "OK " + yamltest.Typed(m)
	})
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func slicesOf(texts []string) []yamltest.Case {
	out := make([]yamltest.Case, 0, len(texts))
	for _, s := range texts {
		out = append(out, yamltest.Case{Name: strconv.Quote(s), Doc: s})
	}
	return out
}
