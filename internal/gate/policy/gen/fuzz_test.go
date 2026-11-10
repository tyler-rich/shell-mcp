package gen_test

import (
	"bytes"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
)

func seedAnswers(f *testing.F) {
	f.Helper()
	m, _ := filepath.Glob(filepath.Join("testdata", "*.answers.yaml"))
	for _, name := range []string{gen.PresetReadOnly, gen.PresetOperator, gen.PresetAdmin} {
		m = append(m, filepath.Join(examples, "policies", name+".answers.yaml"))
	}
	for _, p := range m {
		f.Add(readFile(f, p))
	}
	f.Add([]byte(minimal))
	f.Add([]byte(minimal + "commands:\n  # c\n  - { id: a, path: /usr/bin/apt, tier: read, templates: [[\"list\"]] }\n"))
	f.Add([]byte("# h\r\n#\r\n\r\npreset: read-only\r\naccount: { user: a, uid: 1 }\r\n"))
	f.Add([]byte("preset: &p read-only\naccount: { user: a, uid: 1 }\nread: [*p]\n"))
}

// FuzzDecode: the answers decoder never panics; what it accepts renders
// (or is refused by the renderer) into a policy whose values are exactly
// the answers' and the preset's (RenderGate checks that itself), and
// decoding is deterministic.
func FuzzDecode(f *testing.F) {
	seedAnswers(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := gen.Decode(data)
		if err != nil {
			return
		}
		b, err2 := gen.Decode(data)
		if err2 != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("decode is not deterministic: %v", err2)
		}
		out, err := gen.RenderGate(a)
		if err != nil {
			return
		}
		var v map[string]any
		if err := yaml.Unmarshal(out, &v); err != nil {
			t.Fatalf("rendered policy does not parse: %v\n%s", err, out)
		}
		if v["max_tier"] != map[string]string{gen.PresetReadOnly: "read", gen.PresetOperator: "operator", gen.PresetAdmin: "destructive"}[a.Preset] {
			t.Fatalf("max_tier %v for preset %s", v["max_tier"], a.Preset)
		}
	})
}

// FuzzComment: a carried comment is refused or rendered as comment lines
// only: the policy's values are those without it (POLICY §9.3).
func FuzzComment(f *testing.F) {
	for _, s := range injections {
		f.Add(s)
	}
	f.Add("a\x00b")
	f.Add("a" + string(rune(0x2028)) + "max_tier: destructive")
	a0, err := gen.Decode(readFile(f, filepath.Join(examples, "policies", "operator.answers.yaml")))
	if err != nil {
		f.Fatal(err)
	}
	a0.Header = ""
	for i := range a0.Commands {
		a0.Commands[i].Comment = ""
	}
	plain, err := gen.RenderGate(a0)
	if err != nil {
		f.Fatal(err)
	}
	var want map[string]any
	if err := yaml.Unmarshal(plain, &want); err != nil {
		f.Fatal(err)
	}
	plainLines := map[string]bool{}
	for _, l := range strings.Split(string(plain), "\n") {
		plainLines[l] = true
	}
	f.Fuzz(func(t *testing.T, c string) {
		for _, slot := range []int{-1, 0, 1} {
			a := *a0
			a.Commands = slices.Clone(a0.Commands)
			if slot < 0 {
				a.Header = c
			} else {
				a.Commands[slot].Comment = c
			}
			out, err := gen.RenderGate(&a)
			if err != nil {
				if gen.CheckComment(c) == nil {
					t.Fatalf("a comment the rules accept was refused: %q: %v", c, err)
				}
				continue
			}
			var got map[string]any
			if err := yaml.Unmarshal(out, &got); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("comment %q changed the policy (%v):\n%s", c, err, out)
			}
			for _, l := range strings.Split(string(out), "\n") {
				if !plainLines[l] && !strings.HasPrefix(strings.TrimLeft(l, " "), "#") {
					t.Fatalf("comment %q added a line that is not a comment: %q", c, l)
				}
			}
		}
	})
}

// FuzzParseTemplate: the template parser never panics, and what it accepts
// it gives back verbatim, so rendering cannot lose a line of a preset.
func FuzzParseTemplate(f *testing.F) {
	for _, name := range []string{gen.PresetReadOnly, gen.PresetOperator, gen.PresetAdmin} {
		b, err := gen.Preset(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("# a\n#\n# b\n\nk: v\n"))
	f.Add([]byte("#\n\nk:\n  - x\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > 1<<16 {
			return
		}
		tp, err := gen.ParseTemplate(src)
		if err != nil {
			return
		}
		o := &gen.Out{}
		o.Lines(tp.ExampleHeader)
		if tp.Split {
			o.Line("#")
		}
		o.Lines(tp.Header)
		for _, n := range tp.Nodes {
			o.Verbatim(n)
		}
		got, err := o.Bytes()
		if err != nil || !bytes.Equal(got, src) {
			t.Fatalf("verbatim differs (%v):\n%q\n%q", err, src, got)
		}
	})
}

// FuzzLoaderField: mapping a loader error line never panics, keeps the
// message, and never names an answers key for a line without the loader's
// prefix.
func FuzzLoaderField(f *testing.F) {
	f.Add("policy: paths.write[0]: /etc/ssh is, or is inside, a protected path")
	f.Add("policy: commands[a]: x: y")
	f.Add("policy: policy is empty")
	f.Add("other: paths.read[0]: x")
	f.Fuzz(func(t *testing.T, line string) {
		got := gen.GateField(line, gen.PresetOperator)
		if !strings.HasPrefix(line, "policy: ") && !strings.HasPrefix(got, line) {
			t.Fatalf("%q became %q", line, got)
		}
		if _, msg, ok := strings.Cut(line, ": "); ok {
			if _, m2, ok := strings.Cut(msg, ": "); ok && !strings.Contains(got, m2) {
				t.Fatalf("%q lost its message: %q", line, got)
			}
		}
	})
}

// FuzzParseFlags: the flag parser never panics, and what it accepts has an
// absolute, clean answers path and an --out.
func FuzzParseFlags(f *testing.F) {
	f.Add("--answers setup.yaml --out -")
	f.Add("--answers /root/a.yaml --out /etc/shell-mcp/x.yaml --dry-run")
	f.Add("--answers ../../a --out x --out y")
	f.Fuzz(func(t *testing.T, s string) {
		o, err := gen.ParseFlags(strings.Fields(s), "/root")
		if err != nil {
			return
		}
		if !filepath.IsAbs(o.Answers) || filepath.Clean(o.Answers) != o.Answers || o.Out == "" {
			t.Fatalf("%q: %+v", s, o)
		}
	})
}
