package gen_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func values(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return m
}

// fixtures are every answers file the tests render: the examples' and
// testdata's.
func fixtures(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{gen.PresetReadOnly, gen.PresetOperator, gen.PresetAdmin} {
		out["example "+name] = filepath.Join(examples, "policies", name+".answers.yaml")
	}
	m, err := filepath.Glob(filepath.Join("testdata", "*.answers.yaml"))
	if err != nil || len(m) < 4 {
		t.Fatalf("testdata answers: %v %v", m, err)
	}
	for _, p := range m {
		out[filepath.Base(p)] = p
	}
	return out
}

// TestGolden: each testdata answers file renders its golden policy, for
// every preset and the sections each leaves out (POLICY §9.3).
func TestGolden(t *testing.T) {
	m, err := filepath.Glob(filepath.Join("testdata", "*.answers.yaml"))
	if err != nil || len(m) < 4 {
		t.Fatalf("testdata answers: %v %v", m, err)
	}
	for _, p := range m {
		t.Run(filepath.Base(p), func(t *testing.T) {
			got, err := gen.RenderGate(decodeFile(t, p))
			if err != nil {
				t.Fatal(err)
			}
			golden := strings.TrimSuffix(p, ".answers.yaml") + ".golden"
			if *update {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if want := readFile(t, golden); !bytes.Equal(got, want) {
				t.Errorf("%s:\n%s", golden, setupx.UnifiedDiff("golden", "rendered", want, got))
			}
		})
	}
}

// leaves collects every scalar of a decoded YAML value.
func leaves(v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			leaves(e, out)
		}
	case []any:
		for _, e := range x {
			leaves(e, out)
		}
	default:
		out[fmt.Sprintf("%T:%v", v, v)] = true
	}
}

// TestNeverMorePermissive is POLICY §9.2's rule, checked from outside the
// renderer: every value of every generated gate policy is a value of its
// answers file or of its preset's example, every top-level key is one the
// example has, and the preset's own sections (version, max_tier, limits,
// redact, the sandbox but for landlock, journal.max_lines, the privileged
// forwarding) are exactly the example's: no built-in protection is
// dropped and nothing is added.
func TestNeverMorePermissive(t *testing.T) {
	for name, p := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			src := readFile(t, p)
			a := decodeFile(t, p)
			out, err := gen.RenderGate(a)
			if err != nil {
				t.Fatal(err)
			}
			tb, err := gen.Preset(a.Preset)
			if err != nil {
				t.Fatal(err)
			}
			got, tmpl, ans := values(t, out), values(t, tb), values(t, src)
			allowed := map[string]bool{}
			leaves(tmpl, allowed)
			leaves(ans, allowed)
			seen := map[string]bool{}
			leaves(got, seen)
			for l := range seen {
				if !allowed[l] {
					t.Errorf("value %s is in neither the answers nor the preset", l)
				}
			}
			for k := range got {
				if _, ok := tmpl[k]; !ok {
					t.Errorf("key %s is not in the preset's example", k)
				}
			}
			for _, k := range []string{"version", "max_tier", "limits", "redact"} {
				if !reflect.DeepEqual(got[k], tmpl[k]) {
					t.Errorf("%s: %v, the preset has %v", k, got[k], tmpl[k])
				}
			}
			gs, ts := got["sandbox"].(map[string]any), tmpl["sandbox"].(map[string]any)
			for k, v := range ts {
				want := v
				if k == "landlock" && a.Landlock != "" {
					want = a.Landlock
				}
				if !reflect.DeepEqual(gs[k], want) {
					t.Errorf("sandbox.%s: %v, want %v", k, gs[k], want)
				}
			}
			if len(gs) != len(ts) {
				t.Errorf("sandbox has keys %v, the preset %v", gs, ts)
			}
			if j, ok := got["journal"].(map[string]any); ok && !reflect.DeepEqual(j["max_lines"], tmpl["journal"].(map[string]any)["max_lines"]) {
				t.Errorf("journal.max_lines %v is not the preset's", j["max_lines"])
			}
			if pv, ok := got["privileged"].(map[string]any); ok {
				for k, v := range pv {
					if !reflect.DeepEqual(v, tmpl["privileged"].(map[string]any)[k]) {
						t.Errorf("privileged.%s: %v is not the preset's", k, v)
					}
				}
				if a.Root == nil {
					t.Error("privileged forwarding without root: in the answers")
				}
			} else if a.Root != nil {
				t.Error("root: in the answers but no privileged forwarding")
			}
		})
	}
}

// injections are comments that would change the policy if they were not
// rendered as comment lines only (POLICY §9.3).
var injections = []string{
	"\nmax_tier: destructive",
	"x\nmax_tier: destructive\n",
	"x\r\nmax_tier: destructive\r\n",
	"x\rprivileged:\r  enabled: true",
	"---\nmax_tier: destructive\n...",
	"# ## #\n#\n##",
	"- id: evil\n  path: /bin/sh\n  tier: destructive",
	"a\n\n\nb",
	"  indented: value",
	"limits: { max_output_bytes: 4194304 }",
	"'\"quoted\"' & *alias !!binary |",
	"write: [/]",
}

// TestCommentsCannotChangeValues: whatever an answers comment holds, the
// rendered policy's values are those of the same answers without it, and
// every line it adds is a comment line.
func TestCommentsCannotChangeValues(t *testing.T) {
	base := decodeFile(t, filepath.Join(examples, "policies", "admin.answers.yaml"))
	bare := *base
	bare.Header = ""
	bare.Commands = slices.Clone(base.Commands)
	for i := range bare.Commands {
		bare.Commands[i].Comment = ""
	}
	plain, err := gen.RenderGate(&bare)
	if err != nil {
		t.Fatal(err)
	}
	want := values(t, plain)
	plainLines := map[string]bool{}
	for _, l := range strings.Split(string(plain), "\n") {
		plainLines[l] = true
	}
	for _, evil := range injections {
		for slot, set := range map[string]func(*gen.Answers){
			"header":      func(a *gen.Answers) { a.Header = evil },
			"commands[0]": func(a *gen.Answers) { a.Commands[0].Comment = evil },
			"commands[1]": func(a *gen.Answers) { a.Commands[1].Comment = evil },
		} {
			a := bare
			a.Commands = slices.Clone(bare.Commands)
			set(&a)
			out, err := gen.RenderGate(&a)
			if err != nil {
				t.Fatalf("%s %q: %v", slot, evil, err)
			}
			if got := values(t, out); !reflect.DeepEqual(got, want) {
				t.Errorf("%s %q changed the values", slot, evil)
			}
			for _, l := range strings.Split(string(out), "\n") {
				if !plainLines[l] && !strings.HasPrefix(strings.TrimLeft(l, " "), "#") {
					t.Errorf("%s %q added a line that is not a comment: %q", slot, evil, l)
				}
			}
		}
	}
	for _, bad := range []string{"a\x00b", "a\tb", "a\x1b[2J", "a" + string(rune(0x2028)) + "max_tier: destructive", "a\xffb"} {
		a := bare
		a.Header = bad
		if out, err := gen.RenderGate(&a); err == nil {
			t.Errorf("header %q rendered:\n%s", bad, out)
		}
		a = bare
		a.Commands = slices.Clone(bare.Commands)
		a.Commands[0].Comment = bad
		if out, err := gen.RenderGate(&a); err == nil {
			t.Errorf("command comment %q rendered:\n%s", bad, out)
		}
	}
}

// TestQuoting: values YAML would read as something else, or that hold a
// comment marker or a quote, are written so they read back as given.
func TestQuoting(t *testing.T) {
	odd := []string{"/srv/my app", "/srv/a#b", "/srv/a #b", "true", "null", "~", "123", "0x10", "1e3", "/srv/app: x", "/srv/'q'", `/srv/"q"`,
		`/srv/back\slash`, "/srv/[x]", "/srv/{x}", "/srv/a,b", "/srv/*", "/srv/&a", "/srv/!b", "/srv/café"}
	a := decodeFile(t, filepath.Join(examples, "policies", "operator.answers.yaml"))
	a.Read, a.Write = odd, odd
	a.Commands[0].Description = `say "hi" \ # not a comment`
	a.Commands[0].Templates = [][]string{odd}
	out, err := gen.RenderGate(a)
	if err != nil {
		t.Fatal(err)
	}
	v := values(t, out)
	paths := v["paths"].(map[string]any)
	for _, k := range []string{"read", "write"} {
		var got []string
		for _, e := range paths[k].([]any) {
			s, ok := e.(string)
			if !ok {
				t.Fatalf("paths.%s holds %T %v", k, e, e)
			}
			got = append(got, s)
		}
		if !slices.Equal(got, odd) {
			t.Errorf("paths.%s: %q", k, got)
		}
	}
	c := v["commands"].([]any)[0].(map[string]any)
	if c["description"] != a.Commands[0].Description {
		t.Errorf("description %q", c["description"])
	}
	for _, bad := range []string{"/srv/a\nb", "/srv/a\x00", "/srv/a\tb"} {
		b := *a
		b.Read = []string{bad}
		if _, err := gen.RenderGate(&b); err == nil {
			t.Errorf("read root %q rendered", bad)
		}
	}
}

// TestRenderValidates: RenderGate applies the presets' rules itself, so a
// caller that skips Decode cannot render what Decode refuses.
func TestRenderValidates(t *testing.T) {
	a := decodeFile(t, filepath.Join(examples, "policies", "read-only.answers.yaml"))
	a.Write = []string{"/srv/app/config"}
	if out, err := gen.RenderGate(a); err == nil {
		t.Fatalf("read-only with write rendered:\n%s", out)
	}
	a = decodeFile(t, filepath.Join(examples, "policies", "operator.answers.yaml"))
	a.Root = &gen.Root{SocketGroup: gen.Group{Name: "svc-shell-priv", GID: 60124}}
	if out, err := gen.RenderGate(a); err == nil {
		t.Fatalf("operator with root rendered:\n%s", out)
	}
}

// TestParseTemplateVerbatim: rendering every node of every preset
// verbatim gives back the file, so the template parser loses nothing.
func TestParseTemplateVerbatim(t *testing.T) {
	for _, name := range []string{gen.PresetReadOnly, gen.PresetOperator, gen.PresetAdmin} {
		src, err := gen.Preset(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := verbatim(t, src); got != string(src) {
			t.Errorf("%s:\n%s", name, setupx.UnifiedDiff("preset", "verbatim", src, []byte(got)))
		}
	}
}

func verbatim(t *testing.T, src []byte) string {
	t.Helper()
	tp, err := gen.ParseTemplate(src)
	if err != nil {
		t.Fatal(err)
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
	b, err := o.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
