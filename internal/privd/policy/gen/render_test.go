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

	ggen "github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy/gen"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func decodeFile(t *testing.T, p string) *ggen.Answers {
	t.Helper()
	a, err := ggen.Decode(readFile(t, p))
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return a
}

// TestGolden: each testdata answers file renders its golden privileged
// policy (POLICY §9.3).
func TestGolden(t *testing.T) {
	m, err := filepath.Glob(filepath.Join("testdata", "*.answers.yaml"))
	if err != nil || len(m) < 2 {
		t.Fatalf("testdata answers: %v %v", m, err)
	}
	for _, p := range m {
		t.Run(filepath.Base(p), func(t *testing.T) {
			got, err := gen.Render(decodeFile(t, p))
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

// TestNeverMorePermissive: the privileged policy's preset sections
// (version, max_tier, limits, modes, backups, the sandbox but for
// landlock, the packages' manager) are exactly the example's, and every
// value is the answers' or the example's.
func TestNeverMorePermissive(t *testing.T) {
	paths := []string{filepath.Join(examples, "policies", "admin.answers.yaml")}
	m, _ := filepath.Glob(filepath.Join("testdata", "*.answers.yaml"))
	for _, p := range append(paths, m...) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			a := decodeFile(t, p)
			out, err := gen.Render(a)
			if err != nil {
				t.Fatal(err)
			}
			got, tmpl, ans := decode(t, out), decode(t, gen.Preset()), decode(t, readFile(t, p))
			allowed := map[string]bool{}
			leavesOf(tmpl, allowed)
			leavesOf(ans, allowed)
			seen := map[string]bool{}
			leavesOf(got, seen)
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
			for _, k := range []string{"version", "max_tier", "limits", "modes", "backups"} {
				if !reflect.DeepEqual(got[k], tmpl[k]) {
					t.Errorf("%s: %v, the preset has %v", k, got[k], tmpl[k])
				}
			}
			want := "required"
			if a.Landlock != "" {
				want = a.Landlock
			}
			if l := sub(got, "sandbox", "landlock"); l != want {
				t.Errorf("sandbox.landlock %v, want %s", l, want)
			}
			if p, ok := got["packages"].(map[string]any); ok && (p["manager"] != "apt" || p["enabled"] != true) {
				t.Errorf("packages: %v", p)
			}
		})
	}
}

func leavesOf(v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			leavesOf(e, out)
		}
	case []any:
		for _, e := range x {
			leavesOf(e, out)
		}
	default:
		out[fmt.Sprintf("%T:%v", v, v)] = true
	}
}

// TestCommentsCannotChangeValues: the comment above root: and above each
// root.commands entry is rendered as comment lines only (POLICY §9.3).
func TestCommentsCannotChangeValues(t *testing.T) {
	base := adminAnswers(t)
	bare := *base
	root := *base.Root
	root.Comment = ""
	root.Commands = slices.Clone(base.Root.Commands)
	for i := range root.Commands {
		root.Commands[i].Comment = ""
	}
	bare.Root = &root
	plain, err := gen.Render(&bare)
	if err != nil {
		t.Fatal(err)
	}
	want := decode(t, plain)
	plainLines := map[string]bool{}
	for _, l := range strings.Split(string(plain), "\n") {
		plainLines[l] = true
	}
	evils := []string{"\nmax_tier: destructive", "x\r\nclient_uid: 0", "x\rpackages:\r  allow_upgrade: true", "---\nsocket_group: root\n...",
		"# ## #", "- id: shell\n  path: /bin/sh", "  indented: value", "paths: { write: [/etc/ssh] }"}
	for _, evil := range evils {
		for slot, set := range map[string]func(*ggen.Root){
			"root":           func(r *ggen.Root) { r.Comment = evil },
			"root.commands0": func(r *ggen.Root) { r.Commands[0].Comment = evil },
			"root.commands2": func(r *ggen.Root) { r.Commands[2].Comment = evil },
		} {
			a := bare
			r := root
			r.Commands = slices.Clone(root.Commands)
			set(&r)
			a.Root = &r
			out, err := gen.Render(&a)
			if err != nil {
				t.Fatalf("%s %q: %v", slot, evil, err)
			}
			if !reflect.DeepEqual(decode(t, out), want) {
				t.Errorf("%s %q changed the values", slot, evil)
			}
			for _, l := range strings.Split(string(out), "\n") {
				if !plainLines[l] && !strings.HasPrefix(strings.TrimLeft(l, " "), "#") {
					t.Errorf("%s %q added a line that is not a comment: %q", slot, evil, l)
				}
			}
		}
	}
	for _, bad := range []string{"a\x00b", "a\tb", "a" + string(rune(0x2029)) + "x"} {
		a := bare
		r := root
		r.Comment = bad
		a.Root = &r
		if out, err := gen.Render(&a); err == nil {
			t.Errorf("root comment %q rendered:\n%s", bad, out)
		}
	}
}
