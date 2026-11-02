package gen_test

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	ggen "github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy/gen"
)

// FuzzRootComments: the comment above root: and above each root.commands
// entry is refused or rendered as comment lines only, so the privileged
// policy's values are those without it (POLICY §9.3).
func FuzzRootComments(f *testing.F) {
	for _, s := range []string{"\nmax_tier: destructive", "x\r\nclient_uid: 0", "---\nsocket_group: root", "# #", "a\x00", "- id: sh\n  path: /bin/sh"} {
		f.Add(s)
	}
	a0, err := ggen.Decode(readFile(f, filepath.Join(examples, "policies", "admin.answers.yaml")))
	if err != nil {
		f.Fatal(err)
	}
	a0.Root.Comment = ""
	for i := range a0.Root.Commands {
		a0.Root.Commands[i].Comment = ""
	}
	plain, err := gen.Render(a0)
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
		for _, slot := range []int{-1, 0, 2} {
			a := *a0
			r := *a0.Root
			r.Commands = slices.Clone(a0.Root.Commands)
			if slot < 0 {
				r.Comment = c
			} else {
				r.Commands[slot].Comment = c
			}
			a.Root = &r
			out, err := gen.Render(&a)
			if err != nil {
				if ggen.CheckComment(c) == nil {
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

// FuzzField: mapping a privileged loader error line never panics and
// keeps the message.
func FuzzField(f *testing.F) {
	f.Add("privileged policy: paths.write[0]: /etc/ssh is, or is inside, a path on the never list (PRIVILEGED §5.3 list A)")
	f.Add("privileged policy: commands[x].acknowledge: needs one")
	f.Fuzz(func(t *testing.T, line string) {
		got := gen.Field(line, ggen.PresetAdmin)
		if _, msg, ok := strings.Cut(line, ": "); ok {
			if _, m2, ok := strings.Cut(msg, ": "); ok && !strings.Contains(got, m2) {
				t.Fatalf("%q lost its message: %q", line, got)
			}
		}
	})
}
