package policy

import (
	"slices"
	"strings"
	"testing"
)

// FuzzDescriptorWarning: tokens are split on \x1f. DescriptorWarning never
// panics; it warns only about a template with a {path:read:fd}, only for a
// program on the measured list, never when a token that makes the program
// follow the link is present, and names the command and the program.
func FuzzDescriptorWarning(f *testing.F) {
	for _, c := range [][2]string{
		{"stat", "-c\x1f%s\x1f{path:read:fd}"},
		{"stat", "-L\x1f{path:read:fd}"},
		{"tar", "-cf\x1f{path:write}\x1f{path:read:fd}"},
		{"tar", "tf\x1f{path:read:fd}"},
		{"tar", "-chf\x1f{path:write}\x1f{path:read:fd}"},
		{"tar", "{path:read:fd}"},
		{"tar", "-f"},
		{"docker", "compose\x1f-f\x1f{path:read:fd}\x1fconfig"},
		{"cp", "-a\x1f{path:read:fd}\x1f{path:write}"},
		{"cat", "{path:read:fd}"},
		{"find", ""},
	} {
		f.Add(c[0], c[1])
	}
	f.Fuzz(func(t *testing.T, name, joined string) {
		tokens := strings.Split(joined, "\x1f")
		w := DescriptorWarning("commands[x]", tokens, name)
		if w == "" {
			return
		}
		r, listed := fdRules[name]
		switch {
		case !slices.Contains(tokens, fdToken):
			t.Fatalf("warned without a {path:read:fd}: %q", w)
		case !listed:
			t.Fatalf("warned about an unlisted program %q: %q", name, w)
		case slices.ContainsFunc(tokens, func(s string) bool { return slices.Contains(r.follow, s) }):
			t.Fatalf("warned although the template follows the link: %q", w)
		case !strings.HasPrefix(w, "commands[x]: "+name+" given a {path:read:fd} "):
			t.Fatalf("warning %q", w)
		}
	})
}
