//go:build linux

package policy_test

import (
	"slices"
	"strings"
	"testing"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// FuzzN13Match (handoff N-13): the program classifier and the find-action
// matcher never panic, are deterministic, and agree with the lists they
// implement: a name is a package tool, find, a D-Bus client or a built-in
// operation exactly when it is one of those names; otherwise its class is
// its POLICY §5 group's (never for 1–10, acknowledge for 11–13) or none;
// and a template has a find action exactly when one of its tokens equals
// an action, the first such token being the one reported.
func FuzzN13Match(f *testing.F) {
	for _, s := range []string{"apt-get", "apt", "dpkg", "dpkg-query", "find", "findmnt", "busctl", "systemctl", "git", "env",
		"systemd-run", "reboot", "nft", "python3.13", "", "-exec", "-execdir", "-fprint0", "-fprint", "-execx", "x-delete", "/srv/-exec"} {
		f.Add(s, "/srv", s)
	}
	f.Add("unattended-upgrades", "-name", "-delete")
	f.Add("sort", "--compress-program=x", "-u")
	f.Add("gnuinstall", "-Ds", "--strip")
	f.Add("split", "--f", "--filter=cat")
	f.Fuzz(func(t *testing.T, base, tok1, tok2 string) {
		class, group := policy.Classify(base)
		if c2, g2 := policy.Classify(base); c2 != class || g2 != group {
			t.Fatalf("Classify(%q) not deterministic", base)
		}
		g, _, denied := gpolicy.HardDenied(base)
		var want policy.Class
		switch {
		case slices.Contains(n13PackageTools, base):
			want = policy.ClassPackageTool
		case base == "find":
			want = policy.ClassFind
		case slices.Contains([]string{"sort", "split", "install"}, gpolicy.CanonicalName(base)):
			want = policy.ClassAction
		case slices.Contains(n13BusClients, base) || gpolicy.IsBuiltinOp(base):
			want = policy.ClassNotCommand
		case denied && g <= 10:
			want = policy.ClassNever
		case denied:
			want = policy.ClassListB
		}
		if class != want {
			t.Fatalf("Classify(%q) = %v, want %v", base, class, want)
		}
		if (class == policy.ClassNever || class == policy.ClassListB) != (group != 0) || (group != 0 && group != g) {
			t.Fatalf("Classify(%q) group %d, POLICY §5 group %d", base, group, g)
		}

		tokens := []string{tok1, base, tok2}
		got := policy.FindAction(tokens)
		first := ""
		for _, tok := range tokens {
			if slices.Contains(n13FindActions, tok) {
				first = tok
				break
			}
		}
		if got != first {
			t.Fatalf("FindAction(%q) = %q, want %q", tokens, got, first)
		}
		// Padding never makes or hides an action except by forming one exactly.
		padded := []string{"x" + tok1, tok2 + "x", strings.ToUpper(base)}
		for _, tok := range padded {
			if !slices.Contains(n13FindActions, tok) && policy.FindAction([]string{tok}) != "" {
				t.Fatalf("FindAction(%q) found an action", tok)
			}
		}
		// ProgramAction reports one of the tokens, only an option (a placeholder
		// value never starts with "-"), and only for sort, split and install.
		for _, prog := range []string{"sort", "split", "install", base} {
			a := policy.ProgramAction(prog, tokens)
			if a != "" && (!slices.Contains(tokens, a) || !strings.HasPrefix(a, "-") || !slices.Contains([]string{"sort", "split", "install"}, prog)) {
				t.Fatalf("ProgramAction(%q, %q) = %q", prog, tokens, a)
			}
		}
	})
}
