//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/template"
)

// {path:read:fd} (POLICY §4, handoff N-22): the gate policy accepts the
// placeholder, at most 8 per template, and check-policy warns about each
// program measured to give wrong results, or no gain, with a descriptor,
// recognised by the name as written, as resolved and canonical (as the
// GTFOBins warning is); a flag that makes the program follow the link
// silences it. Every binary is an invented fixture, never executed.

func TestPathReadFDParses(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, cmdPolicy("  - id: a\n    path: {BIN}/example-tool\n    tier: operator\n    templates: [[\"{path:read:fd}\", \"{path:read}\"]]\n"))
	c, _ := p.Command("a")
	if len(c.Templates) != 1 || c.Templates[0].Tokens[0].Kind != template.PathReadFD {
		t.Fatalf("command %+v", c)
	}
	nine := strings.Repeat(`"{path:read:fd}", `, 9)
	f.mustFail(t, cmdPolicy("  - id: a\n    path: {BIN}/example-tool\n    tier: read\n    templates: [["+strings.TrimSuffix(nine, ", ")+"]]\n"), "at most 8 {path:read:fd}")
}

// fdWarning is the descriptor warning about command id, or "".
func fdWarning(warnings []string, id string) string {
	for _, w := range warnings {
		if strings.HasPrefix(w, "commands["+id+"]: ") && strings.Contains(w, "{path:read:fd}") {
			return w
		}
	}
	return ""
}

func TestPathReadFDWarnings(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"stat", "du", "file", "ls", "find", "cp", "tar", "findmnt", "nginx", "docker", "docker-compose", "cat", "jq", "gnustat"} {
		f.exe(t, n)
	}
	if err := os.Symlink("stat", filepath.Join(f.bin, "mystat")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id, bin, tpl, want string // want "" means no warning
		rootEquivalent     bool
	}{
		{"stat", "stat", `"-c", "%s", "{path:read:fd}"`, "link itself", false},
		{"stat-l", "stat", `"-L", "-c", "%s", "{path:read:fd}"`, "", false},
		{"stat-deref", "stat", `"--dereference", "{path:read:fd}"`, "", false},
		{"stat-gnu", "gnustat", `"{path:read:fd}"`, "link itself", false},
		{"stat-link", "mystat", `"{path:read:fd}"`, "link itself", false},
		{"du", "du", `"-sb", "{path:read:fd}"`, "link itself", false},
		{"du-l", "du", `"-L", "-sb", "{path:read:fd}"`, "", false},
		{"du-d", "du", `"-D", "-sb", "{path:read:fd}"`, "", false},
		{"du-h", "du", `"-H", "{path:read:fd}"`, "", false},
		{"du-args", "du", `"--dereference-args", "{path:read:fd}"`, "", false},
		{"file", "file", `"{path:read:fd}"`, "link itself", false},
		{"file-l", "file", `"-L", "{path:read:fd}"`, "", false},
		{"ls", "ls", `"-l", "{path:read:fd}"`, "link itself", false},
		{"ls-l", "ls", `"-L", "-l", "{path:read:fd}"`, "", false},
		{"find", "find", `"{path:read:fd}", "-type", "f"`, "does not descend", false},
		{"find-h", "find", `"-H", "{path:read:fd}", "-type", "f"`, "", false},
		{"cp", "cp", `"{path:read:fd}", "{path:write}"`, "", false},
		{"cp-a", "cp", `"-a", "{path:read:fd}", "{path:write}"`, "copies the /dev/fd/N link", false},
		{"cp-p", "cp", `"-P", "{path:read:fd}", "{path:write}"`, "copies the /dev/fd/N link", false},
		{"cp-r", "cp", `"-r", "{path:read:fd}", "{path:write}"`, "copies the /dev/fd/N link", false},
		{"cp-nd", "cp", `"--no-dereference", "{path:read:fd}", "{path:write}"`, "copies the /dev/fd/N link", false},
		{"tar-list", "tar", `"-tzf", "{path:read:fd}"`, "", false},
		{"tar-file", "tar", `"-x", "--file", "{path:read:fd}", "-C", "{path:write}"`, "", false},
		{"tar-old", "tar", `"tf", "{path:read:fd}"`, "", false},
		{"tar-member", "tar", `"-cf", "{path:write}", "{path:read:fd}"`, "archives the /dev/fd/N link", false},
		{"tar-member-h", "tar", `"-chf", "{path:write}", "{path:read:fd}"`, "", false},
		{"tar-member-deref", "tar", `"--dereference", "-cf", "{path:write}", "{path:read:fd}"`, "", false},
		{"findmnt", "findmnt", `"--target", "{path:read:fd}"`, "looks the real path up again", false},
		{"nginx", "nginx", `"-t", "-c", "{path:read:fd}"`, "relative paths", false},
		{"compose", "docker", `"compose", "-f", "{path:read:fd}", "config"`, "relative paths", true},
		{"docker-other", "docker", `"image", "load", "-i", "{path:read:fd}"`, "", true},
		{"compose-v1", "docker-compose", `"-f", "{path:read:fd}", "config"`, "relative paths", true},
		{"cat", "cat", `"{path:read:fd}"`, "", false},
		{"jq", "jq", `".", "{path:read:fd}"`, "", false},
	}
	var y strings.Builder
	for _, c := range cases {
		y.WriteString("  - id: " + c.id + "\n    path: {BIN}/" + c.bin + "\n    tier: operator\n")
		if c.rootEquivalent {
			y.WriteString("    root_equivalent: true\n")
		}
		y.WriteString("    templates: [[" + c.tpl + "]]\n")
	}
	p := f.mustLoad(t, "version: 1\nmax_tier: destructive\nsandbox:\n  system_read_exec: [{BIN}, {GATEDIR}]\npaths:\n  read: [{R}]\n  write: [{W}]\ncommands:\n"+y.String())
	for _, c := range cases {
		w := fdWarning(p.Warnings, c.id)
		switch {
		case c.want == "" && w != "":
			t.Errorf("%s: unexpected warning %q", c.id, w)
		case c.want != "" && (w == "" || !strings.Contains(w, c.want) || !strings.Contains(w, "POLICY §4")):
			t.Errorf("%s: warning %q, want one containing %q", c.id, w, c.want)
		}
	}
	// A {path:read} (no descriptor) never gets the warning.
	q := f.mustLoad(t, cmdPolicy("  - id: s\n    path: {BIN}/stat\n    tier: read\n    templates: [[\"{path:read}\"]]\n"))
	if w := fdWarning(q.Warnings, "s"); w != "" {
		t.Fatalf("a {path:read}: %q", w)
	}
}
