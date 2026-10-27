//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// #! scripts in the privileged policy (handoff N-26, N-31): a script runs
// its interpreter as root on whatever the script holds, which the policy
// does not show, so a command whose program is a script needs an
// acknowledge, as list B programs do, and the GTFOBins warning also checks
// the interpreter. Every binary here is an invented fixture, never run.

func hasScriptFinding(t *testing.T, p *policy.Policy, interp string) bool {
	t.Helper()
	return slices.Contains(findings(t, p), policy.CommandFinding{Category: "script", Program: interp, Match: "script"})
}

// TestScriptNeedsAcknowledge: an unacknowledged script is refused, naming
// the script and its interpreter; acknowledged, it loads with a finding and
// a review line. A symlink to the script, a renamed copy of it and a
// chain of scripts need it too; a program that is no script does not.
func TestScriptNeedsAcknowledge(t *testing.T) {
	f := newFixture(t)
	interp := f.exe(t, "example-interp", "invented interpreter\n")
	script := f.exe(t, "renew", "#!"+interp+" -q\nrenew\n")
	link := filepath.Join(f.bin, "renew-link")
	if err := os.Symlink(script, link); err != nil {
		t.Fatal(err)
	}
	renamed := f.exe(t, "other-name", "#!"+interp+" -q\nrenew\n")
	inner := f.exe(t, "inner", "#!"+interp+"\n")
	outer := f.exe(t, "outer", "#!"+inner+"\n")

	for name, path := range map[string]string{"script": script, "symlink": link, "renamed copy": renamed} {
		t.Run(name, func(t *testing.T) {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				t.Fatal(err)
			}
			f.mustFail(t, cmdWith(path, "", "[[]]"), "acknowledge")
			f.mustFail(t, cmdWith(path, "", "[[]]"), resolved)
			f.mustFail(t, cmdWith(path, "", "[[]]"), interp)
			p := f.mustLoad(t, cmdWith(path, ack, "[[]]"))
			if !hasScriptFinding(t, p, interp) {
				t.Fatalf("findings %+v", findings(t, p))
			}
			if !reviewed(p, "script") {
				t.Fatalf("not reviewed: %+v", p.Acknowledged)
			}
			if c, _ := p.Command("x"); c.Acknowledge == "" || c.Interpreter != interp {
				t.Fatalf("acknowledge %q, interpreter %q", c.Acknowledge, c.Interpreter)
			}
		})
	}

	t.Run("chain", func(t *testing.T) {
		f.mustFail(t, cmdWith(outer, "", "[[]]"), "acknowledge")
		f.mustFail(t, cmdWith(outer, "", "[[]]"), interp)
		p := f.mustLoad(t, cmdWith(outer, ack, "[[]]"))
		if !hasScriptFinding(t, p, interp) {
			t.Fatalf("findings %+v", findings(t, p))
		}
	})

	t.Run("not a script", func(t *testing.T) {
		p := f.mustLoad(t, cmdWith(f.exe(t, "plain-tool", "invented binary\n"), "", "[[]]"))
		if len(findings(t, p)) != 0 || reviewed(p, "script") {
			t.Fatalf("findings %+v, review %+v", findings(t, p), p.Acknowledged)
		}
	})
}

// TestScriptNeverInterpreterStaysRefused: an acknowledge does not override
// the never list: a script run by a shell, by env, or by a copy of a shell
// is refused with or without one (S-MC).
func TestScriptNeverInterpreterStaysRefused(t *testing.T) {
	f := newFixture(t)
	sh := f.exe(t, "sh", "invented shell\n")
	env := f.exe(t, "env", "invented env\n")
	link := filepath.Join(f.bin, "dash-link")
	if err := os.Symlink(sh, link); err != nil {
		t.Fatal(err)
	}
	for name, interp := range map[string]string{"sh": sh, "env": env, "symlink to sh": link} {
		script := f.exe(t, "s-"+filepath.Base(interp), "#!"+interp+"\nrenew\n")
		t.Run(name, func(t *testing.T) {
			f.mustFail(t, cmdWith(script, "", "[[]]"), "never")
			f.mustFail(t, cmdWith(script, ack, "[[]]"), "never")
		})
	}
}

// TestScriptGTFOBinsInterpreter (N-31): a script whose interpreter has
// documented escape techniques gets the GTFOBins warning naming both, by
// the interpreter's written name and by the name it resolves to; one whose
// interpreter is not listed does not.
func TestScriptGTFOBinsInterpreter(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"make", "sed"} {
		interp := f.exe(t, name, "invented "+name+"\n")
		mk := filepath.Join(f.bin, "alias-"+name)
		if err := os.Symlink(interp, mk); err != nil {
			t.Fatal(err)
		}
		for way, written := range map[string]string{"written": interp, "resolved": mk} {
			script := f.exe(t, "run-"+name+"-"+way, "#!"+written+" -f\n")
			t.Run(name+"/"+way, func(t *testing.T) {
				p := f.mustLoad(t, cmdWith(script, ack, "[[]]"))
				if !hasWarning(p, "commands[x]", "(GTFOBins: ", script, interp, "it runs as root") {
					t.Fatalf("no GTFOBins warning naming the script and its interpreter: %q", p.Warnings)
				}
			})
		}
	}

	t.Run("not listed", func(t *testing.T) {
		interp := f.exe(t, "example-interp", "invented interpreter\n")
		p := f.mustLoad(t, cmdWith(f.exe(t, "plain-script", "#!"+interp+"\n"), ack, "[[]]"))
		if hasWarning(p, "(GTFOBins: ") {
			t.Fatalf("GTFOBins warning for an unlisted interpreter: %q", p.Warnings)
		}
	})
}
