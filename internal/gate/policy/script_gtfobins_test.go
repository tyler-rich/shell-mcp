//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// A #! script's interpreter in the GTFOBins warning (handoff N-31), and the
// gate's scripts left as they were (N-26 changes the privileged policy
// only): the warning names the script and its interpreter, by the
// interpreter's written name and the name it resolves to, and a script
// whose interpreter is not listed gets none. Invented fixtures, never run.
func TestScriptGTFOBinsInterpreter(t *testing.T) {
	f := newFixture(t)
	script := func(name, body string) string {
		p := filepath.Join(f.bin, name)
		gatetest.WriteFile(t, p, body, 0o755)
		return p
	}
	for _, name := range []string{"make", "sed"} {
		f.exe(t, name)
		interp := filepath.Join(f.bin, name)
		alias := filepath.Join(f.bin, "alias-"+name)
		if err := os.Symlink(interp, alias); err != nil {
			t.Fatal(err)
		}
		for way, written := range map[string]string{"written": interp, "resolved": alias} {
			s := script("run-"+name+"-"+way, "#!"+written+" -f\n")
			t.Run(name+"/"+way, func(t *testing.T) {
				p := f.mustLoad(t, cmdPath(s))
				if !warned(p, "commands[x]", "(GTFOBins: ", s, interp) {
					t.Fatalf("no GTFOBins warning naming the script and its interpreter: %q", p.Warnings)
				}
			})
		}
	}

	t.Run("not listed", func(t *testing.T) {
		interp := filepath.Join(f.bin, "example-interp")
		gatetest.WriteFile(t, interp, "invented interpreter\n", 0o755)
		p := f.mustLoad(t, cmdPath(script("plain-script", "#!"+interp+"\n")))
		if warned(p, "(GTFOBins: ") {
			t.Fatalf("GTFOBins warning for an unlisted interpreter: %q", p.Warnings)
		}
	})

	t.Run("no acknowledge needed", func(t *testing.T) {
		interp := filepath.Join(f.bin, "example-interp")
		p := f.mustLoad(t, cmdPath(script("gate-script", "#!"+interp+"\n")))
		if c, _ := p.Command("x"); c.Interpreter != interp {
			t.Fatalf("interpreter %q", c.Interpreter)
		}
	})
}
