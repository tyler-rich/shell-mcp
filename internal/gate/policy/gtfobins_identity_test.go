//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// The GTFOBins warning matches by binary identity as well as by the name
// written and the name resolved (handoff N-33), for a command's program and
// for a #! script's interpreter, as the hard-deny list does (POLICY §5, §6).
// Every binary is an invented fixture, never executed.

const (
	sedBody   = "invented sed body, a few bytes long\n"
	zpoolBody = "invented unlisted body, a few bytes\n"
)

// gtfoSys lays out an invented system binary directory with a listed
// program (sed) and an unlisted one (zpool), and returns it.
func (f *fixture) gtfoSys(t *testing.T) string {
	t.Helper()
	sys := filepath.Join(f.dir, "gtfosys")
	gatetest.Mkdir(t, sys, 0o755)
	gatetest.WriteFile(t, filepath.Join(sys, "sed"), sedBody, 0o755)
	gatetest.WriteFile(t, filepath.Join(sys, "zpool"), zpoolBody, 0o755)
	f.opts.SystemBinDirs = []string{sys}
	return sys
}

func gtfoWarnings(p *policy.Policy) []string {
	var out []string
	for _, w := range p.Warnings {
		if strings.Contains(w, "(GTFOBins: ") {
			out = append(out, w)
		}
	}
	return out
}

// TestGTFOBinsIdentity: a renamed copy and a hard link of a listed program
// get the warning naming the listed program and "binary identity"; a
// symlink to it and a file of its name get it by the resolved and the
// written name, once each; an unlisted program, a copy of one and a file of
// a listed program's size and other content get none.
func TestGTFOBinsIdentity(t *testing.T) {
	f := newFixture(t)
	sys := f.gtfoSys(t)
	gatetest.WriteFile(t, filepath.Join(f.bin, "report-tool"), sedBody, 0o755)
	if err := os.Link(filepath.Join(sys, "sed"), filepath.Join(f.bin, "report-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(sys, "sed"), filepath.Join(f.bin, "report-sym")); err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(f.bin, "sed"), "invented other body, a few bytes\n", 0o755)
	gatetest.WriteFile(t, filepath.Join(f.bin, "pool-status"), zpoolBody, 0o755)
	gatetest.WriteFile(t, filepath.Join(f.bin, "lookalike"), strings.Replace(sedBody, "invented", "Invented", 1), 0o755)

	for _, c := range []struct{ name, kind string }{
		{"report-tool", "matched sed by binary identity"},
		{"report-link", "matched sed by binary identity"},
		{"report-sym", "matched sed by resolved name"},
		{"sed", "matched sed by written name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := f.mustLoad(t, cmdPath(filepath.Join(f.bin, c.name)))
			hits := gtfoWarnings(p)
			if len(hits) != 1 || !strings.Contains(hits[0], "commands[x]: sed has documented escape techniques") || !strings.Contains(hits[0], c.kind) {
				t.Fatalf("GTFOBins warnings %q, want one containing %q", hits, c.kind)
			}
		})
	}
	for _, name := range []string{"pool-status", "lookalike", "example-tool"} {
		t.Run("no warning/"+name, func(t *testing.T) {
			if hits := gtfoWarnings(f.mustLoad(t, cmdPath(filepath.Join(f.bin, name)))); len(hits) != 0 {
				t.Fatalf("GTFOBins warning for %s: %q", name, hits)
			}
		})
	}
}

// TestGTFOBinsIdentityInterpreter: a #! script whose interpreter is a
// renamed copy of a listed program gets the interpreter warning (handoff
// N-31), naming the script, the interpreter and the listed program; one
// whose interpreter is an unlisted program's copy gets none.
func TestGTFOBinsIdentityInterpreter(t *testing.T) {
	f := newFixture(t)
	f.gtfoSys(t)
	copyInterp := filepath.Join(f.bin, "interp-copy")
	gatetest.WriteFile(t, copyInterp, sedBody, 0o755)
	plainInterp := filepath.Join(f.bin, "interp-plain")
	gatetest.WriteFile(t, plainInterp, zpoolBody, 0o755)
	script := func(name, interp string) string {
		p := filepath.Join(f.bin, name)
		gatetest.WriteFile(t, p, "#!"+interp+" -f\n", 0o755)
		return p
	}
	s := script("run-copy", copyInterp)
	p := f.mustLoad(t, cmdPath(s))
	if !warned(p, "commands[x]", "(GTFOBins: ", s, copyInterp, "matched sed by binary identity") {
		t.Fatalf("no GTFOBins warning naming the script, its interpreter and the listed program: %q", p.Warnings)
	}
	if hits := gtfoWarnings(f.mustLoad(t, cmdPath(script("run-plain", plainInterp)))); len(hits) != 0 {
		t.Fatalf("GTFOBins warning for an unlisted interpreter: %q", hits)
	}
}

// TestGTFOBinsIdentityContent: a renamed copy of a listed GNU coreutils
// program is recognised by what it holds, where no system copy of it is
// scanned (S-MC).
func TestGTFOBinsIdentityContent(t *testing.T) {
	f := newFixture(t)
	f.gtfoSys(t)
	gatetest.WriteFile(t, filepath.Join(f.bin, "show-file"), "invented GNU program\x00"+marker("gnu")+"\x00cat\x00", 0o755)
	p := f.mustLoad(t, cmdPath(filepath.Join(f.bin, "show-file")))
	if !warned(p, "commands[x]: cat has documented escape techniques", "matched cat by binary identity") {
		t.Fatalf("no GTFOBins warning for a renamed GNU cat: %q", p.Warnings)
	}
}

// TestGTFOBinsIdentityNeverRefuses: the warning is an aid. A listed
// program's copy that cannot be read, of the command's size, does not
// refuse the policy (a hard-denied one would, fail-closed); the skipped
// comparison is a warning.
func TestGTFOBinsIdentityNeverRefuses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0 file")
	}
	f := newFixture(t)
	sys := f.gtfoSys(t)
	chmod(t, filepath.Join(sys, "sed"), 0)
	gatetest.WriteFile(t, filepath.Join(f.bin, "same-size"), strings.Replace(sedBody, "invented", "Invented", 1), 0o755)
	p := f.mustLoad(t, cmdPath(filepath.Join(f.bin, "same-size")))
	if hits := gtfoWarnings(p); len(hits) != 0 {
		t.Fatalf("GTFOBins warning: %q", hits)
	}
	if !warned(p, "commands[x]", "GTFOBins", "could not be compared") {
		t.Fatalf("no warning that the comparison was skipped: %q", p.Warnings)
	}
}
