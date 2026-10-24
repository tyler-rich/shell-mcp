//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// N-16 (handoff docs/handoff/S4C-PRIVILEGED.md): the privileged policy
// warns, as the gate's does (POLICY §6), about every command whose binary
// has documented escape techniques, from the gate's one list
// (gpolicy.EscapeTechniques), by the name the policy writes and the name
// it resolves to. A root command is the more dangerous place for one.
// Every binary is an invented fixture and is never executed.

func gtfoWarnings(ws []string) []string {
	var out []string
	for _, w := range ws {
		if strings.Contains(w, "(GTFOBins: ") { // the temp dir's name holds the test's name
			out = append(out, w)
		}
	}
	return out
}

// TestGTFOBinsWarnings: one warning for a listed binary, naming the
// command, the binary, every category the gate's list gives it and its
// page; none for an unlisted one; a symlink with an innocent name is
// recognised by the name it resolves to.
func TestGTFOBinsWarnings(t *testing.T) {
	f := newFixture(t)
	tar := f.exe(t, "tar", "invented tar\n")
	zpool := f.exe(t, "zpool", "invented zpool\n")
	real := filepath.Join(f.dir, "real")
	gatetest.Mkdir(t, real, 0o755)
	sed := filepath.Join(real, "sed")
	gatetest.WriteFile(t, sed, "invented sed\n", 0o755)
	link := filepath.Join(f.bin, "edit-config")
	if err := os.Symlink(sed, link); err != nil {
		t.Fatal(err)
	}
	pol := f.mustLoad(t, head+"commands:\n"+cmd("backup", tar, "")+cmd("pools", zpool, "")+cmd("edit", link, ""))
	hits := gtfoWarnings(pol.Warnings)
	if len(hits) != 2 {
		t.Fatalf("GTFOBins warnings %q, want two (tar and sed)", hits)
	}
	for i, c := range []struct{ id, base string }{{"backup", "tar"}, {"edit", "sed"}} {
		w := hits[i]
		if !strings.HasPrefix(w, "commands["+c.id+"]: "+c.base+" has documented escape techniques") ||
			!strings.Contains(w, "https://gtfobins.org/gtfobins/"+c.base+"/") || !strings.Contains(w, "as root") {
			t.Errorf("warning %q", w)
		}
		cats := gpolicy.EscapeTechniques(c.base)
		if len(cats) == 0 || !strings.Contains(w, "(GTFOBins: "+strings.Join(cats, ", ")+")") {
			t.Errorf("warning %q lacks the gate's categories %q", w, cats)
		}
	}
}

// TestGTFOBinsSharedList: every name on the gate's list that a privileged
// policy accepts as a command gets the warning with exactly the gate's
// categories; the list is the gate's, not a copy.
func TestGTFOBinsSharedList(t *testing.T) {
	f := newFixture(t)
	loaded := 0
	for _, name := range gpolicy.GTFOBinsNames() {
		p := f.exe(t, name, "invented "+name+"\n")
		pol, err := f.load(t, head+"commands:\n"+cmd("x", p, "    acknowledge: \"reviewed\"\n"))
		if err != nil {
			continue // refused by the privileged policy's own lists
		}
		loaded++
		hits := gtfoWarnings(pol.Warnings)
		want := "commands[x]: " + name + " has documented escape techniques (GTFOBins: " + strings.Join(gpolicy.EscapeTechniques(name), ", ") + ")"
		if len(hits) != 1 || !strings.HasPrefix(hits[0], want) {
			t.Errorf("%s: warnings %q, want one starting %q", name, hits, want)
		}
	}
	if loaded < 40 {
		t.Fatalf("only %d of %d listed names loaded as privileged commands", loaded, len(gpolicy.GTFOBinsNames()))
	}
}
