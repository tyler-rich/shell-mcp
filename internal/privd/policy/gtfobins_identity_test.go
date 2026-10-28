//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The helper's GTFOBins warning matches by binary identity as well as by
// the name written and the name resolved (handoff N-33), as the gate's
// does: for a command's program and for a #! script's interpreter. Every
// binary is an invented fixture, never executed.

const (
	sedBody   = "invented sed body, a few bytes long\n"
	zpoolBody = "invented unlisted body, a few bytes\n"
)

func (f *fixture) gtfoSys(t *testing.T) {
	t.Helper()
	gatetest.WriteFile(t, filepath.Join(f.sysbin, "sed"), sedBody, 0o755)
	gatetest.WriteFile(t, filepath.Join(f.sysbin, "zpool"), zpoolBody, 0o755)
}

func TestGTFOBinsIdentity(t *testing.T) {
	f := newFixture(t)
	f.gtfoSys(t)
	f.exe(t, "report-tool", sedBody)
	if err := os.Link(filepath.Join(f.sysbin, "sed"), filepath.Join(f.bin, "report-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.sysbin, "sed"), filepath.Join(f.bin, "report-sym")); err != nil {
		t.Fatal(err)
	}
	f.exe(t, "sed", "invented other body, a few bytes\n")
	f.exe(t, "pool-status", zpoolBody)
	f.exe(t, "lookalike", strings.Replace(sedBody, "invented", "Invented", 1))

	for _, c := range []struct{ name, kind string }{
		{"report-tool", "matched sed by binary identity"},
		{"report-link", "matched sed by binary identity"},
		{"report-sym", "matched sed by resolved name"},
		{"sed", "matched sed by written name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := f.mustLoad(t, head+"commands:\n"+cmd("x", filepath.Join(f.bin, c.name), ack))
			hits := gtfoWarnings(p.Warnings)
			if len(hits) != 1 || !strings.Contains(hits[0], "commands[x]: sed has documented escape techniques") ||
				!strings.Contains(hits[0], "as root") || !strings.Contains(hits[0], c.kind) {
				t.Fatalf("GTFOBins warnings %q, want one containing %q", hits, c.kind)
			}
		})
	}
	for _, name := range []string{"pool-status", "lookalike", "example-tool"} {
		t.Run("no warning/"+name, func(t *testing.T) {
			p := f.mustLoad(t, head+"commands:\n"+cmd("x", filepath.Join(f.bin, name), ack))
			if hits := gtfoWarnings(p.Warnings); len(hits) != 0 {
				t.Fatalf("GTFOBins warning for %s: %q", name, hits)
			}
		})
	}
}

func TestGTFOBinsIdentityInterpreter(t *testing.T) {
	f := newFixture(t)
	f.gtfoSys(t)
	copyInterp := f.exe(t, "interp-copy", sedBody)
	script := f.exe(t, "run-copy", "#!"+copyInterp+" -f\n")
	p := f.mustLoad(t, head+"commands:\n"+cmd("x", script, ack))
	hits := gtfoWarnings(p.Warnings)
	if len(hits) != 1 || !strings.Contains(hits[0], script) || !strings.Contains(hits[0], copyInterp) ||
		!strings.Contains(hits[0], "as root") || !strings.Contains(hits[0], "matched sed by binary identity") {
		t.Fatalf("GTFOBins warnings %q", hits)
	}
	plain := f.exe(t, "interp-plain", zpoolBody)
	s2 := f.exe(t, "run-plain", "#!"+plain+"\n")
	p = f.mustLoad(t, head+"commands:\n"+cmd("x", s2, ack))
	if hits := gtfoWarnings(p.Warnings); len(hits) != 0 {
		t.Fatalf("GTFOBins warning for an unlisted interpreter: %q", hits)
	}
}

func TestGTFOBinsIdentityNeverRefuses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0 file")
	}
	f := newFixture(t)
	f.gtfoSys(t)
	if err := os.Chmod(filepath.Join(f.sysbin, "sed"), 0); err != nil {
		t.Fatal(err)
	}
	f.exe(t, "same-size", strings.Replace(sedBody, "invented", "Invented", 1))
	p := f.mustLoad(t, head+"commands:\n"+cmd("x", filepath.Join(f.bin, "same-size"), ack))
	if hits := gtfoWarnings(p.Warnings); len(hits) != 0 {
		t.Fatalf("GTFOBins warning: %q", hits)
	}
}
