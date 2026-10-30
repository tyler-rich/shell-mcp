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

// reads_private_keys (handoff N-35): a command's opt-in to {path:read}
// files that hold a private key, and check-policy's warning when the
// opted-in program prints ranges or filtered parts of its input. Every
// binary is an invented fixture, never executed.

const tailBody = "invented tail body, a few bytes\n"

func keyCmd(path, extra string) string {
	return cmdPolicy("  - id: x\n    path: " + path + "\n    tier: read\n" + extra + "    templates: [[\"{path:read}\"]]\n")
}

func rangeWarnings(p *policy.Policy) []string {
	var out []string
	for _, w := range p.Warnings {
		if strings.Contains(w, "reads_private_keys") {
			out = append(out, w)
		}
	}
	return out
}

func TestReadsPrivateKeysParsed(t *testing.T) {
	f := newFixture(t)
	p := f.mustLoad(t, keyCmd("{BIN}/example-tool", "    reads_private_keys: true\n"))
	if c, _ := p.Command("x"); !c.ReadsPrivateKeys {
		t.Fatalf("reads_private_keys not set: %+v", c)
	}
	p = f.mustLoad(t, keyCmd("{BIN}/example-tool", ""))
	if c, _ := p.Command("x"); c.ReadsPrivateKeys {
		t.Fatal("reads_private_keys set by default")
	}
	if w := rangeWarnings(p); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
	f.mustFail(t, keyCmd("{BIN}/example-tool", "    reads_private_keys: yes please\n"), "into bool")
}

// TestReadsPrivateKeysRangeWarning: an opted-in command whose program is
// a range or filter program gets a warning, by the name written, the name
// resolved or the binary's identity; the same program without the opt-in,
// and an opted-in program that is none of them, get none.
func TestReadsPrivateKeysRangeWarning(t *testing.T) {
	f := newFixture(t)
	sys := filepath.Join(f.dir, "rangesys")
	gatetest.Mkdir(t, sys, 0o755)
	gatetest.WriteFile(t, filepath.Join(sys, "tail"), tailBody, 0o755)
	f.opts.SystemBinDirs = []string{sys}
	gatetest.WriteFile(t, filepath.Join(f.bin, "tail"), "invented other tail, a few bytes\n", 0o755)
	gatetest.WriteFile(t, filepath.Join(f.bin, "log-viewer"), tailBody, 0o755)
	if err := os.Symlink(filepath.Join(sys, "tail"), filepath.Join(f.bin, "viewer-link")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, kind string }{
		{"tail", "matched tail by written name"},
		{"log-viewer", "matched tail by binary identity"},
		{"viewer-link", "matched tail by resolved name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := f.mustLoad(t, keyCmd(filepath.Join(f.bin, c.name), "    reads_private_keys: true\n"))
			w := rangeWarnings(p)
			if len(w) != 1 || !strings.Contains(w[0], "commands[x]:") || !strings.Contains(w[0], c.kind) {
				t.Fatalf("warnings %q, want one containing %q", w, c.kind)
			}
			if w := rangeWarnings(f.mustLoad(t, keyCmd(filepath.Join(f.bin, c.name), ""))); len(w) != 0 {
				t.Fatalf("without the opt-in: %q", w)
			}
		})
	}
	if w := rangeWarnings(f.mustLoad(t, keyCmd("{BIN}/example-tool", "    reads_private_keys: true\n"))); len(w) != 0 {
		t.Fatalf("an unlisted program: %q", w)
	}
}

func TestRangeProgramsListShape(t *testing.T) {
	names := policy.RangeProgramNames()
	for _, n := range []string{"tail", "head", "sed", "cut", "grep", "awk", "dd", "tac", "sort"} {
		found := false
		for _, m := range names {
			found = found || m == n
		}
		if !found {
			t.Errorf("%s is not listed", n)
		}
	}
	for _, n := range []string{"openssl", "ssh-keygen", "sha256sum", "cat"} {
		for _, m := range names {
			if m == n {
				t.Errorf("%s is listed", n)
			}
		}
	}
}
