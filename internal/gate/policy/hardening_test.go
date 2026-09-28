//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// sysBin makes an invented "system binary directory" for the identity
// check: a denied binary named bash, a denied name that is a symlink
// (sh) to a binary with an innocent name, and an unrelated binary. None
// is ever executed.
func (f *fixture) sysBin(t *testing.T) string {
	t.Helper()
	sys := filepath.Join(f.dir, "sysbin")
	gatetest.Mkdir(t, sys, 0o755)
	gatetest.WriteFile(t, filepath.Join(sys, "bash"), "invented shell binary, several bytes long\n", 0o755)
	gatetest.WriteFile(t, filepath.Join(sys, "zpool"), "invented unrelated binary\n", 0o755)
	gatetest.WriteFile(t, filepath.Join(sys, "multicall"), "invented multi-call binary\n", 0o755)
	if err := os.Symlink("multicall", filepath.Join(sys, "sh")); err != nil {
		t.Fatal(err)
	}
	f.opts.SystemBinDirs = []string{sys}
	return sys
}

func cmdAt(name string) string {
	return cmdPolicy("  - id: a\n    path: {BIN}/" + name + "\n    tier: read\n    templates: [[status]]\n")
}

// TestBinaryIdentity: a hard link and a copy of a hard-denied binary under
// an innocent name are rejected, naming the denied binary; an unrelated
// binary, and one of the same size but different content, are accepted.
func TestBinaryIdentity(t *testing.T) {
	f := newFixture(t)
	sys := f.sysBin(t)
	if err := os.Link(filepath.Join(sys, "bash"), filepath.Join(f.bin, "report-tool")); err != nil {
		t.Fatal(err)
	}
	f.mustFail(t, cmdAt("report-tool"), `hard-denied "bash"`)

	b, err := os.ReadFile(filepath.Join(sys, "bash"))
	if err != nil {
		t.Fatal(err)
	}
	gatetest.WriteFile(t, filepath.Join(f.bin, "status-tool"), string(b), 0o755)
	f.mustFail(t, cmdAt("status-tool"), `hard-denied "bash"`)

	// A copy of a binary that only a denied name (sh, a symlink) points to.
	b, _ = os.ReadFile(filepath.Join(sys, "multicall"))
	gatetest.WriteFile(t, filepath.Join(f.bin, "helper"), string(b), 0o755)
	f.mustFail(t, cmdAt("helper"), `hard-denied "sh"`)

	// Same size, different content: accepted.
	same := strings.Replace(string(b), "invented", "Invented", 1)
	gatetest.WriteFile(t, filepath.Join(f.bin, "lookalike"), same, 0o755)
	f.mustLoad(t, cmdAt("lookalike"))

	// An unrelated binary, including a copy of an unrelated system binary.
	f.mustLoad(t, cmdAt("example-tool"))
	u, _ := os.ReadFile(filepath.Join(sys, "zpool"))
	gatetest.WriteFile(t, filepath.Join(f.bin, "pool-status"), string(u), 0o755)
	f.mustLoad(t, cmdAt("pool-status"))
}

func TestGitRemotesHTTPSOnly(t *testing.T) {
	f := newFixture(t)
	repo := func(remote string) string {
		return minimal + "paths:\n  read: [{R}]\ngit:\n  repos:\n    - path: {R}/deploy\n      remote: \"" + remote + "\"\n"
	}
	for _, bad := range []string{
		"http://git.example.test/org/deploy.git", "ssh://git@git.example.test/org/deploy.git",
		"git@git.example.test:org/deploy.git", "file:///srv/app/deploy.git", "git://git.example.test/org/deploy.git",
		"ext::example", "HTTPS://git.example.test/org/deploy.git", "https://", "https:///org/deploy.git", "/srv/app/deploy.git",
	} {
		f.mustFail(t, repo(bad), "https://")
	}
	p := f.mustLoad(t, repo("https://git.example.test/org/deploy.git"))
	if p.Git.Repos[0].Remote != "https://git.example.test/org/deploy.git" {
		t.Fatalf("remote %q", p.Git.Repos[0].Remote)
	}
	// git_pull needs the remote's port in tcp_connect_ports: warn when missing.
	if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "tcp_connect_ports") && strings.Contains(w, "443") }) {
		t.Fatalf("no port warning: %q", p.Warnings)
	}
	p = f.mustLoad(t, strings.Replace(repo("https://git.example.test:8443/org/deploy.git"), "paths:", "sandbox:\n  tcp_connect_ports: [8443]\npaths:", 1))
	if slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "tcp_connect_ports") }) {
		t.Fatalf("port warning with the port listed: %q", p.Warnings)
	}
}

func TestGTFOBinsWarnings(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"tar", "find", "openssl"} {
		f.exe(t, n)
	}
	f.exe(t, "zpool")
	p := f.mustLoad(t, cmdPolicy("  - id: backup\n    path: {BIN}/tar\n    tier: read\n    templates: [[\"-tf\", \"{path:read}\"]]\n"+
		"  - id: pools\n    path: {BIN}/zpool\n    tier: read\n    templates: [[status]]\n"))
	var hit []string
	for _, w := range p.Warnings {
		if strings.Contains(w, "GTFOBins") {
			hit = append(hit, w)
		}
	}
	if len(hit) != 1 || !strings.Contains(hit[0], "commands[backup]") || !strings.Contains(hit[0], "command execution") ||
		!strings.Contains(hit[0], "file read") || !strings.Contains(hit[0], "https://gtfobins.github.io/gtfobins/tar/") {
		t.Fatalf("warnings %q", p.Warnings)
	}
	for _, n := range []string{"tar", "find", "openssl"} {
		if len(policy.EscapeTechniques(n)) == 0 {
			t.Errorf("%s has no techniques", n)
		}
	}
	if policy.EscapeTechniques("zpool") != nil || policy.EscapeTechniques("") != nil {
		t.Error("unlisted binary has techniques")
	}
}

// The GTFOBins list is our own: names and our four categories only.
func TestGTFOBinsListShape(t *testing.T) {
	names := policy.GTFOBinsNames()
	if len(names) < 40 || !slices.IsSorted(names) {
		t.Fatalf("list has %d names or is unsorted", len(names))
	}
	allowed := []string{"command execution", "file read", "file write", "SUID abuse"}
	for _, n := range names {
		cats := policy.EscapeTechniques(n)
		if len(cats) == 0 {
			t.Errorf("%s: no categories", n)
		}
		for _, c := range cats {
			if !slices.Contains(allowed, c) {
				t.Errorf("%s: category %q", n, c)
			}
		}
	}
}
