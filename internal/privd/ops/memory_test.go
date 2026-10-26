//go:build linux

package ops_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The helper's commands and apt-get run with RLIMIT_DATA at the privileged
// policy's limits.max_memory_mb, soft and hard (handoff N-30).

const privMemMB = 192

var privMemData = fmt.Sprintf("data=%d/%d", privMemMB<<20, privMemMB<<20)

// withMemLimit sets limits.max_memory_mb in the fixture policy.
func withMemLimit(mb int) opt {
	return replace("  max_delete_entries: 20\n", fmt.Sprintf("  max_delete_entries: 20\n  max_memory_mb: %d\n", mb))
}

// withMemCommand declares a command that reports, raises and tests the
// limit (before any option that appends other sections).
func withMemCommand() opt {
	return func(f *fixture, s *string) {
		*s += fmt.Sprintf("  - id: probe-mem\n    path: %s\n    tier: read\n"+
			"    templates: [[\"rlimits\"], [\"child-rlimits\"], [\"raise-data\"], [\"alloc\", \"{int:1-4096}\"]]\n", f.probe)
	}
}

type privMemExec struct {
	ExitCode *int    `json:"exit_code"`
	Signal   *string `json:"signal"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
}

// TestPrivExecMemoryLimit: a root command runs with the policy's limit,
// passes it on, cannot raise it without CAP_SYS_RESOURCE (which the core
// unit never holds), and an allocation past it is the command's own
// failure, answered as its result (not outcome_unknown).
func TestPrivExecMemoryLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, withMemCommand(), withMemLimit(privMemMB))
	var d privMemExec
	f.ok("priv_exec", m{"command_id": "probe-mem", "args": []string{"rlimits"}}, &d)
	if !strings.Contains(d.Stdout, privMemData) {
		t.Fatalf("rlimits %q, want %s", d.Stdout, privMemData)
	}
	f.ok("priv_exec", m{"command_id": "probe-mem", "args": []string{"child-rlimits"}}, &d)
	if !strings.Contains(d.Stdout, privMemData) {
		t.Fatalf("the command's child: %q, want %s", d.Stdout, privMemData)
	}
	if os.Getuid() != 0 {
		f.ok("priv_exec", m{"command_id": "probe-mem", "args": []string{"raise-data"}}, &d)
		if strings.TrimSpace(d.Stdout) != "raise=EPERM unlimited=EPERM" {
			t.Fatalf("raise-data %q", d.Stdout)
		}
	}
	start := time.Now()
	f.ok("priv_exec", m{"command_id": "probe-mem", "args": []string{"alloc", "2048"}}, &d)
	if d.ExitCode == nil || *d.ExitCode == 0 || !goOOM(d.Stderr) {
		t.Fatalf("2048 MiB under %d MiB: %+v", privMemMB, d)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %v", el)
	}
	// The default when the key is absent.
	def := newFixture(t, withMemCommand())
	def.ok("priv_exec", m{"command_id": "probe-mem", "args": []string{"rlimits"}}, &d)
	if want := fmt.Sprintf("data=%d/%d", 1024<<20, 1024<<20); !strings.Contains(d.Stdout, want) {
		t.Fatalf("default rlimits %q, want %s", d.Stdout, want)
	}
}

// TestPkgAptGetMemoryLimit: apt-get, for the previews' simulations and the
// operation alike, runs with the limit (dpkg and maintainer scripts inherit
// it).
func TestPkgAptGetMemoryLimit(t *testing.T) {
	f := pkgFixture(t, "ok", withMemLimit(privMemMB))
	var u preview
	f.ok("priv_pkg_update_index_preview", m{}, &u)
	f.ok("priv_pkg_update_index", m{"expected_preview_sha256": u.PreviewSHA256}, nil)
	b, err := os.ReadFile(f.aptLog + ".limits")
	if err != nil {
		t.Fatalf("apt-get limits log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 1 || len(lines) != f.aptRunsLogged() {
		t.Fatalf("%d limit lines for %d apt-get runs", len(lines), f.aptRunsLogged())
	}
	for i, l := range lines {
		if l != privMemData {
			t.Fatalf("apt-get run %d: %q, want %s", i, l, privMemData)
		}
	}
}

// aptRunsLogged is how many apt-get runs the stand-in logged.
func (f *fixture) aptRunsLogged() int {
	f.t.Helper()
	b, _ := os.ReadFile(f.aptLog)
	return strings.Count(string(b), "\n")
}

// goOOM reports a Go program's fatal error at its memory limit: "out of
// memory" when the heap cannot grow, "cannot allocate memory" when the
// runtime's own metadata cannot (where the limit is met decides which).
func goOOM(stderr string) bool {
	return strings.Contains(stderr, "fatal error: runtime: out of memory") || strings.Contains(stderr, "fatal error: out of memory") ||
		strings.Contains(stderr, "fatal error: runtime: cannot allocate memory")
}
