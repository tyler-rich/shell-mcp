//go:build linux && shellmcp_gitconfig_hook

package ops_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
	"github.com/tyler-rich/shell-mcp/internal/gate/ops"
)

// The second layer of N-20 (handoff docs/handoff/S4C-PRIVILEGED.md; POLICY
// §7), in the shellmcp_gitconfig_hook test build: the repository's
// configuration is changed after the gate checked it and before its next git
// process, as only a trusted account could do in a closed repository, to set
// every program-running key the gate overrides, a hooks directory, and a hook
// defined in configuration for every event, each naming a script that only
// writes a marker in the test's directory. Every git operation must then
// still answer without running any of them. Everything is invented.

// programKeys are the keys set after the check, each to the marker script:
// every key gitx's table forces on the command line (core.hooksPath is set
// again below, to a directory of hooks), and a configured hook.
var programKeys = func() []string {
	out := []string{"hook.marker.command"}
	for i := range gitx.ProgramKeys {
		for _, a := range gitx.ProgramKeys[i].Args {
			k, _, _ := strings.Cut(a, "=")
			out = append(out, k)
		}
	}
	return out
}()

func TestGitConfigChangedAfterCheck(t *testing.T) {
	for _, op := range []string{"git_status", "git_log", "git_diff", "git_pull", "git_discard_preview", "git_discard"} {
		t.Run(op, func(t *testing.T) {
			g := newGitFixture(t, "destructive")
			marker := filepath.Join(g.dir, "MARKER")
			script := filepath.Join(g.dir, "mark.sh")
			gatetest.WriteFile(t, script, "#!/bin/sh\necho \"$0 $*\" >> "+marker+"\n", 0o755)
			hooks := filepath.Join(g.dir, "hooks")
			for _, e := range gitHookEvents {
				gatetest.WriteFile(t, filepath.Join(hooks, e), "#!/bin/sh\necho "+e+" >> "+marker+"\n", 0o755)
			}
			args := m{"repo": g.repo}
			switch op {
			case "git_pull":
				gatetest.Push(t, g.work, "upstream.txt", "from upstream\n", "upstream change")
			case "git_diff", "git_status", "git_log":
				smallChange(t, g)
			case "git_discard_preview", "git_discard":
				smallChange(t, g)
				args["include_untracked"] = true
				if op == "git_discard" {
					pv := g.preview(t, true)
					args["expected_preview_sha256"] = pv.PreviewSHA256
				}
			}
			// The test's own setup can run the planted hooks; only the
			// operation counts.
			_ = os.Remove(marker)
			var build string
			g.opts.AfterGitConfigCheck = func(b, repo string) {
				build = b
				for _, k := range programKeys {
					gatetest.Git(t, repo, "config", k, script)
				}
				gatetest.Git(t, repo, "config", "core.hooksPath", hooks)
				for _, e := range gitHookEvents {
					gatetest.Git(t, repo, "config", "--add", "hook.marker.event", e)
				}
			}
			r := g.call(op, args)
			if build != "shellmcp_gitconfig_hook test build" {
				t.Fatalf("the hook did not run after the configuration check (%q)", build)
			}
			if exists(marker) {
				b, _ := os.ReadFile(marker) //nolint:gosec // G304: the test's own marker
				t.Fatalf("%s ran a program the repository's configuration named after the check: %s (answer %+v)", op, b, r.Error)
			}
			if !r.OK {
				t.Fatalf("%s: %+v, want it to ignore the configuration it overrides", op, r.Error)
			}
			// The keys are in place: the next operation's check refuses them.
			g.opts.AfterGitConfigCheck = nil
			g.fail("git_status", m{"repo": g.repo}, "policy_denied")
		})
	}
}

// TestProductionOptionsHaveNoGitConfigHook: the production constructor
// leaves the test build's hook unset.
func TestProductionOptionsHaveNoGitConfigHook(t *testing.T) {
	o, err := ops.ProductionOptions("v", "/etc/shell-mcp/policy.yaml", "readonly")
	if err != nil {
		t.Fatal(err)
	}
	if o.AfterGitConfigCheck != nil {
		t.Fatal("production options set AfterGitConfigCheck")
	}
}
