//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// No git process the gate starts enters a submodule, end to end (handoff
// docs/handoff/S4C-PRIVILEGED.md N-23, POLICY §7): the real gate as the
// service account (svc-shell), with Landlock, under the hardening policy,
// on the closed repository of gate_git_chain_test.go with a gitlink at
// vendor/lib whose directory example-app owns. It holds a repository whose
// own configuration names a clean filter that only creates a marker file
// in svc-shell's git directory, applied to a file whose stat data changed,
// so any git status run inside it as svc-shell runs the filter. Every git
// operation must answer without creating the marker. Every path and name
// is invented.

const (
	subLib    = hardRepo + "/vendor/lib"
	subMarker = hardGit + "/submodule-marker"
)

// asRoot runs git as root in svc-shell's repository (safe.directory: root
// is not its owner).
func asRoot(t *testing.T, dir string, args ...string) {
	t.Helper()
	gatetest.Git(t, dir, append([]string{"-c", "safe.directory=*"}, args...)...)
}

// gitlinkRepo gives hardRepo a local commit adding the gitlink vendor/lib,
// populated with example-app's repository and its marker filter.
func gitlinkRepo(t *testing.T) {
	t.Helper()
	hardRepoFixture(t)
	src := filepath.Join(t.TempDir(), "lib-src")
	gatetest.Mkdir(t, src, 0o755)
	gatetest.Git(t, src, "init", "-q")
	gatetest.WriteFile(t, filepath.Join(src, "data.txt"), "data\n", 0o644)
	gatetest.WriteFile(t, filepath.Join(src, ".gitattributes"), "data.txt filter=marker\n", 0o644)
	gatetest.Git(t, src, "add", "-A")
	gatetest.Git(t, src, "commit", "-q", "-m", "lib")
	head := strings.TrimSpace(gatetest.Git(t, src, "rev-parse", "HEAD"))
	asRoot(t, hardRepo, "update-index", "--add", "--cacheinfo", "160000,"+head+",vendor/lib")
	asRoot(t, hardRepo, "commit", "-q", "-m", "add lib")
	gatetest.Mkdir(t, filepath.Dir(subLib), 0o755)
	gatetest.Git(t, filepath.Dir(subLib), "clone", "-q", src, "lib")
	gatetest.Git(t, subLib, "config", "filter.marker.clean", "touch "+subMarker+"; cat")
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "svc-shell:svc-shell", hardRepo).CombinedOutput(); err != nil {
		t.Fatalf("chown: %v: %s", err, out)
	}
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "example-app:example-app", subLib).CombinedOutput(); err != nil {
		t.Fatalf("chown: %v: %s", err, out)
	}
}

// subStatDirty changes data.txt's stat data in the submodule, not its
// content, and removes the marker.
func subStatDirty(t *testing.T) {
	t.Helper()
	_ = os.Remove(subMarker)
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(subLib+"/data.txt", old, old); err != nil {
		t.Fatal(err)
	}
}

// TestGateGitNeverEntersSubmodule (N-23): see the file comment.
func TestGateGitNeverEntersSubmodule(t *testing.T) {
	gitlinkRepo(t)
	conf := hardRepo + "/app.conf"
	for _, c := range []struct {
		name, op string
		args     map[string]any
	}{
		{"git_status", "git_status", map[string]any{"repo": hardRepo}},
		{"git_log", "git_log", map[string]any{"repo": hardRepo}},
		{"git_diff", "git_diff", map[string]any{"repo": hardRepo}},
		{"git_diff staged", "git_diff", map[string]any{"repo": hardRepo, "staged": true}},
		{"git_pull", "git_pull", map[string]any{"repo": hardRepo}},
		{"git_discard_preview", "git_discard_preview", map[string]any{"repo": hardRepo, "include_untracked": true}},
		{"git_discard", "git_discard", map[string]any{"repo": hardRepo, "include_untracked": true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.HasPrefix(c.op, "git_discard") {
				ownFile(t, conf, "changed\n", svcShell, 0o644)
			}
			if c.op == "git_discard" {
				pv := hard(t, "git_discard_preview", map[string]any{"repo": hardRepo, "include_untracked": true})
				var p struct {
					PreviewSHA256 string `json:"preview_sha256"`
				}
				if !pv.OK || json.Unmarshal(pv.Data, &p) != nil {
					t.Fatalf("discard preview: %+v %s", pv.Error, pv.Data)
				}
				c.args["expected_preview_sha256"] = p.PreviewSHA256
			}
			subStatDirty(t)
			r := hard(t, c.op, c.args)
			if _, err := os.Stat(subMarker); err == nil {
				t.Fatalf("%s entered the submodule as svc-shell: the filter example-app's configuration names ran (answer %+v)", c.name, r.Error)
			}
			if !r.OK {
				t.Fatalf("%s with a populated submodule: %+v", c.name, r.Error)
			}
			if c.op == "git_discard" {
				fileIs(t, conf, "version: 1\n")
			}
		})
	}
}
