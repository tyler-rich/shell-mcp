package workflowcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workflowDir is the repository's workflows; WORKFLOWCHECK_DIR points the
// tests at another copy (used to show they fail on an older tree).
func workflowDir() string {
	if d := os.Getenv("WORKFLOWCHECK_DIR"); d != "" {
		return d
	}
	return filepath.Join("..", "..", ".github", "workflows")
}

func TestEveryWorkflowRunsWithPipefail(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(workflowDir(), "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yaml, err := filepath.Glob(filepath.Join(workflowDir(), "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, yaml...)
	if len(files) == 0 {
		t.Fatal("no workflows found")
	}
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // G304: the repository's own workflows
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckPipefail(data); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}

const goodPipefail = `
defaults:
  run:
    shell: bash
jobs:
  a:
    runs-on: x
    steps:
      - run: bash run.sh | tee -a "$GITHUB_STEP_SUMMARY"
      - run: "true"
        shell: bash
`

func TestCheckPipefail(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"bash default", goodPipefail, ""},
		{"no defaults", strings.Replace(goodPipefail, "defaults:\n  run:\n    shell: bash\n", "", 1), `top-level defaults.run.shell is "", want bash`},
		{"another default", strings.Replace(goodPipefail, "    shell: bash\njobs", "    shell: sh\njobs", 1), `top-level defaults.run.shell is "sh", want bash`},
		{"a step's own shell", strings.Replace(goodPipefail, "        shell: bash", "        shell: bash -e {0}", 1), `shell is "bash -e {0}"`},
		{"a job's own default", strings.Replace(goodPipefail, "    runs-on: x", "    runs-on: x\n    defaults: {run: {shell: sh}}", 1), `job a: defaults.run.shell is "sh"`},
		{"not a workflow", "jobs: {}\n", "no jobs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckPipefail([]byte(c.yaml))
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}
