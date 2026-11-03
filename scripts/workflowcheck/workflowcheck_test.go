package workflowcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reportOnly are ci.yml's jobs that may never fail the ci aggregate.
var reportOnly = []string{"probes"}

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

func TestCIAggregateRequiresEveryJob(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(workflowDir(), "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckAggregate(data, "ci", reportOnly); err != nil {
		t.Error(err)
	}
}

const goodAggregate = `
jobs:
  a: {runs-on: x, steps: [{run: "true"}]}
  b: {runs-on: x, steps: [{run: "true"}]}
  probes: {runs-on: x, continue-on-error: true, steps: [{run: "true"}]}
  ci:
    if: always()
    needs: [a, b]
    steps:
      - if: contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'skipped')
        run: exit 1
`

func TestCheckAggregate(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"complete", goodAggregate, ""},
		{"a job left out", strings.Replace(goodAggregate, "needs: [a, b]", "needs: [a]", 1), "job b is not in ci's needs"},
		{"a single need", strings.Replace(goodAggregate, "needs: [a, b]", "needs: a", 1), "job b is not in ci's needs"},
		{"a need that is no job", strings.Replace(goodAggregate, "needs: [a, b]", "needs: [a, b, c]", 1), "ci needs c, which is not a job"},
		{"report-only required", strings.Replace(goodAggregate, "needs: [a, b]", "needs: [a, b, probes]", 1), "job probes is report-only but ci needs it"},
		{"report-only that can fail", strings.Replace(goodAggregate, "continue-on-error: true, ", "", 1), "report-only job probes is not continue-on-error: true"},
		{"not always", strings.Replace(goodAggregate, "if: always()", "if: success()", 1), `if is "success()", want always()`},
		{"skipped not failing", strings.Replace(goodAggregate, " || contains(needs.*.result, 'skipped')", "", 1), "no step that exits 1"},
		{"no exit", strings.Replace(goodAggregate, "run: exit 1", "run: echo", 1), "no step that exits 1"},
		{"no aggregate", strings.Replace(goodAggregate, "  ci:\n", "  other:\n", 1), "no job ci"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckAggregate([]byte(c.yaml), "ci", reportOnly)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("error %v, want one containing %q", err, c.want)
			}
		})
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
