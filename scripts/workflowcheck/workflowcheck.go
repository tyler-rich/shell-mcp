// Package workflowcheck checks the structure of the GitHub workflows that
// the repository's CI depends on, where nothing else would notice a
// mistake: every workflow runs its steps with pipefail. Its tests run in
// CI's go job and in ci-local's go test.
package workflowcheck

import (
	"errors"
	"fmt"
	"sort"

	"go.yaml.in/yaml/v3"
)

// workflow is the part of a workflow file these checks read.
type workflow struct {
	Defaults defaults        `yaml:"defaults"`
	Jobs     map[string]*job `yaml:"jobs"`
}

type defaults struct {
	Run struct {
		Shell string `yaml:"shell"`
	} `yaml:"run"`
}

type job struct {
	If              string   `yaml:"if"`
	Needs           needs    `yaml:"needs"`
	ContinueOnError any      `yaml:"continue-on-error"`
	Defaults        defaults `yaml:"defaults"`
	Uses            string   `yaml:"uses"`
	Steps           []step   `yaml:"steps"`
}

type step struct {
	Name  string `yaml:"name"`
	If    string `yaml:"if"`
	Run   string `yaml:"run"`
	Shell string `yaml:"shell"`
}

// needs is a job's needs: one job id or a list of them.
type needs []string

func (n *needs) UnmarshalYAML(v *yaml.Node) error {
	switch v.Kind {
	case yaml.ScalarNode:
		*n = needs{v.Value}
		return nil
	case yaml.SequenceNode:
		var l []string
		if err := v.Decode(&l); err != nil {
			return fmt.Errorf("needs: %w", err)
		}
		*n = l
		return nil
	default:
		return errors.New("needs: neither a job id nor a list")
	}
}

func parse(data []byte) (*workflow, error) {
	var w workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(w.Jobs) == 0 {
		return nil, errors.New("no jobs")
	}
	return &w, nil
}

// CheckPipefail reports whether a workflow runs every step with pipefail:
// a top-level defaults.run.shell of bash (GitHub then runs bash --noprofile
// --norc -eo pipefail {0}; without it, bash -e {0}), and no job or step
// that sets another shell.
func CheckPipefail(data []byte) error {
	w, err := parse(data)
	if err != nil {
		return err
	}
	var errs []error
	if w.Defaults.Run.Shell != "bash" {
		errs = append(errs, fmt.Errorf("top-level defaults.run.shell is %q, want bash", w.Defaults.Run.Shell))
	}
	for _, id := range sortedKeys(w.Jobs) {
		j := w.Jobs[id]
		if s := j.Defaults.Run.Shell; s != "" && s != "bash" {
			errs = append(errs, fmt.Errorf("job %s: defaults.run.shell is %q, want bash or unset", id, s))
		}
		for i, s := range j.Steps {
			if s.Shell != "" && s.Shell != "bash" {
				errs = append(errs, fmt.Errorf("job %s step %d (%s): shell is %q, want bash or unset", id, i+1, s.Name, s.Shell))
			}
		}
	}
	return errors.Join(errs...)
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}
