package runner

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestCheckEnv(t *testing.T) {
	ok := map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
	if err := CheckEnv("linux", env(ok)); err != nil {
		t.Fatalf("a GitHub-hosted Linux runner was refused: %v", err)
	}
	cases := map[string]struct {
		goos string
		env  map[string]string
	}{
		"nothing set":           {"linux", map[string]string{}},
		"not Linux":             {"windows", ok},
		"darwin":                {"darwin", ok},
		"no GITHUB_ACTIONS":     {"linux", map[string]string{"RUNNER_ENVIRONMENT": "github-hosted"}},
		"GITHUB_ACTIONS=1":      {"linux", map[string]string{"GITHUB_ACTIONS": "1", "RUNNER_ENVIRONMENT": "github-hosted"}},
		"GITHUB_ACTIONS=TRUE":   {"linux", map[string]string{"GITHUB_ACTIONS": "TRUE", "RUNNER_ENVIRONMENT": "github-hosted"}},
		"self-hosted":           {"linux", map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}},
		"no RUNNER_ENVIRONMENT": {"linux", map[string]string{"GITHUB_ACTIONS": "true"}},
		"padded":                {"linux", map[string]string{"GITHUB_ACTIONS": "true ", "RUNNER_ENVIRONMENT": " github-hosted"}},
		"github-hosted-ish":     {"linux", map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted-not"}},
	}
	for name, c := range cases {
		err := CheckEnv(c.goos, env(c.env))
		if err == nil {
			t.Fatalf("%s: not refused", name)
		}
		if !strings.Contains(err.Error(), "GitHub-hosted") || strings.Contains(err.Error(), "\n") {
			t.Fatalf("%s: message %q", name, err)
		}
	}
}
