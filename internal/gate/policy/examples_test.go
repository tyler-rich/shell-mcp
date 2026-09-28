//go:build linux

package policy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// TestExamplePolicies loads and validates every example gate policy with
// the test constructor for ownership (the repository checkout is not
// root-owned); the command binaries they name are the real, root-owned
// system binaries. The examples use placeholders only.
func TestExamplePolicies(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "examples", "policies")
	want := map[string]policy.Tier{"read-only.yaml": policy.TierRead, "operator.yaml": policy.TierOperator, "admin.yaml": policy.TierDestructive}
	placeholder := regexp.MustCompile(`https://[^\s"']+`)
	for name, tier := range want {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: this repository's example files
			if err != nil {
				t.Fatal(err)
			}
			p, err := policy.Parse(data, "/etc/shell-mcp/"+name, policy.LoadOptions{
				Trust: gatetest.Trust(), GateExecutable: "/usr/local/bin/shell-mcp-gate", ServiceHome: "/home/svc-shell",
			})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if p.MaxTier != tier || len(p.Commands) == 0 || len(p.Git.Repos) == 0 {
				t.Fatalf("%s: %+v", name, p)
			}
			if tier >= policy.TierOperator && len(p.Services.ControlUnits) == 0 {
				t.Fatalf("%s: no service control", name)
			}
			for _, u := range placeholder.FindAllString(string(data), -1) {
				if !strings.HasPrefix(u, "https://git.example.test/") {
					t.Errorf("%s: non-placeholder URL %s", name, u)
				}
			}
			for _, r := range append(append([]string(nil), p.Paths.Read...), p.Paths.Write...) {
				if !strings.HasPrefix(r, "/srv/app") && !strings.HasPrefix(r, "/etc/example-app") && !strings.HasPrefix(r, "/var/log/example-app") {
					t.Errorf("%s: non-placeholder root %s", name, r)
				}
			}
		})
	}
}
