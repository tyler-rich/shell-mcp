//go:build linux

package policy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// Benchmarks for the cost of a policy load (check-policy runs the same
// load) with the binary identity scan over the real system binary
// directories: the example policies, and one policy with many commands
// (handoff N-33 measures the identity scan's added cost). They load the
// real, root-owned system binaries of the machine that runs them.

func benchOpts() *policy.LoadOptions {
	return &policy.LoadOptions{Trust: gatetest.Trust(), GateExecutable: "/usr/local/bin/shell-mcp-gate", ServiceHome: "/home/svc-shell"}
}

func BenchmarkLoadExamplePolicies(b *testing.B) {
	dir := filepath.Join("..", "..", "..", "examples", "policies")
	for _, name := range []string{"read-only.yaml", "operator.yaml", "admin.yaml"} {
		data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: this repository's example files
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := policy.Parse(data, "/etc/shell-mcp/"+name, benchOpts()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// manyCommands returns a policy with up to n commands, one per real
// executable of /usr/bin that a policy accepts.
func manyCommands(b *testing.B, n int) []byte {
	b.Helper()
	ents, err := os.ReadDir("/usr/bin")
	if err != nil {
		b.Skip("no /usr/bin")
	}
	var sb strings.Builder
	sb.WriteString("version: 1\nmax_tier: read\ncommands:\n")
	count := 0
	for _, e := range ents {
		if count == n {
			break
		}
		p := "/usr/bin/"+e.Name()
		one := fmt.Sprintf("  - id: c-%d\n    path: %s\n    tier: read\n    templates: [[\"--version\"]]\n", count, p)
		if _, err := policy.Parse([]byte("version: 1\nmax_tier: read\ncommands:\n"+one), "/etc/shell-mcp/p.yaml", benchOpts()); err != nil {
			continue
		}
		sb.WriteString(one)
		count++
	}
	if count < n/2 {
		b.Skipf("only %d loadable commands", count)
	}
	b.Logf("%d commands", count)
	return []byte(sb.String())
}

func BenchmarkLoadManyCommands(b *testing.B) {
	data := manyCommands(b, 250)
	for b.Loop() {
		if _, err := policy.Parse(data, "/etc/shell-mcp/p.yaml", benchOpts()); err != nil {
			b.Fatal(err)
		}
	}
}
