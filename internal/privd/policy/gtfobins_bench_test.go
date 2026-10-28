//go:build linux

package policy_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

// Benchmarks for the cost of a privileged policy load (check-policy runs
// the same load) with the binary identity scan over the real system
// binary directories: the example policy, and one with many commands
// (handoff N-33). They load the real, root-owned system binaries of the
// machine that runs them.

func benchOpts() *policy.LoadOptions {
	ids := map[string]uint32{"root": 0, "example-app": 1001, "svc-shell-priv": 60124}
	lookup := func(n string) (uint32, error) {
		if id, ok := ids[n]; ok {
			return id, nil
		}
		return 0, errors.New("unknown")
	}
	return &policy.LoadOptions{
		Trust: gatetest.Trust(), HelperExecutable: "/usr/local/libexec/shell-mcp-privd",
		LookupUser: lookup, LookupGroup: lookup, UserName: func(uint32) string { return "" },
	}
}

func BenchmarkLoadExamplePolicy(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "privileged", "privileged.yaml"))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := policy.Parse(data, "/etc/shell-mcp/privileged.yaml", benchOpts()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadManyCommands(b *testing.B) {
	ents, err := os.ReadDir("/usr/bin")
	if err != nil {
		b.Skip("no /usr/bin")
	}
	var sb strings.Builder
	sb.WriteString(head + "commands:\n")
	count := 0
	for _, e := range ents {
		if count == 250 {
			break
		}
		one := fmt.Sprintf("  - id: c-%d\n    path: %s\n    tier: operator\n    acknowledge: \"invented review note\"\n    templates: [[\"--version\"]]\n", count, "/usr/bin/"+e.Name())
		if _, err := policy.Parse([]byte(head+"commands:\n"+one), "/etc/shell-mcp/privileged.yaml", benchOpts()); err != nil {
			continue
		}
		sb.WriteString(one)
		count++
	}
	if count < 150 {
		b.Skipf("only %d loadable commands", count)
	}
	b.Logf("%d commands", count)
	data := []byte(sb.String())
	for b.Loop() {
		if _, err := policy.Parse(data, "/etc/shell-mcp/privileged.yaml", benchOpts()); err != nil {
			b.Fatal(err)
		}
	}
}
