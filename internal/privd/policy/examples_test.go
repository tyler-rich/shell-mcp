//go:build linux

package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// TestExamplePrivilegedPolicy loads and validates the example privileged
// policy exactly as the helper would, with the test constructor for
// ownership (the checkout is not root-owned) and invented user and group
// databases; the command binaries and apt-get it names are the real,
// root-owned system binaries. Both unit pairs are generated from it. The
// example uses placeholders only.
func TestExamplePrivilegedPolicy(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "privileged", "privileged.yaml")
	data, err := os.ReadFile(path) //nolint:gosec // G304: this repository's example file
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]uint32{"root": 0, "example-app": 1001, "svc-shell-priv": 60124}
	lookup := func(n string) (uint32, error) {
		if id, ok := ids[n]; ok {
			return id, nil
		}
		return 0, errors.New("unknown")
	}
	p, err := policy.Parse(data, "/etc/shell-mcp/privileged.yaml", &policy.LoadOptions{
		Trust: gatetest.Trust(), HelperExecutable: "/usr/local/libexec/shell-mcp-privd",
		LookupUser: lookup, LookupGroup: lookup, UserName: func(uint32) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientUID != 60123 || p.MaxTier != policy.TierDestructive || !p.Packages.Enabled || !slices.Equal(p.Power.Allowed, []string{"reboot"}) ||
		len(p.Paths.Persistence) != 1 || !p.UsesBroad() {
		t.Fatalf("example: %+v", p)
	}
	var core, broad int
	for _, c := range p.Commands {
		if c.Unit == policy.UnitBroad {
			broad++
		} else {
			core++
		}
	}
	if core == 0 || broad == 0 {
		t.Fatalf("the example needs core and broad commands: %d core, %d broad", core, broad)
	}
	for _, r := range append(slices.Clone(p.Paths.Read), p.Paths.WriteRoots()...) {
		if !strings.Contains(r, "example-app") {
			t.Errorf("non-placeholder root %s", r)
		}
	}
	kinds := map[string]bool{}
	for _, fd := range p.Acknowledged {
		kinds[fd.Kind] = true
	}
	for _, k := range []string{"persistence", "root-equivalent", "power"} {
		if !kinds[k] {
			t.Errorf("check-policy findings lack %s", k)
		}
	}
	if _, err := units.Core(p); err != nil {
		t.Fatalf("core units: %v", err)
	}
	if _, err := units.Broad(p); err != nil {
		t.Fatalf("broad units: %v", err)
	}
}
