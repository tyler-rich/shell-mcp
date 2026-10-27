//go:build linux

// Package gen writes the helper's generated units for privileged policies,
// for the offline exposure check (scripts/exposure/run.sh). It is a test so
// that the test trust set it needs stays out of every non-test file (the
// rule of internal/gate/policy's TestForTestingOnlyInTests). It does nothing
// under a plain `go test ./...`: gen.sh runs it with EXPOSURE_OUT and
// EXPOSURE_POLICIES set.
//
// For each policy file, <out>/<name>/shell-mcp-privd@.service (the core
// unit) and, when the policy uses it, shell-mcp-privd-broad@.service. The
// policies are loaded and validated as the helper loads them, with invented
// user and group databases, so the command binaries a policy names must
// exist where this runs.
package gen

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/units"
)

// policyFile is the path the units name, as in the golden files.
const policyFile = "/etc/shell-mcp/privileged.yaml"

// ids are the invented identities the example and end-to-end policies use.
var ids = map[string]uint32{
	"root": 0, "svc-shell": 4200001, "svc-shell-priv": 4200002, "svc-other": 4200003, "example-app": 4200004,
}

func lookup(n string) (uint32, error) {
	if id, ok := ids[n]; ok {
		return id, nil
	}
	return 0, errors.New("unknown")
}

func TestGenerateUnits(t *testing.T) {
	out, list := os.Getenv("EXPOSURE_OUT"), os.Getenv("EXPOSURE_POLICIES")
	if out == "" || list == "" {
		t.Skip("EXPOSURE_OUT and EXPOSURE_POLICIES are set by scripts/exposure/gen.sh")
	}
	for _, f := range strings.Split(list, ":") {
		data, err := os.ReadFile(f) //nolint:gosec // G304: policy files named by the script that runs this
		if err != nil {
			t.Fatal(err)
		}
		p, err := policy.Parse(data, policyFile, &policy.LoadOptions{
			Trust: gatetest.Trust(), HelperExecutable: units.HelperPath,
			LookupUser: lookup, LookupGroup: lookup, UserName: func(uint32) string { return "" },
		})
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		dir := filepath.Join(out, name)
		if err = os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // G703: the script's own private working directory
			t.Fatal(err)
		}
		core, err := units.Core(p)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err = os.WriteFile(filepath.Join(dir, units.ServiceUnit), []byte(core.Service), 0o600); err != nil { //nolint:gosec // G703: as above
			t.Fatal(err)
		}
		if p.UsesBroad() {
			b, err := units.Broad(p)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if err = os.WriteFile(filepath.Join(dir, units.BroadServiceUnit), []byte(b.Service), 0o600); err != nil { //nolint:gosec // G703: as above
				t.Fatal(err)
			}
		}
		home, _ := units.ProtectHome(p)
		t.Logf("%s: core unit ProtectHome=%s", name, home)
	}
}
