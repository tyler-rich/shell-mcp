//go:build linux

// Command gen writes the helper's generated units for privileged policies,
// for the offline exposure check (scripts/exposure/run.sh): for each policy
// file, <out>/<name>/shell-mcp-privd@.service (the core unit) and, when the
// policy uses it, shell-mcp-privd-broad@.service. The policies are loaded
// and validated as the helper loads them, with the test trust set (the
// files here are not root-owned) and invented user and group databases, so
// the command binaries a policy names must exist where this runs. It is a
// CI and ci-local tool, not part of any binary.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gen <out dir> <policy.yaml>...")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(out string, files []string) error {
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // G304: policy files named on the command line
		if err != nil {
			return err
		}
		p, err := policy.Parse(data, policyFile, &policy.LoadOptions{
			Trust: gatetest.Trust(), HelperExecutable: units.HelperPath,
			LookupUser: lookup, LookupGroup: lookup, UserName: func(uint32) string { return "" },
		})
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		dir := filepath.Join(out, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		core, err := units.Core(p)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := os.WriteFile(filepath.Join(dir, units.ServiceUnit), []byte(core.Service), 0o600); err != nil {
			return err
		}
		if p.UsesBroad() {
			b, err := units.Broad(p)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			if err := os.WriteFile(filepath.Join(dir, units.BroadServiceUnit), []byte(b.Service), 0o600); err != nil {
				return err
			}
		}
		home, _ := units.ProtectHome(p)
		fmt.Fprintf(os.Stderr, "gen: %s: core unit ProtectHome=%s\n", name, home)
	}
	return nil
}
