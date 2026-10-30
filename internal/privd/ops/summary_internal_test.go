//go:build linux

package ops

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// TestSummaryMatchesEnforcementOnExamples (property, handoff P-8): for the
// example privileged policy, and for variants of it under every max_tier
// and package and power switch, the summary lists exactly the operations
// the helper's own checks let through (the tier check every operation
// passes first, the unit, and the package and power operations' policy
// checks), and states every command and template exactly as
// priv_exec_preview's resolution reports it.
func TestSummaryMatchesEnforcementOnExamples(t *testing.T) {
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
	load := func() *policy.Policy {
		p, err := policy.Parse(data, "/etc/shell-mcp/privileged.yaml", &policy.LoadOptions{
			Trust: gatetest.Trust(), HelperExecutable: "/usr/local/libexec/shell-mcp-privd",
			LookupUser: lookup, LookupGroup: lookup, UserName: func(uint32) string { return "" },
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	type variant struct {
		name string
		edit func(*policy.Policy)
	}
	variants := []variant{{"as written", func(*policy.Policy) {}}}
	for _, tier := range []policy.Tier{policy.TierRead, policy.TierOperator, policy.TierDestructive} {
		variants = append(variants,
			variant{"max_tier " + tier.String(), func(p *policy.Policy) { p.MaxTier = tier }},
			variant{"no packages, " + tier.String(), func(p *policy.Policy) { p.MaxTier, p.Packages.Enabled = tier, false }},
			variant{"upgrade, no index, " + tier.String(), func(p *policy.Policy) {
				p.MaxTier, p.Packages.AllowUpgrade, p.Packages.AllowUpdateIndex = tier, true, false
			}},
			variant{"short limit, " + tier.String(), func(p *policy.Policy) { p.MaxTier, p.Limits.MaxTimeoutS = tier, 30 }},
			variant{"no broad unit, " + tier.String(), func(p *policy.Policy) {
				p.MaxTier, p.Packages.Enabled, p.Power = tier, false, policy.Power{}
				p.Commands = slices.DeleteFunc(p.Commands, func(c policy.Command) bool { return c.Unit == policy.UnitBroad })
			}},
		)
	}
	pkgOps := map[string]pkg.Op{
		protocol.OpPrivPkgUpdateIndex: pkg.OpUpdate, protocol.OpPrivPkgUpdateIndexPreview: pkg.OpUpdate,
		protocol.OpPrivPkgInstall: pkg.OpInstall, protocol.OpPrivPkgInstallPreview: pkg.OpInstall,
		protocol.OpPrivPkgUpgrade: pkg.OpUpgrade, protocol.OpPrivPkgUpgradePreview: pkg.OpUpgrade,
		protocol.OpPrivPkgRemove: pkg.OpRemove, protocol.OpPrivPkgRemovePreview: pkg.OpRemove,
		protocol.OpPrivPkgRecover: pkg.OpRecover, protocol.OpPrivPkgRecoverPreview: pkg.OpRecover,
		protocol.OpPrivPkgReinstall: pkg.OpReinstall, protocol.OpPrivPkgReinstallPreview: pkg.OpReinstall,
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			p := load()
			v.edit(p)
			s := &server{o: &Options{}, p: p, unit: policy.UnitCore, req: &protocol.Request{Ceiling: "destructive"}}
			sum := s.summary()
			listed := map[string]summaryOp{}
			for _, o := range sum.Ops {
				if _, dup := listed[o.Op]; dup {
					t.Fatalf("%s listed twice", o.Op)
				}
				listed[o.Op] = o
			}
			for op, spec := range opTable() {
				want := s.within("operation", spec.tier) == nil
				unit := policy.UnitCore
				if slices.Contains(broadOps, op) {
					unit = policy.UnitBroad
					want = want && p.UsesBroad()
				}
				if po, ok := pkgOps[op]; ok {
					want = want && s.pkgAllowed(po, nil) == nil
				}
				if op == protocol.OpPrivPower || op == protocol.OpPrivPowerPreview {
					want = want && slices.ContainsFunc(policy.PowerActions, func(a string) bool { return s.powerAllowed(a) == nil })
				}
				got, ok := listed[op]
				if ok != want {
					t.Errorf("%s: listed %v, the helper's checks allow it %v", op, ok, want)
				}
				if ok && (got.Tier != spec.tier.String() || got.Unit != string(unit)) {
					t.Errorf("%s: listed %+v, enforced at %s in the %s unit", op, got, spec.tier, unit)
				}
			}
			exec := slices.ContainsFunc(p.Commands, func(c policy.Command) bool { return s.within("command", c.Tier) == nil })
			if _, ok := listed[protocol.OpPrivExec]; ok != exec {
				t.Errorf("priv_exec listed %v, a command within max_tier %v", ok, exec)
			}
			if len(sum.Commands) != len(p.Commands) {
				t.Fatalf("summary has %d commands, policy %d", len(sum.Commands), len(p.Commands))
			}
			for i := range p.Commands {
				c := &p.Commands[i]
				sc := sum.Commands[i]
				if sc.ID != c.ID || len(sc.Templates) != len(c.Templates) {
					t.Fatalf("command %d: %+v for %s", i, sc, c.ID)
				}
				for j := range c.Templates {
					pv := (&resolvedExec{c: c, template: j}).preview(p.SHA256)
					if pv.Tier != sc.Tier || pv.Unit != sc.Unit || pv.Description != sc.Description || pv.RootEquivalent != sc.RootEquivalent ||
						!slices.Equal(pv.Capabilities, sc.Capabilities) || !slices.Equal(pv.Template, sc.Templates[j]) || pv.PolicySHA256 != sum.PolicySHA256 {
						t.Errorf("%s template %d: preview %+v, summary %+v", c.ID, j, pv, sc)
					}
				}
			}
		})
	}
}
