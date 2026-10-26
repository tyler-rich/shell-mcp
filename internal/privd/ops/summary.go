//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"

	"github.com/tyler-rich/shell-mcp/internal/privd/pkg"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// summaryData is priv_policy's result (handoff P-8, S4c-9): the privileged
// policy as this instance enforces it, built from the policy it loaded,
// never from the file's bytes. It never carries paths.deny values (only
// their count) or any acknowledge text, nor the command binaries' paths,
// client_uid or socket_group.
type summaryData struct {
	PolicySHA256         string           `json:"policy_sha256"`
	MaxTier              string           `json:"max_tier"`
	Limits               summaryLimits    `json:"limits"`
	Roots                summaryRoots     `json:"roots"`
	DenyPatterns         int              `json:"deny_patterns"`
	Owners               summaryOwners    `json:"owners"`
	ModesMax             string           `json:"modes_max"`
	BackupsKeep          int              `json:"backups_keep"`
	BackupsMaxStoreBytes int64            `json:"backups_max_store_bytes"`
	Commands             []summaryCommand `json:"commands"`
	Packages             summaryPackages  `json:"packages"`
	Power                summaryPower     `json:"power"`
	Ops                  []summaryOp      `json:"ops"`
	Findings             []summaryFinding `json:"findings"`
}

type summaryLimits struct {
	MaxReadBytes     int `json:"max_read_bytes"`
	MaxWriteBytes    int `json:"max_write_bytes"`
	MaxOutputBytes   int `json:"max_output_bytes"`
	DefaultTimeoutS  int `json:"default_timeout_s"`
	MaxTimeoutS      int `json:"max_timeout_s"`
	MaxDeleteEntries int `json:"max_delete_entries"`
	MaxMemoryMB      int `json:"max_memory_mb"`
}

type summaryRoots struct {
	Read        []string `json:"read"`
	Write       []string `json:"write"`
	Persistence []string `json:"persistence"`
}

type summaryOwners struct {
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
}

type summaryCommand struct {
	ID             string     `json:"id"`
	Tier           string     `json:"tier"`
	Unit           string     `json:"unit"`
	Description    string     `json:"description"`
	Templates      [][]string `json:"templates"`
	RootEquivalent bool       `json:"root_equivalent"`
	Capabilities   []string   `json:"capabilities"`
}

type summaryPackages struct {
	Enabled          bool     `json:"enabled"`
	Install          []string `json:"install"`
	Remove           []string `json:"remove"`
	AllowUpdateIndex bool     `json:"allow_update_index"`
	AllowUpgrade     bool     `json:"allow_upgrade"`
}

type summaryPower struct {
	Allowed []string `json:"allowed"`
}

// summaryOp is an operation the policy allows. priv_exec's tier and unit
// are each command's ("command").
type summaryOp struct {
	Op   string `json:"op"`
	Tier string `json:"tier"`
	Unit string `json:"unit"`
}

type summaryFinding struct {
	CommandID string `json:"command_id"`
	Category  string `json:"category"`
	Program   string `json:"program"`
	Match     string `json:"match"`
}

// perCommand is priv_exec's tier and unit in the summary.
const perCommand = "command"

// pkgOpOf maps the package operations and their previews to what
// pkgAllowed checks.
var pkgOpOf = map[string]pkg.Op{
	protocol.OpPrivPkgUpdateIndex: pkg.OpUpdate, protocol.OpPrivPkgUpdateIndexPreview: pkg.OpUpdate,
	protocol.OpPrivPkgInstall: pkg.OpInstall, protocol.OpPrivPkgInstallPreview: pkg.OpInstall,
	protocol.OpPrivPkgUpgrade: pkg.OpUpgrade, protocol.OpPrivPkgUpgradePreview: pkg.OpUpgrade,
	protocol.OpPrivPkgRemove: pkg.OpRemove, protocol.OpPrivPkgRemovePreview: pkg.OpRemove,
}

// allowed reports whether the policy lets op through at all, by the checks
// the operations themselves make: its tier within max_tier (the request's
// ceiling aside, which is the caller's), a broad operation only where the
// policy uses the broad unit (otherwise no broad instance exists, and a
// core one refuses it), the package operations' policy switches
// (pkgAllowed) and the power operations' (powerAllowed, for some action).
func (s *server) allowed(op string, tier policy.Tier) bool {
	if tier > s.p.MaxTier {
		return false
	}
	if slices.Contains(broadOps, op) && !s.p.UsesBroad() {
		return false
	}
	if po, ok := pkgOpOf[op]; ok {
		return s.pkgAllowed(po, nil) == nil
	}
	if op == protocol.OpPrivPower || op == protocol.OpPrivPowerPreview {
		return slices.ContainsFunc(policy.PowerActions, func(a string) bool { return s.powerAllowed(a) == nil })
	}
	return true
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return slices.Clone(s)
}

// summary builds the summary from the policy this instance enforces.
func (s *server) summary() summaryData {
	p := s.p
	d := summaryData{
		PolicySHA256: p.SHA256, MaxTier: p.MaxTier.String(),
		Limits: summaryLimits{
			MaxReadBytes: p.Limits.MaxReadBytes, MaxWriteBytes: p.Limits.MaxWriteBytes, MaxOutputBytes: p.Limits.MaxOutputBytes,
			DefaultTimeoutS: p.Limits.DefaultTimeoutS, MaxTimeoutS: p.Limits.MaxTimeoutS, MaxDeleteEntries: p.Limits.MaxDeleteEntries,
			MaxMemoryMB: p.Limits.MaxMemoryMB,
		},
		Roots:        summaryRoots{Read: orEmpty(p.Paths.Read), Write: orEmpty(p.Paths.Write), Persistence: []string{}},
		DenyPatterns: len(p.Paths.DenyUser),
		Owners:       summaryOwners{Users: []string{}, Groups: []string{}},
		ModesMax:     fmt.Sprintf("%04o", uint32(p.ModesMax)),
		BackupsKeep:  p.BackupsKeep, BackupsMaxStoreBytes: p.BackupsMaxStoreBytes,
		Commands: []summaryCommand{},
		Packages: summaryPackages{Enabled: p.Packages.Enabled, Install: orEmpty(p.Packages.Install), Remove: orEmpty(p.Packages.Remove),
			AllowUpdateIndex: p.Packages.AllowUpdateIndex, AllowUpgrade: p.Packages.AllowUpgrade},
		Power:    summaryPower{Allowed: orEmpty(p.Power.Allowed)},
		Ops:      []summaryOp{},
		Findings: []summaryFinding{},
	}
	for _, e := range p.Paths.Persistence {
		d.Roots.Persistence = append(d.Roots.Persistence, e.Path)
	}
	for _, u := range p.Owners.Users {
		d.Owners.Users = append(d.Owners.Users, u.Name)
	}
	for _, g := range p.Owners.Groups {
		d.Owners.Groups = append(d.Owners.Groups, g.Name)
	}
	execOK := false
	for i := range p.Commands {
		c := &p.Commands[i]
		sc := summaryCommand{ID: c.ID, Tier: c.Tier.String(), Unit: string(c.Unit), Description: c.Description, Templates: [][]string{},
			RootEquivalent: c.RootEquivalent, Capabilities: orEmpty(c.Capabilities)}
		for _, t := range c.Templates {
			sc.Templates = append(sc.Templates, t.String())
		}
		d.Commands = append(d.Commands, sc)
		for _, fd := range c.Findings {
			d.Findings = append(d.Findings, summaryFinding{CommandID: c.ID, Category: fd.Category, Program: fd.Program, Match: fd.Match})
		}
		execOK = execOK || c.Tier <= p.MaxTier
	}
	table := opTable()
	for _, op := range protocol.PrivOps {
		if op == protocol.OpPrivExec {
			if execOK {
				d.Ops = append(d.Ops, summaryOp{Op: op, Tier: perCommand, Unit: perCommand})
			}
			continue
		}
		spec, ok := table[op]
		if !ok || !s.allowed(op, spec.tier) {
			continue
		}
		unit := policy.UnitCore
		if slices.Contains(broadOps, op) {
			unit = policy.UnitBroad
		}
		d.Ops = append(d.Ops, summaryOp{Op: op, Tier: spec.tier.String(), Unit: string(unit)})
	}
	return d
}

// policySummary is priv_policy (handoff P-8): read tier, core unit, no
// arguments. An authenticated gate may read it; what it leaves out never
// reaches the wire (PRIVILEGED §6).
func (s *server) policySummary(raw jsontext.Value) (data any, warns []string, failure error) {
	if err := decode(raw, &noArgs{}); err != nil {
		return nil, nil, err
	}
	return s.summary(), nil, nil
}
