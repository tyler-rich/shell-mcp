//go:build linux

// Package policy loads the privileged helper's policy strictly
// (docs/PRIVILEGED.md §4): unknown keys, wrong types and duplicate keys are
// errors; the never list (§5.3 list A) is rejected wherever it appears; the
// acknowledge list (list B) is accepted only with a non-empty acknowledge;
// owners must exist; the mode mask never includes setuid, setgid or sticky
// bits; commands resolve and are checked exactly as the gate's (POLICY §4,
// §5); and the unit-level capability set is derived from the commands.
//
// The helper and its `check-policy` and `units` commands load the policy
// through Load, so a policy that the helper would refuse is never turned
// into units.
package policy

import (
	"os"
	"slices"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// SchemaVersion is the privileged policy schema version this helper
// implements.
const SchemaVersion = 1

// MaxPolicyBytes bounds the policy file.
const MaxPolicyBytes = 1 << 20

// Tier is the gate's tier type (read < operator < destructive).
type Tier = gpolicy.Tier

// Tiers.
const (
	TierRead        = gpolicy.TierRead
	TierOperator    = gpolicy.TierOperator
	TierDestructive = gpolicy.TierDestructive
)

// LandlockMode is sandbox.landlock.
type LandlockMode = gpolicy.LandlockMode

// Landlock modes.
const (
	LandlockRequired   = gpolicy.LandlockRequired
	LandlockBestEffort = gpolicy.LandlockBestEffort
)

// Unit names the systemd unit a command runs under (PRIVILEGED §5).
type Unit string

// Units.
const (
	UnitCore  Unit = "core"
	UnitBroad Unit = "broad"
)

// BaseCapabilities is the core unit's capability bounding set before
// declared additions (PRIVILEGED §5.1).
var BaseCapabilities = []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER"}

// Policy is a validated privileged policy.
type Policy struct {
	ClientUID   uint32
	SocketGroup string
	SocketGID   uint32
	MaxTier     Tier
	Landlock    LandlockMode
	Limits      Limits
	Paths       Paths
	Owners      Owners
	// ModesMax is the mask no requested mode may exceed.
	ModesMax    os.FileMode
	BackupsKeep int
	Commands    []Command
	Packages    Packages
	Power       Power
	// Capabilities is the core unit's bounding set: BaseCapabilities plus
	// every capability a core-unit command declares, sorted by number.
	Capabilities []string
	// SHA256 is the lowercase hex SHA-256 of the policy file bytes.
	SHA256 string
	// File is the policy path the helper was given (ExecStart= uses it).
	File string
	// Warnings are non-fatal findings for check-policy.
	Warnings []string
	// Acknowledged lists every list B item and its acknowledge string, and
	// every root-equivalent or capability-extending declaration, for
	// check-policy.
	Acknowledged []Finding
}

// Limits is the limits section, with defaults applied.
type Limits struct {
	MaxReadBytes     int
	MaxWriteBytes    int
	MaxOutputBytes   int
	DefaultTimeoutS  int
	MaxTimeoutS      int
	MaxDeleteEntries int
}

// Paths holds the roots and the matchers the helper's fsx uses.
type Paths struct {
	Read        []string
	Write       []string
	Persistence []Persistence
	DenyUser    []string
	// Deny is the built-in read deny list plus paths.deny.
	Deny *pathx.Matcher
	// Protected is what no helper write may touch: the never list, the
	// helper and gate binaries, and every .git (PRIVILEGED §5.3, POLICY §3).
	Protected *pathx.Matcher
}

// Persistence is one paths.persistence entry.
type Persistence struct {
	Path        string
	Acknowledge string
}

// WriteRoots returns paths.write followed by the persistence roots: every
// directory the helper may write, and the core unit's ReadWritePaths=
// (with the backup directory).
func (p *Paths) WriteRoots() []string {
	out := append([]string(nil), p.Write...)
	for _, e := range p.Persistence {
		out = append(out, e.Path)
	}
	return out
}

// Owners are the users and groups chown may set, resolved at load.
type Owners struct {
	Users  []NamedID
	Groups []NamedID
}

// NamedID is a user or group name with its id.
type NamedID struct {
	Name string
	ID   uint32
}

// Command is one declared root command.
type Command struct {
	ID             string
	Path           string // as written
	Resolved       string // after EvalSymlinks; the execve path and argv[0]
	Tier           Tier
	Description    string
	Unit           Unit
	RootEquivalent bool
	Capabilities   []string
	Acknowledge    string
	// ListB is the POLICY §5 group (11–13) the binary belongs to, or 0.
	ListB     int
	Templates []template.Template
}

// Packages is the packages section (the apt operations, broad unit).
type Packages struct {
	Enabled bool
	// AptGet is the resolved apt-get binary (set when Enabled).
	AptGet           string
	Manager          string
	Install          []string
	Remove           []string
	AllowUpdateIndex bool
	AllowUpgrade     bool
}

// Power is the power section (the built-in priv_power operation).
type Power struct {
	Allowed     []string // reboot | poweroff
	Acknowledge string
}

// UsesBroad reports whether the policy uses the broad unit (PRIVILEGED §5.2):
// packages enabled, a command declared unit: broad, or power. Only then is
// the broad unit generated.
func (p *Policy) UsesBroad() bool {
	if p.Packages.Enabled || len(p.Power.Allowed) > 0 {
		return true
	}
	return slices.ContainsFunc(p.Commands, func(c Command) bool { return c.Unit == UnitBroad })
}

// BroadProtectClock reports whether the broad unit keeps ProtectClock=yes:
// it does unless a broad-unit command declares CAP_SYS_TIME, the only
// directive a capability may relax there (PRIVILEGED §5.2).
func (p *Policy) BroadProtectClock() bool {
	return !slices.ContainsFunc(p.Commands, func(c Command) bool {
		return c.Unit == UnitBroad && slices.Contains(c.Capabilities, "CAP_SYS_TIME")
	})
}

// Finding is one item check-policy reports for review.
type Finding struct {
	Kind   string // list-b-binary | persistence | capability | root-equivalent
	Item   string
	Detail string
}

// Command returns the command with the given id.
func (p *Policy) Command(id string) (*Command, bool) {
	for i := range p.Commands {
		if p.Commands[i].ID == id {
			return &p.Commands[i], true
		}
	}
	return nil, false
}

// Error is a policy validation failure. Field names the offending key; the
// message may name host paths and is for local display (check-policy), not
// for the wire.
type Error struct {
	Field string
	Msg   string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return "privileged policy: " + e.Msg
	}
	return "privileged policy: " + e.Field + ": " + e.Msg
}

// LoadOptions carries the facts about this host that validation needs.
type LoadOptions struct {
	// Trust decides who may own the policy, its directories and command
	// binaries. Production uses gate policy RootTrust().
	Trust gpolicy.Trust
	// HelperExecutable is the resolved path of the running helper binary;
	// it joins the never list.
	HelperExecutable string
	// AptGet is the apt-get binary package operations run (production:
	// /usr/bin/apt-get); it is resolved and ownership-checked when packages
	// are enabled.
	AptGet string
	// SystemBinDirs are the directories the binary identity check scans;
	// nil means the gate's defaults. Tests set their own.
	SystemBinDirs []string
	// LookupUser and LookupGroup resolve names to ids, and UserName an id
	// to a name ("" when unknown). Production reads the local user and
	// group databases (ProductionLookups).
	LookupUser  func(name string) (uint32, error)
	LookupGroup func(name string) (uint32, error)
	UserName    func(uid uint32) string
}
