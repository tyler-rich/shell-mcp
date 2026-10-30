package tools

import (
	"context"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The package tools (docs/TOOLS.md, privileged tier: packages; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-7: D5, D9, P-2e, P-3, P-5, P-6, Q7,
// Q9): shell_priv_preview_packages (read) sends the matching
// priv_pkg_*_preview; shell_priv_update_package_index,
// shell_priv_install_packages, shell_priv_upgrade_packages (operator) and
// shell_priv_remove_packages (destructive), admin profile only and always
// approval-gated, use that preview (the simulated transaction with exact
// versions, or for the index update the action) as their approval preview,
// bound with both policies' hashes, and the re-call sends the operation
// with the fresh preview's preview_sha256 (taken before the server's
// redaction). The helper simulates again, pins, runs, and decides the
// result from dpkg's status. The client sends package names only.

const (
	// maxPkgNames is the helper's bound on one install or remove.
	maxPkgNames = 20
	// pkgNamePattern is Debian Policy §5.6.1: lower-case letters, digits,
	// "+", "-" and ".", at least two characters, alphanumeric first.
	pkgNamePattern = `^[a-z0-9][a-z0-9+.-]+$`
	maxPkgName     = 128
)

var pkgNameRE = regexp.MustCompile(pkgNamePattern)

// checkPkgNames: 1..20 Debian package names, without duplicates; for an
// install none ending in "-" and for a removal none ending in "+" (apt-get
// reads those as the other operation).
func checkPkgNames(op string, names []string) *envelope.Error {
	if len(names) == 0 || len(names) > maxPkgNames {
		return invalid("packages must list 1..%d package names", maxPkgNames)
	}
	for i, n := range names {
		switch {
		case len(n) > maxPkgName || !pkgNameRE.MatchString(n):
			return invalid("packages[%d] is not a Debian package name (lower-case letters, digits, +, - and ., at least two characters, alphanumeric first, at most %d bytes)", i, maxPkgName)
		case (op == "install" || op == "reinstall") && strings.HasSuffix(n, "-"), op == "remove" && strings.HasSuffix(n, "+"):
			return invalid("packages[%d] ends in a character apt-get reads as the opposite operation", i)
		case slices.Contains(names[:i], n):
			return invalid("packages[%d] is listed twice", i)
		}
	}
	return nil
}

func boundPkgNames(s *jsonschema.Schema) {
	boundCommon(s)
	if p := s.Properties["packages"]; p != nil {
		p.Type, p.Types = "array", nil
		p.MinItems, p.MaxItems = new(1), new(maxPkgNames)
		p.Items.Pattern, p.Items.MaxLength = pkgNamePattern, new(maxPkgName)
	}
}

type privPkgNamesIn struct {
	targetArg
	Packages []string `json:"packages" jsonschema:"Debian package names (1-20), each on the host's privileged policy's allow-list for this operation. Names only: no versions, options, sources or paths."`
	timeoutArg
	// expectedPreview is set only by an approved call: the preview_sha256
	// of its fresh preview (never an input).
	expectedPreview string
}

type privInstallIn struct{ privPkgNamesIn }

func (in *privInstallIn) validate() *envelope.Error { return checkPkgNames("install", in.Packages) }

type privRemoveIn struct{ privPkgNamesIn }

func (in *privRemoveIn) validate() *envelope.Error { return checkPkgNames("remove", in.Packages) }

type privPkgNoNamesIn struct {
	targetArg
	timeoutArg
	expectedPreview string
}

type privPreviewPackagesIn struct {
	targetArg
	Operation string   `json:"operation" jsonschema:"install, upgrade, remove or reinstall."`
	Packages  []string `json:"packages,omitzero" jsonschema:"Debian package names (1-20) for install, remove and reinstall; none for upgrade."`
}

func (in *privPreviewPackagesIn) validate() *envelope.Error {
	switch in.Operation {
	case "install", "remove", "reinstall":
		return checkPkgNames(in.Operation, in.Packages)
	case "upgrade":
		if in.Packages != nil {
			return invalid("an upgrade takes no packages: it previews every upgrade the host's index offers")
		}
		return nil
	}
	return invalid("operation must be install, upgrade, remove or reinstall")
}

// PackageVersion is a package a transaction installs.
type PackageVersion struct {
	Name    string `json:"name" jsonschema:"Package name (with :arch for a foreign architecture)."`
	Version string `json:"version" jsonschema:"Exact version."`
}

// PackageUpgrade is a package whose version a transaction changes.
type PackageUpgrade struct {
	Name string `json:"name" jsonschema:"Package name (with :arch for a foreign architecture)."`
	From string `json:"from" jsonschema:"Installed version."`
	To   string `json:"to" jsonschema:"Version it changes to."`
}

// PackageRemoval is a package a transaction removes.
type PackageRemoval struct {
	Name    string `json:"name" jsonschema:"Package name (with :arch for a foreign architecture)."`
	Version string `json:"version" jsonschema:"Installed version."`
}

// PackageChanges is a transaction: what a preview would change, or what
// dpkg's status shows an operation changed.
type PackageChanges struct {
	Install []PackageVersion `json:"install" jsonschema:"Packages newly installed, with exact versions."`
	Upgrade []PackageUpgrade `json:"upgrade" jsonschema:"Packages whose version changes."`
	Remove  []PackageRemoval `json:"remove" jsonschema:"Packages removed (configuration files are kept)."`
}

// PackagePreview is shell_priv_preview_packages' data.
type PackagePreview struct {
	Op       string   `json:"op" jsonschema:"install, upgrade, remove or reinstall."`
	Packages []string `json:"packages" jsonschema:"The requested names."`
	PackageChanges
	Unfinished    []UnfinishedPackage `json:"unfinished" jsonschema:"The packages dpkg left unfinished, each with its version and state, for a removal of exactly them; empty when nothing is unfinished."`
	Reinstall     []UnfinishedPackage `json:"reinstall" jsonschema:"For a reinstall: each package to reinstall at the version dpkg names, with its state; empty otherwise."`
	Argv          []string            `json:"argv" jsonschema:"The apt-get arguments simulated."`
	PreviewSHA256 string              `json:"preview_sha256" jsonschema:"SHA-256 over the privileged policy, the requested names, every list with its versions and the argv and, while packages are unfinished, their state; an operation runs only while it is unchanged."`
}

// PackageResult is the install, upgrade and remove tools' data.
type PackageResult struct {
	Op       string         `json:"op" jsonschema:"install, upgrade or remove."`
	Packages []string       `json:"packages" jsonschema:"The requested names."`
	Applied  PackageChanges `json:"applied" jsonschema:"What dpkg's status shows was installed, upgraded and removed: exactly the approved transaction."`
	PackageRun
}

// PackageRun is apt-get's run.
type PackageRun struct {
	ExitCode        *int   `json:"exit_code" jsonschema:"apt-get's exit code (informational: the result is decided by dpkg's status)."`
	Stdout          string `json:"stdout" jsonschema:"apt-get's output, redacted and capped."`
	Stderr          string `json:"stderr" jsonschema:"apt-get's error output, redacted and capped."`
	StdoutTruncated bool   `json:"stdout_truncated" jsonschema:"True when stdout was cut."`
	StderrTruncated bool   `json:"stderr_truncated" jsonschema:"True when stderr was cut."`
	Attempts        int    `json:"attempts" jsonschema:"apt-get runs, more than one after another process held the lock."`
	LockWaitMS      int64  `json:"lock_wait_ms" jsonschema:"How long a held dpkg or package-list lock was waited for."`
	DurationMS      int64  `json:"duration_ms" jsonschema:"Duration of the last run."`
}

// PackageIndexUpdate is shell_priv_update_package_index's data.
type PackageIndexUpdate struct {
	PackageRun
}

// pkgRemovalWire is a removal on the wire; purge is never set by the
// helper (APT::Get::Purge=false), and not shown.
type pkgRemovalWire struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purge   bool   `json:"purge"`
}

// pkgChangesWire is a transaction on the wire (handoff P-5, P-6).
type pkgChangesWire struct {
	Install []PackageVersion `json:"install"`
	Upgrade []PackageUpgrade `json:"upgrade"`
	Remove  []pkgRemovalWire `json:"remove"`
}

func (w *pkgChangesWire) changes() PackageChanges {
	c := PackageChanges{Install: w.Install, Upgrade: w.Upgrade}
	for _, r := range w.Remove {
		c.Remove = append(c.Remove, PackageRemoval{Name: r.Name, Version: r.Version})
	}
	emptyChanges(&c)
	return c
}

type pkgPreviewWire struct {
	Op       string   `json:"op"`
	Packages []string `json:"packages"`
	pkgChangesWire
	Unfinished      []recoverEntryWire `json:"unfinished"`
	Complete        bool               `json:"complete"`
	Argv            []string           `json:"argv"`
	ExitCode        *int               `json:"exit_code"`
	Signal          *string            `json:"signal"`
	Stderr          string             `json:"stderr"`
	StderrTruncated bool               `json:"stderr_truncated"`
	DurationMS      int64              `json:"duration_ms"`
	PolicySHA256    string             `json:"policy_sha256"`
	PreviewSHA256   string             `json:"preview_sha256"`
}

type pkgUpdatePreviewWire struct {
	Argv          []string `json:"argv"`
	PolicySHA256  string   `json:"policy_sha256"`
	PreviewSHA256 string   `json:"preview_sha256"`
}

type pkgResultWire struct {
	Op       string          `json:"op"`
	Packages []string        `json:"packages"`
	Applied  *pkgChangesWire `json:"applied"`
	Signal   *string         `json:"signal"`
	TimedOut bool            `json:"timed_out"`
	PackageRun
}

type pkgNamesWire struct {
	Packages []string `json:"packages"`
}

type pkgBoundWire struct {
	Packages              []string `json:"packages,omitempty"`
	ExpectedPreviewSHA256 string   `json:"expected_preview_sha256"`
}

func emptyChanges(c *PackageChanges) {
	if c.Install == nil {
		c.Install = []PackageVersion{}
	}
	if c.Upgrade == nil {
		c.Upgrade = []PackageUpgrade{}
	}
	if c.Remove == nil {
		c.Remove = []PackageRemoval{}
	}
}

func changesSummary(c *PackageChanges) string {
	return plural(len(c.Install), "install", "installs") + ", " + plural(len(c.Upgrade), "upgrade", "upgrades") + ", " +
		plural(len(c.Remove), "removal", "removals")
}

func pkgAudit(target string, names []string) map[string]any {
	m := map[string]any{"target": target}
	if names != nil {
		m["packages"] = names
	}
	return m
}

func privPreviewPackages(d *Deps) Tool {
	return define(d, spec[privPreviewPackagesIn, PackagePreview]{
		name:        "shell_priv_preview_packages",
		title:       "Preview packages as root",
		description: "Reports, as root, what installing, upgrading or removing packages would change, without changing anything: every package with its exact version, and a hash of the transaction.",
		tier:        TierRead,
		privileged:  true,
		schema: func(s *jsonschema.Schema) {
			boundPkgNames(s)
			enumIn(s, "operation", "install", "upgrade", "remove", "reinstall")
		},
		audit: func(in privPreviewPackagesIn) map[string]any {
			m := pkgAudit(in.Target, in.Packages)
			m["operation"] = in.Operation
			return m
		},
		summary: func(p *PackagePreview) string { return changesSummary(&p.PackageChanges) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privPreviewPackagesIn) envelope.Envelope[PackagePreview] {
			if in.Operation == "reinstall" {
				r := fetch[reinstallPreviewWire](ctx, d, in.Target, protocol.OpPrivPkgReinstallPreview, pkgNamesWire{Packages: in.Packages}, d.budget())
				if !r.OK {
					return envelope.Failure[PackagePreview](r.Target, r.Error)
				}
				x := r.Data
				c := PackageChanges{}
				emptyChanges(&c)
				out := PackagePreview{Op: x.Op, Packages: orNone(x.Packages), PackageChanges: c, Unfinished: []UnfinishedPackage{}, Reinstall: unfinishedOf(x.Reinstall),
					Argv: orNone(x.Argv), PreviewSHA256: x.PreviewSHA256}
				env := envelope.Success(r.Target, out)
				env.Gate, env.Warnings = r.Gate, r.Warnings
				return env
			}
			var args any = noArgsWire{}
			if in.Operation != "upgrade" {
				args = pkgNamesWire{Packages: in.Packages}
			}
			r := fetch[pkgPreviewWire](ctx, d, in.Target, "priv_pkg_"+in.Operation+"_preview", args, d.budget())
			if !r.OK {
				return envelope.Failure[PackagePreview](r.Target, r.Error)
			}
			x := r.Data
			out := PackagePreview{Op: x.Op, Packages: orNone(x.Packages), PackageChanges: x.changes(), Unfinished: unfinishedOf(x.Unfinished), Reinstall: []UnfinishedPackage{},
				Argv: x.Argv, PreviewSHA256: x.PreviewSHA256}
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
	})
}

type noArgsWire struct{}

// pkgSpec is what differs between the gated package tools.
type pkgSpec struct {
	name, title, description, op string
	tier                         Tier
	verb                         string
}

func privInstallPackages(d *Deps) Tool {
	return privPkgNamesTool[privInstallIn](d, &pkgSpec{name: "shell_priv_install_packages", title: "Install packages as root", op: "install", tier: TierOperator, verb: "install",
		description: "Installs, as root, allow-listed packages exactly as their approved preview resolved them, every package at its approved version, never removing any; returns what dpkg shows was installed."})
}

func privRemovePackages(d *Deps) Tool {
	return privPkgNamesTool[privRemoveIn](d, &pkgSpec{name: "shell_priv_remove_packages", title: "Remove packages as root", op: "remove", tier: TierDestructive, verb: "remove",
		description: "Removes, as root, allow-listed packages exactly as their approved preview listed them, keeping their configuration files; returns what dpkg shows was removed."})
}

// pkgIn is what the install and remove tools' inputs share.
type pkgIn interface {
	privInstallIn | privRemoveIn
}

func namesOf[In pkgIn](in *In) *privPkgNamesIn {
	switch v := any(in).(type) {
	case *privInstallIn:
		return &v.privPkgNamesIn
	case *privRemoveIn:
		return &v.privPkgNamesIn
	}
	return nil
}

func privPkgNamesTool[In pkgIn](d *Deps, ps *pkgSpec) Tool {
	return define(d, spec[In, PackageResult]{
		name: ps.name, title: ps.title, description: ps.description,
		tier: ps.tier, privileged: true, idempotent: false,
		schema:  boundPkgNames,
		audit:   func(in In) map[string]any { n := namesOf(&in); return pkgAudit(n.Target, n.Packages) },
		summary: func(r *PackageResult) string { return "as root: " + changesSummary(&r.Applied) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in In) envelope.Envelope[PackageResult] {
			n := namesOf(&in)
			return d.runPkg(ctx, n.Target, ps.op, n.Packages, n.timeoutArg, n.expectedPreview)
		},
		approvalArgs: func(in In) any {
			n := namesOf(&in)
			return struct {
				Packages       []string `json:"packages"`
				TimeoutSeconds int      `json:"timeout_seconds"`
			}{n.Packages, d.timeoutDefault(n.timeoutArg)}
		},
		describe: func(in In, target string) string {
			return "As root, " + ps.verb + " " + plural(len(namesOf(&in).Packages), "package", "packages") + " on " + target
		},
		preview: func(ctx context.Context, in In, target string) (*preview, *envelope.Error) {
			return d.privPkgPreview(ctx, target, ps.op, namesOf(&in).Packages)
		},
		precondition: func(in *In, p *preview) { namesOf(in).expectedPreview = p.contentSHA256 },
		precheck: func(in *In) *envelope.Error {
			_, e := d.timeoutFor(namesOf(in).timeoutArg)
			return e
		},
	})
}

func privUpgradePackages(d *Deps) Tool {
	return define(d, spec[privPkgNoNamesIn, PackageResult]{
		name: "shell_priv_upgrade_packages", title: "Upgrade packages as root",
		description: "Upgrades, as root, exactly the packages its approved preview listed, each to its approved version, never installing what was not approved nor removing anything; returns what dpkg shows was upgraded.",
		tier:        TierOperator, privileged: true, idempotent: false,
		schema:  boundCommon,
		audit:   func(in privPkgNoNamesIn) map[string]any { return pkgAudit(in.Target, nil) },
		summary: func(r *PackageResult) string { return "as root: " + changesSummary(&r.Applied) },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privPkgNoNamesIn) envelope.Envelope[PackageResult] {
			return d.runPkg(ctx, in.Target, "upgrade", nil, in.timeoutArg, in.expectedPreview)
		},
		approvalArgs: func(in privPkgNoNamesIn) any {
			return struct {
				TimeoutSeconds int `json:"timeout_seconds"`
			}{d.timeoutDefault(in.timeoutArg)}
		},
		describe: func(_ privPkgNoNamesIn, target string) string { return "As root, upgrade packages on " + target },
		describePreview: func(_ privPkgNoNamesIn, target string, p *preview) string {
			return "As root, upgrade " + plural(p.count, "package", "packages") + " on " + target
		},
		preview: func(ctx context.Context, _ privPkgNoNamesIn, target string) (*preview, *envelope.Error) {
			return d.privPkgPreview(ctx, target, "upgrade", nil)
		},
		precondition: func(in *privPkgNoNamesIn, p *preview) { in.expectedPreview = p.contentSHA256 },
		precheck: func(in *privPkgNoNamesIn) *envelope.Error {
			_, e := d.timeoutFor(in.timeoutArg)
			return e
		},
	})
}

func privUpdatePackageIndex(d *Deps) Tool {
	return define(d, spec[privPkgNoNamesIn, PackageIndexUpdate]{
		name: "shell_priv_update_package_index", title: "Update package index as root",
		description: "Updates, as root, the host's package index from its configured sources; returns apt-get's exit status and redacted, size-capped output.",
		tier:        TierOperator, privileged: true, idempotent: false,
		schema:  boundCommon,
		audit:   func(in privPkgNoNamesIn) map[string]any { return pkgAudit(in.Target, nil) },
		summary: func(r *PackageIndexUpdate) string { return plural(r.Attempts, "apt-get run", "apt-get runs") },
		run: func(ctx context.Context, _ *mcp.CallToolRequest, in privPkgNoNamesIn) envelope.Envelope[PackageIndexUpdate] {
			if in.expectedPreview == "" {
				return envelope.Failure[PackageIndexUpdate](in.Target, envelope.Errorf("internal", "an index update needs the hash of an approved preview; nothing was sent"))
			}
			budget, e := d.timeoutFor(in.timeoutArg)
			if e != nil {
				return envelope.Failure[PackageIndexUpdate](in.Target, e)
			}
			r := fetch[pkgResultWire](ctx, d, in.Target, protocol.OpPrivPkgUpdateIndex, pkgBoundWire{ExpectedPreviewSHA256: in.expectedPreview}, budget)
			if !r.OK {
				return envelope.Failure[PackageIndexUpdate](r.Target, r.Error)
			}
			out := PackageIndexUpdate{PackageRun: d.capRun(r.Data.PackageRun)}
			env := envelope.Success(r.Target, out)
			env.Gate, env.Warnings = r.Gate, r.Warnings
			return env
		},
		approvalArgs: func(in privPkgNoNamesIn) any {
			return struct {
				TimeoutSeconds int `json:"timeout_seconds"`
			}{d.timeoutDefault(in.timeoutArg)}
		},
		describe: func(_ privPkgNoNamesIn, target string) string {
			return "As root, update the package index on " + target
		},
		preview: func(ctx context.Context, _ privPkgNoNamesIn, target string) (*preview, *envelope.Error) {
			resp, e := d.call(ctx, target, protocol.OpPrivPkgUpdateIndexPreview, noArgsWire{}, d.budget())
			if e != nil {
				return nil, e
			}
			env := envelope.FromGate[pkgUpdatePreviewWire](target, resp)
			if !env.OK {
				return nil, env.Error
			}
			policy, e := privPolicy(resp)
			if e != nil {
				return nil, e
			}
			hash := env.Data.PreviewSHA256
			if !sha256RE.MatchString(hash) {
				return nil, envelope.Errorf("internal", "the helper's preview has no valid preview_sha256")
			}
			argv := env.Data.Argv
			if argv == nil {
				argv = []string{}
			}
			return &preview{value: map[string]any{"action": "update the package index", "argv": argv, "preview_sha256": hash}, policy: policy, contentSHA256: hash}, nil
		},
		precondition: func(in *privPkgNoNamesIn, p *preview) { in.expectedPreview = p.contentSHA256 },
		precheck: func(in *privPkgNoNamesIn) *envelope.Error {
			_, e := d.timeoutFor(in.timeoutArg)
			return e
		},
	})
}

// capRun redacts and caps apt-get's output to the server's limit.
func (d *Deps) capRun(r PackageRun) PackageRun {
	limit := d.maxOutput()
	red := d.redactor()
	r.StdoutTruncated = capText(red, &r.Stdout, limit) || r.StdoutTruncated
	r.StderrTruncated = capText(red, &r.Stderr, limit) || r.StderrTruncated
	return r
}

// runPkg sends an approved install, upgrade or remove with its fresh
// preview's hash.
func (d *Deps) runPkg(ctx context.Context, target, op string, names []string, ta timeoutArg, expected string) envelope.Envelope[PackageResult] {
	if expected == "" {
		return envelope.Failure[PackageResult](target, envelope.Errorf("internal", "a package operation needs the hash of an approved preview; nothing was sent"))
	}
	budget, e := d.timeoutFor(ta)
	if e != nil {
		return envelope.Failure[PackageResult](target, e)
	}
	r := fetch[pkgResultWire](ctx, d, target, "priv_pkg_"+op, pkgBoundWire{Packages: names, ExpectedPreviewSHA256: expected}, budget)
	if !r.OK {
		return envelope.Failure[PackageResult](r.Target, r.Error)
	}
	x := r.Data
	if x.Applied == nil {
		return envelope.Failure[PackageResult](r.Target, envelope.Errorf("internal", "the helper answered without what dpkg shows was changed; preview again to see the host's state"))
	}
	out := PackageResult{Op: x.Op, Packages: x.Packages, Applied: x.Applied.changes(), PackageRun: d.capRun(x.PackageRun)}
	if out.Packages == nil {
		out.Packages = []string{}
	}
	env := envelope.Success(r.Target, out)
	env.Gate, env.Warnings = r.Gate, r.Warnings
	return env
}

// privPkgPreview is the install, upgrade and remove tools' approval
// preview: the helper's simulated transaction (every package with its
// exact version), the argv and preview_sha256, bound with both policies'
// hashes. The hash the re-call sends is taken from the helper's answer
// before the server's redaction.
func (d *Deps) privPkgPreview(ctx context.Context, target, op string, names []string) (*preview, *envelope.Error) {
	var args any = noArgsWire{}
	if names != nil {
		args = pkgNamesWire{Packages: names}
	}
	resp, e := d.call(ctx, target, "priv_pkg_"+op+"_preview", args, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[pkgPreviewWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	policy, e := privPolicy(resp)
	if e != nil {
		return nil, e
	}
	hash := env.Data.PreviewSHA256
	if !sha256RE.MatchString(hash) || !env.Data.Complete {
		return nil, envelope.Errorf("internal", "the helper's preview has no valid preview_sha256, or is incomplete")
	}
	x := *env.Data
	redactStrings(d.redactor(), reflect.ValueOf(&x))
	c := x.changes()
	inst := make([]map[string]any, 0, len(c.Install))
	for _, v := range c.Install {
		inst = append(inst, map[string]any{"name": v.Name, "version": v.Version})
	}
	upg := make([]map[string]any, 0, len(c.Upgrade))
	for _, u := range c.Upgrade {
		upg = append(upg, map[string]any{"name": u.Name, "from": u.From, "to": u.To})
	}
	rem := make([]map[string]any, 0, len(c.Remove))
	for _, r := range c.Remove {
		rem = append(rem, map[string]any{"name": r.Name, "version": r.Version})
	}
	if names == nil {
		names = []string{}
	}
	argv := x.Argv
	if argv == nil {
		argv = []string{}
	}
	value := map[string]any{"op": op, "packages": names, "install": inst, "upgrade": upg, "remove": rem, "argv": argv, "preview_sha256": hash}
	if len(x.Unfinished) > 0 {
		// A removal of exactly the unfinished packages (handoff N-36):
		// each with its version and state, so that a package that worked
		// at an older version is visibly being removed.
		value["unfinished"] = recoverEntries(x.Unfinished)
	}
	return &preview{value: value, policy: policy, contentSHA256: hash, count: len(c.Install) + len(c.Upgrade) + len(c.Remove)}, nil
}
