//go:build linux

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// Bounds on list sizes (every count is bounded).
const (
	maxRoots       = 64
	maxPatterns    = 256
	maxOwners      = 64
	maxCommands    = 256
	maxPackages    = 256
	maxText        = 256 // acknowledge and description
	maxErrors      = 50
	maxBackupsKeep = 100
	// MaxTimeoutCeiling is the hard ceiling on limits.max_timeout_s
	// (PRIVILEGED §4).
	MaxTimeoutCeiling = 1800
)

// The raw YAML schema. Pointers distinguish "omitted" from zero values.
// KnownFields(true) makes any key not listed here an error.
type rawPolicy struct {
	Version     *int         `yaml:"version"`
	ClientUID   *int64       `yaml:"client_uid"`
	SocketGroup *string      `yaml:"socket_group"`
	MaxTier     *string      `yaml:"max_tier"`
	Sandbox     *rawSandbox  `yaml:"sandbox"`
	Limits      *rawLimits   `yaml:"limits"`
	Paths       *rawPaths    `yaml:"paths"`
	Owners      *rawOwners   `yaml:"owners"`
	Modes       *rawModes    `yaml:"modes"`
	Backups     *rawBackups  `yaml:"backups"`
	Commands    []rawCommand `yaml:"commands"`
	Packages    *rawPackages `yaml:"packages"`
}

type rawSandbox struct {
	Landlock *string `yaml:"landlock"`
}

type rawLimits struct {
	MaxReadBytes     *int `yaml:"max_read_bytes"`
	MaxWriteBytes    *int `yaml:"max_write_bytes"`
	MaxOutputBytes   *int `yaml:"max_output_bytes"`
	DefaultTimeoutS  *int `yaml:"default_timeout_s"`
	MaxTimeoutS      *int `yaml:"max_timeout_s"`
	MaxDeleteEntries *int `yaml:"max_delete_entries"`
}

type rawPaths struct {
	Read        []string         `yaml:"read"`
	Write       []string         `yaml:"write"`
	Persistence []rawPersistence `yaml:"persistence"`
	Deny        []string         `yaml:"deny"`
}

type rawPersistence struct {
	Path        string `yaml:"path"`
	Acknowledge string `yaml:"acknowledge"`
}

type rawOwners struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}

type rawModes struct {
	Max *string `yaml:"max"`
}

type rawBackups struct {
	Keep *int `yaml:"keep"`
}

type rawCommand struct {
	ID             string     `yaml:"id"`
	Path           string     `yaml:"path"`
	Tier           string     `yaml:"tier"`
	Description    string     `yaml:"description"`
	Unit           string     `yaml:"unit"`
	RootEquivalent bool       `yaml:"root_equivalent"`
	Capabilities   []string   `yaml:"capabilities"`
	Acknowledge    string     `yaml:"acknowledge"`
	Templates      [][]string `yaml:"templates"`
}

type rawPackages struct {
	Enabled          bool     `yaml:"enabled"`
	Manager          string   `yaml:"manager"`
	Install          []string `yaml:"install"`
	Remove           []string `yaml:"remove"`
	AllowUpdateIndex bool     `yaml:"allow_update_index"`
	AllowUpgrade     bool     `yaml:"allow_upgrade"`
}

// validator accumulates errors, warnings and findings.
type validator struct {
	opts     *LoadOptions
	errs     []error
	warnings []string
	findings []Finding
	never    *pathx.Matcher // list A plus this host's additions
	anchors  []pathx.Glob   // this host's additions: the helper binary and the policy file
	gateProt *pathx.Matcher // the gate's protected set (POLICY §3)
	scan     *gpolicy.IdentityScan
}

func (v *validator) fail(field, format string, args ...any) {
	if len(v.errs) < maxErrors {
		v.errs = append(v.errs, &Error{field, fmt.Sprintf(format, args...)})
	}
}

func (v *validator) warn(format string, args ...any) {
	v.warnings = append(v.warnings, fmt.Sprintf(format, args...))
}

func (v *validator) find(kind, item, format string, args ...any) {
	v.findings = append(v.findings, Finding{Kind: kind, Item: item, Detail: fmt.Sprintf(format, args...)})
}

// decodeStrict decodes exactly one YAML document with unknown keys
// rejected; go.yaml.in/yaml/v3 rejects duplicate mapping keys itself.
func decodeStrict(data []byte, out *rawPolicy) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("policy is empty")
		}
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("policy must be a single YAML document")
	}
	return nil
}

// oneLine reports whether s is a non-empty single line of printable
// characters of at most maxText bytes.
func oneLine(s string) bool {
	return s != "" && len(s) <= maxText && strings.IndexFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) < 0
}

func parse(data []byte, files []string, opts *LoadOptions) (*Policy, error) {
	var raw rawPolicy
	if err := decodeStrict(data, &raw); err != nil {
		return nil, &Error{"", err.Error()}
	}
	if opts.LookupUser == nil || opts.LookupGroup == nil || opts.UserName == nil {
		return nil, &Error{"", "internal: user and group lookups are not configured"}
	}
	sum := sha256.Sum256(data)
	p := &Policy{SHA256: hex.EncodeToString(sum[:])}
	if len(files) > 0 {
		p.File = files[0]
	}
	v := &validator{opts: opts, scan: gpolicy.NewIdentityScan(opts.SystemBinDirs)}
	if err := v.matchers(files); err != nil {
		return nil, err
	}

	switch {
	case raw.Version == nil:
		v.fail("version", "is required")
	case *raw.Version != SchemaVersion:
		v.fail("version", "is %d; this helper implements %d", *raw.Version, SchemaVersion)
	}
	v.identity(p, &raw)
	if raw.MaxTier == nil {
		v.fail("max_tier", "is required")
	} else if t, err := gpolicy.ParseTier(*raw.MaxTier); err != nil {
		v.fail("max_tier", "%v", err)
	} else {
		p.MaxTier = t
	}
	v.sandbox(p, raw.Sandbox)
	v.limits(p, raw.Limits)
	v.paths(p, raw.Paths)
	v.owners(p, raw.Owners)
	v.modes(p, raw.Modes)
	v.backups(p, raw.Backups)
	v.commands(p, raw.Commands)
	v.packages(p, raw.Packages)
	v.capabilities(p)

	if len(v.errs) > 0 {
		return nil, errors.Join(v.errs...)
	}
	p.Warnings, p.Acknowledged = v.warnings, v.findings
	return p, nil
}

// matchers builds list A (with the running helper and the policy file) and
// the gate's protected set.
func (v *validator) matchers(files []string) error {
	never, err := pathx.NewMatcher(neverPaths)
	if err != nil {
		return &Error{"", "internal: never list: " + err.Error()}
	}
	for _, e := range append([]string{v.opts.HelperExecutable}, files...) {
		if e == "" || pathx.CheckClean(e) != nil {
			continue
		}
		g, gerr := pathx.LiteralGlob(e)
		if gerr != nil {
			return &Error{"", "internal: trust anchor: " + gerr.Error()}
		}
		never.Add(g)
		v.anchors = append(v.anchors, g)
	}
	if v.opts.HelperExecutable == "" {
		return &Error{"", "internal: helper executable path unknown"}
	}
	prot, err := pathx.NewMatcher(gpolicy.BuiltinProtected())
	if err != nil {
		return &Error{"", "internal: protected set: " + err.Error()}
	}
	v.never, v.gateProt = never, prot
	return nil
}

func (v *validator) identity(p *Policy, raw *rawPolicy) {
	switch {
	case raw.ClientUID == nil:
		v.fail("client_uid", "is required (the gate service account's pinned UID, D-020)")
	case *raw.ClientUID < 1 || *raw.ClientUID > 4294967294:
		v.fail("client_uid", "%d is not in 1..4294967294 (root may never be the client)", *raw.ClientUID)
	default:
		p.ClientUID = uint32(*raw.ClientUID)
		if v.opts.UserName(p.ClientUID) == "" {
			v.warn("client_uid %d has no entry in the local user database", p.ClientUID)
		}
	}
	if raw.SocketGroup == nil || *raw.SocketGroup == "" {
		v.fail("socket_group", "is required")
		return
	}
	g := *raw.SocketGroup
	gid, err := v.opts.LookupGroup(g)
	switch {
	case err != nil:
		v.fail("socket_group", "group %q does not exist in the local group database", g)
	case slices.Contains(install.DeniedGroups, g):
		v.fail("socket_group", "group %q is in the D-020 deny list", g)
	case gid == 0:
		v.fail("socket_group", "group %q has gid 0", g)
	default:
		p.SocketGroup, p.SocketGID = g, gid
	}
}

func (v *validator) sandbox(p *Policy, raw *rawSandbox) {
	p.Landlock = LandlockRequired
	if raw == nil || raw.Landlock == nil {
		return
	}
	switch m := LandlockMode(*raw.Landlock); m {
	case LandlockRequired, LandlockBestEffort:
		p.Landlock = m
	default:
		v.fail("sandbox.landlock", "is %q; want required or best-effort", *raw.Landlock)
	}
}

func (v *validator) limits(p *Policy, raw *rawLimits) {
	if raw == nil {
		raw = &rawLimits{}
	}
	l := &p.Limits
	set := func(dst *int, src *int, name string, def, hi int) {
		*dst = def
		if src == nil {
			return
		}
		if *src < 1 || *src > hi {
			v.fail("limits."+name, "%d is not in 1..%d", *src, hi)
			return
		}
		*dst = *src
	}
	set(&l.MaxReadBytes, raw.MaxReadBytes, "max_read_bytes", 1<<20, 4<<20)
	set(&l.MaxWriteBytes, raw.MaxWriteBytes, "max_write_bytes", 1<<20, 1<<20)
	set(&l.MaxOutputBytes, raw.MaxOutputBytes, "max_output_bytes", 1<<20, 4<<20)
	set(&l.MaxTimeoutS, raw.MaxTimeoutS, "max_timeout_s", 900, MaxTimeoutCeiling)
	set(&l.DefaultTimeoutS, raw.DefaultTimeoutS, "default_timeout_s", 60, MaxTimeoutCeiling)
	set(&l.MaxDeleteEntries, raw.MaxDeleteEntries, "max_delete_entries", 1000, 10000)
	if l.DefaultTimeoutS > l.MaxTimeoutS {
		if raw.DefaultTimeoutS == nil {
			l.DefaultTimeoutS = l.MaxTimeoutS
		} else {
			v.fail("limits.default_timeout_s", "%d exceeds max_timeout_s %d", l.DefaultTimeoutS, l.MaxTimeoutS)
		}
	}
}

// hasGit reports whether a clean absolute path has a .git component.
func hasGit(p string) bool {
	return slices.Contains(strings.Split(p, "/"), ".git")
}

// writable checks one write or persistence root against list A and .git
// and reports whether it overlaps the gate's protected set.
func (v *validator) writable(field, r string) (ok, persistence bool) {
	if err := gpolicy.CheckRoot(r); err != nil {
		v.fail(field, "%v", err)
		return false, false
	}
	switch {
	case v.never.Covers(r):
		v.fail(field, "%s is, or is inside, a path on the never list (PRIVILEGED §5.3 list A)", r)
		return false, false
	case v.never.MayContain(r, true):
		v.fail(field, "%s contains a path on the never list (PRIVILEGED §5.3 list A)", r)
		return false, false
	case hasGit(r):
		v.fail(field, "%s is inside a .git directory, which is never writable (POLICY §3)", r)
		return false, false
	}
	return true, v.gateProt.Covers(r) || v.gateProt.MayContain(r, true)
}

func (v *validator) paths(p *Policy, raw *rawPaths) {
	if raw == nil {
		raw = &rawPaths{}
	}
	deny, err := pathx.NewMatcher(gpolicy.BuiltinDeny())
	if err != nil {
		v.fail("", "internal: deny list: %v", err)
		return
	}
	if len(raw.Deny) > maxPatterns {
		v.fail("paths.deny", "has more than %d patterns", maxPatterns)
	}
	for i, d := range raw.Deny {
		g, gerr := pathx.CompileGlob(d)
		if gerr != nil {
			v.fail(fmt.Sprintf("paths.deny[%d]", i), "%v", gerr)
			continue
		}
		deny.Add(g)
		p.Paths.DenyUser = append(p.Paths.DenyUser, d)
	}
	p.Paths.Deny = deny

	// Writes: list A, every .git, and this host's trust anchors.
	prot, err := pathx.NewMatcher(append(NeverPaths(), "**/.git"))
	if err != nil {
		v.fail("", "internal: protected set: %v", err)
		return
	}
	prot.Add(v.anchors...)
	p.Paths.Protected = prot

	if len(raw.Read)+len(raw.Write)+len(raw.Persistence) > maxRoots {
		v.fail("paths", "has more than %d roots", maxRoots)
	}
	// Duplicates are checked per list: read roots among themselves, and write
	// and persistence roots together (a root may be both read and write).
	seenRead, seen := map[string]bool{}, map[string]bool{}
	for i, r := range raw.Read {
		field := fmt.Sprintf("paths.read[%d]", i)
		if err := gpolicy.CheckRoot(r); err != nil {
			v.fail(field, "%v", err)
			continue
		}
		if v.never.Covers(r) {
			v.fail(field, "%s is, or is inside, a path on the never list (PRIVILEGED §5.3 list A)", r)
			continue
		}
		if seenRead[r] {
			v.fail(field, "duplicate root %s", r)
			continue
		}
		seenRead[r] = true
		p.Paths.Read = append(p.Paths.Read, r)
	}
	for i, r := range raw.Write {
		field := fmt.Sprintf("paths.write[%d]", i)
		ok, persistence := v.writable(field, r)
		switch {
		case !ok:
		case persistence:
			v.fail(field, "%s is, is inside, or contains a protected path (POLICY §3); declare it under paths.persistence with an acknowledge", r)
		case seen[r]:
			v.fail(field, "duplicate root %s", r)
		default:
			seen[r] = true
			p.Paths.Write = append(p.Paths.Write, r)
		}
	}
	for i, e := range raw.Persistence {
		field := fmt.Sprintf("paths.persistence[%d]", i)
		ok, persistence := v.writable(field+".path", e.Path)
		switch {
		case !ok:
			continue
		case !oneLine(e.Acknowledge):
			v.fail(field+".acknowledge", "is required: one line of at most %d characters saying why this persistence area is writable", maxText)
			continue
		case seen[e.Path]:
			v.fail(field+".path", "duplicate root %s", e.Path)
			continue
		}
		seen[e.Path] = true
		if !persistence {
			v.warn("%s: %s is not a persistence area; list it under paths.write", field, e.Path)
		}
		p.Paths.Persistence = append(p.Paths.Persistence, Persistence(e))
		v.find("persistence", e.Path, "acknowledge: %s", e.Acknowledge)
	}
	for _, r := range p.Paths.Read {
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
			v.warn("read root %s does not exist or is not a directory; operations under it will fail", r)
		}
	}
	for _, r := range p.Paths.WriteRoots() {
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
			v.warn("write root %s does not exist or is not a directory; the core unit cannot start until it does (ReadWritePaths=)", r)
		}
	}
}

func (v *validator) owners(p *Policy, raw *rawOwners) {
	if raw == nil {
		return
	}
	for _, list := range []struct {
		name   string
		in     []string
		out    *[]NamedID
		lookup func(string) (uint32, error)
	}{{"owners.users", raw.Users, &p.Owners.Users, v.opts.LookupUser}, {"owners.groups", raw.Groups, &p.Owners.Groups, v.opts.LookupGroup}} {
		if len(list.in) > maxOwners {
			v.fail(list.name, "has more than %d names", maxOwners)
		}
		for i, n := range list.in {
			field := fmt.Sprintf("%s[%d]", list.name, i)
			if slices.ContainsFunc(*list.out, func(e NamedID) bool { return e.Name == n }) {
				v.fail(field, "duplicate name %q", n)
				continue
			}
			id, err := list.lookup(n)
			if err != nil {
				v.fail(field, "%q does not exist in the local database", n)
				continue
			}
			*list.out = append(*list.out, NamedID{Name: n, ID: id})
		}
	}
	for _, u := range p.Owners.Users {
		if p.ClientUID != 0 && u.ID == p.ClientUID {
			v.warn("owners.users: %s is the gate's service account (client_uid); files chowned to it become writable by the gate itself", u.Name)
		}
	}
}

var modeRE = regexp.MustCompile(`^[0-7]{3,4}$`)

func (v *validator) modes(p *Policy, raw *rawModes) {
	p.ModesMax = 0o755
	if raw == nil || raw.Max == nil {
		return
	}
	s := *raw.Max
	if !modeRE.MatchString(s) {
		v.fail("modes.max", "%q is not 3 or 4 octal digits", s)
		return
	}
	m, _ := strconv.ParseUint(s, 8, 32)
	switch {
	case m&0o7000 != 0:
		v.fail("modes.max", "%s includes setuid, setgid or sticky bits, which are never allowed", s)
	case m&0o002 != 0:
		v.fail("modes.max", "%s includes world-write, which the file operations never set", s)
	default:
		p.ModesMax = os.FileMode(m)
	}
}

func (v *validator) backups(p *Policy, raw *rawBackups) {
	p.BackupsKeep = 10
	if raw == nil || raw.Keep == nil {
		return
	}
	if k := *raw.Keep; k < 0 || k > maxBackupsKeep {
		v.fail("backups.keep", "%d is not in 0..%d", k, maxBackupsKeep)
		return
	}
	p.BackupsKeep = *raw.Keep
	if p.BackupsKeep == 0 {
		v.warn("backups.keep is 0: overwritten and deleted files are not backed up (not recommended)")
	}
}

var commandIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (v *validator) commands(p *Policy, raw []rawCommand) {
	if len(raw) > maxCommands {
		v.fail("commands", "has more than %d commands", maxCommands)
	}
	for i := range raw {
		rc := &raw[i]
		field := fmt.Sprintf("commands[%d]", i)
		if !commandIDRE.MatchString(rc.ID) {
			v.fail(field+".id", "%q does not match [a-z0-9][a-z0-9-]{0,62}", rc.ID)
			continue
		}
		field = fmt.Sprintf("commands[%s]", rc.ID)
		if _, dup := p.Command(rc.ID); dup {
			v.fail(field, "duplicate command id")
			continue
		}
		c, ok := v.command(field, rc, p.MaxTier)
		if !ok {
			continue
		}
		p.Commands = append(p.Commands, c)
	}
}

func (v *validator) command(field string, rc *rawCommand, maxTier Tier) (Command, bool) {
	c := Command{ID: rc.ID, Path: rc.Path, RootEquivalent: rc.RootEquivalent, Acknowledge: rc.Acknowledge, Description: rc.Description}
	ok := true
	t, err := gpolicy.ParseTier(rc.Tier)
	if err != nil {
		v.fail(field+".tier", "%v", err)
		ok = false
	}
	c.Tier = t
	if rc.Description != "" && !oneLine(rc.Description) {
		v.fail(field+".description", "must be one line of at most %d characters", maxText)
		ok = false
	}
	if rc.Acknowledge != "" && !oneLine(rc.Acknowledge) {
		v.fail(field+".acknowledge", "must be one line of at most %d characters", maxText)
		ok = false
	}
	switch Unit(rc.Unit) {
	case "", UnitCore:
		c.Unit = UnitCore
	case UnitBroad:
		c.Unit = UnitBroad
	default:
		v.fail(field+".unit", "is %q; want core or broad", rc.Unit)
		ok = false
	}
	resolved, listB, rok := v.resolve(field, rc)
	ok = ok && rok
	c.Resolved, c.ListB = resolved, listB
	if !v.commandCapabilities(field, rc, &c) {
		ok = false
	}
	if len(rc.Templates) == 0 || len(rc.Templates) > template.MaxTemplateCount {
		v.fail(field+".templates", "needs 1..%d templates", template.MaxTemplateCount)
		ok = false
	}
	for j, tokens := range rc.Templates {
		tpl, err := template.Parse(tokens)
		switch {
		case err != nil:
			v.fail(fmt.Sprintf("%s.templates[%d]", field, j), "%v", err)
			ok = false
		case tpl.UsesUnit():
			v.fail(fmt.Sprintf("%s.templates[%d]", field, j), "{unit} placeholders are not available in the privileged policy, which declares no units")
			ok = false
		default:
			c.Templates = append(c.Templates, tpl)
		}
	}
	if c.Unit == UnitBroad {
		v.fail(field+".unit", "broad-unit commands arrive in S1d (the broad unit is not generated yet)")
		return c, false
	}
	if !ok {
		return c, false
	}
	if c.ListB > 0 {
		g, gname := c.ListB, listBName(c.ListB)
		v.find("list-b-binary", c.ID, "%s (POLICY §5 group %d: %s); acknowledge: %s", c.Resolved, g, gname, c.Acknowledge)
	}
	if c.RootEquivalent {
		v.find("root-equivalent", c.ID, "%s is declared root_equivalent", c.Resolved)
	}
	if maxTier != 0 && c.Tier > maxTier {
		v.warn("%s: tier %s is above max_tier %s and will always be refused", field, c.Tier, maxTier)
	}
	return c, true
}

func listBName(g int) string {
	for _, base := range []string{"reboot", "modprobe", "nft"} {
		if gg, name, _ := gpolicy.HardDenied(base); gg == g {
			return name
		}
	}
	return "unknown"
}

// resolve resolves the binary and applies the gate's checks with the
// helper's lists: POLICY §5 groups 1–10 are never allowed, 11–13 only with
// an acknowledge (by name as written, as resolved, and by identity).
func (v *validator) resolve(field string, rc *rawCommand) (resolved string, listB int, ok bool) {
	if err := pathx.CheckClean(rc.Path); err != nil {
		v.fail(field+".path", "%v", err)
		return "", 0, false
	}
	resolved, err := filepath.EvalSymlinks(rc.Path)
	if err != nil {
		v.fail(field+".path", "%s cannot be resolved: %v", rc.Path, gpolicy.ErrReason(err))
		return "", 0, false
	}
	deniedGroup := func(g int, what string) bool {
		if g <= 10 {
			v.fail(field+".path", "%s is on the never list (PRIVILEGED §5.3 list A: %s)", rc.Path, what)
			return true
		}
		listB = max(listB, g)
		return false
	}
	for _, base := range []string{filepath.Base(rc.Path), filepath.Base(resolved)} {
		switch {
		case strings.HasPrefix(base, "shell-mcp"):
			v.fail(field+".path", "%q may not be a command: it is one of this project's binaries", base)
			return "", 0, false
		case gpolicy.IsBuiltinOp(base):
			v.fail(field+".path", "%q may not be a privileged command", base)
			return "", 0, false
		case gpolicy.IsContainerCLI(base) && !rc.RootEquivalent:
			v.fail(field+".root_equivalent", "%q is root-equivalent; set root_equivalent: true to acknowledge it", base)
			return "", 0, false
		}
		if g, name, denied := gpolicy.HardDenied(base); denied && deniedGroup(g, fmt.Sprintf("%q is POLICY §5 group %d, %s", base, g, name)) {
			return "", 0, false
		}
	}
	if resolved == v.opts.HelperExecutable || v.never.Covers(resolved) {
		v.fail(field+".path", "%s may not be a command: it is on the never list", resolved)
		return "", 0, false
	}
	if _, err = gpolicy.CheckChain(v.opts.Trust, resolved); err != nil {
		v.fail(field+".path", "%v", err)
		return "", 0, false
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		v.fail(field+".path", "%s: %v", resolved, gpolicy.ErrReason(err))
		return "", 0, false
	}
	if ferr := gpolicy.CheckFile(v.opts.Trust, resolved, fi); ferr != nil {
		v.fail(field+".path", "%v", ferr)
		return "", 0, false
	}
	if fi.Mode().Perm()&0o111 == 0 {
		v.fail(field+".path", "%s is not executable", resolved)
		return "", 0, false
	}
	m, err := v.scan.Match(resolved, fi)
	if err != nil {
		v.fail(field+".path", "%v", err)
		return "", 0, false
	}
	if m != nil && deniedGroup(m.Group, fmt.Sprintf("a hard link to, or a copy of, %q (%s), POLICY §5 group %d, %s", m.Name, m.Path, m.Group, m.GroupName)) {
		return "", 0, false
	}
	if listB > 0 && rc.Acknowledge == "" {
		v.fail(field+".acknowledge", "%s is on the acknowledge list (PRIVILEGED §5.3 list B, POLICY §5 group %d); declaring it needs a non-empty acknowledge", resolved, listB)
		return "", 0, false
	}
	return resolved, listB, true
}

func (v *validator) commandCapabilities(field string, rc *rawCommand, c *Command) bool {
	ok := true
	for j, cp := range rc.Capabilities {
		f := fmt.Sprintf("%s.capabilities[%d]", field, j)
		switch {
		case !slices.Contains(declarable, cp):
			v.fail(f, "%q is not one of %s", cp, strings.Join(declarable, ", "))
			ok = false
		case slices.Contains(c.Capabilities, cp):
			v.fail(f, "duplicate capability %s", cp)
			ok = false
		case cp == "CAP_SYS_ADMIN" && !rc.RootEquivalent:
			v.fail(f, "CAP_SYS_ADMIN is root-equivalent; it needs root_equivalent: true")
			ok = false
		case brokenInCore[cp] != "" && c.Unit != UnitBroad:
			v.fail(f, "%s has no effect in the core unit (%s); it is valid only for commands declared with unit: broad (S1d)", cp, brokenInCore[cp])
			ok = false
		default:
			c.Capabilities = append(c.Capabilities, cp)
		}
	}
	return ok
}

// capabilities computes the core unit's bounding set: the base set plus
// every capability a core-unit command adds, ordered by number.
func (v *validator) capabilities(p *Policy) {
	set := append([]string(nil), BaseCapabilities...)
	for i := range p.Commands {
		c := &p.Commands[i]
		if c.Unit != UnitCore {
			continue
		}
		for _, cp := range c.Capabilities {
			if !slices.Contains(set, cp) {
				set = append(set, cp)
				v.find("capability", cp, "added to the core unit's bounding set by command %s", c.ID)
			}
		}
	}
	slices.SortFunc(set, func(a, b string) int { return capabilityNumbers[a] - capabilityNumbers[b] })
	p.Capabilities = set
}

// packageRE is a Debian package name (Debian Policy §5.6.1).
var packageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

func (v *validator) packages(p *Policy, raw *rawPackages) {
	if raw == nil {
		return
	}
	p.Packages = Packages{Manager: "apt", AllowUpdateIndex: raw.AllowUpdateIndex, AllowUpgrade: raw.AllowUpgrade}
	if raw.Manager != "" && raw.Manager != "apt" {
		v.fail("packages.manager", "is %q; only apt is supported in v1", raw.Manager)
	}
	for _, list := range []struct {
		name string
		in   []string
		out  *[]string
	}{{"packages.install", raw.Install, &p.Packages.Install}, {"packages.remove", raw.Remove, &p.Packages.Remove}} {
		if len(list.in) > maxPackages {
			v.fail(list.name, "has more than %d names", maxPackages)
		}
		for i, n := range list.in {
			field := fmt.Sprintf("%s[%d]", list.name, i)
			switch {
			case len(n) > 128 || !packageRE.MatchString(n):
				v.fail(field, "%q is not a Debian package name", n)
			case slices.Contains(*list.out, n):
				v.fail(field, "duplicate package %q", n)
			default:
				*list.out = append(*list.out, n)
			}
		}
	}
	if raw.Enabled {
		v.fail("packages.enabled", "package operations arrive in S1d (they run in the broad unit, which is not generated yet)")
	}
}
