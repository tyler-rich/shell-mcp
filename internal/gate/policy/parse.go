package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// Bounds on list sizes (every count is bounded).
const (
	maxRoots        = 64
	maxPatterns     = 256
	maxPorts        = 64
	maxRepos        = 64
	maxCommands     = 256
	maxRedact       = 64
	maxRedactLen    = 1024
	maxDescription  = 256
	maxRemoteLength = 2048
	maxErrors       = 50
	runShellMCP     = "/run/shell-mcp/"
)

// The raw YAML schema. Pointers distinguish "omitted" from zero values.
// KnownFields(true) makes any key not listed here an error — including
// `sudo`, which exists nowhere in the schema.
type rawPolicy struct {
	Version    *int           `yaml:"version"`
	MaxTier    *string        `yaml:"max_tier"`
	Sandbox    *rawSandbox    `yaml:"sandbox"`
	Limits     *rawLimits     `yaml:"limits"`
	Paths      *rawPaths      `yaml:"paths"`
	Services   *rawServices   `yaml:"services"`
	Journal    *rawJournal    `yaml:"journal"`
	Git        *rawGit        `yaml:"git"`
	Privileged *rawPrivileged `yaml:"privileged"`
	Redact     *rawRedact     `yaml:"redact"`
	Commands   []rawCommand   `yaml:"commands"`
}

type rawSandbox struct {
	Landlock        *string  `yaml:"landlock"`
	SystemReadExec  []string `yaml:"system_read_exec"`
	TCPConnectPorts []int    `yaml:"tcp_connect_ports"`
}

type rawLimits struct {
	DefaultTimeoutS  *int `yaml:"default_timeout_s"`
	MaxTimeoutS      *int `yaml:"max_timeout_s"`
	MaxOutputBytes   *int `yaml:"max_output_bytes"`
	MaxStdinBytes    *int `yaml:"max_stdin_bytes"`
	MaxReadBytes     *int `yaml:"max_read_bytes"`
	MaxWriteBytes    *int `yaml:"max_write_bytes"`
	MaxFindResults   *int `yaml:"max_find_results"`
	MaxFindDepth     *int `yaml:"max_find_depth"`
	MaxDeleteEntries *int `yaml:"max_delete_entries"`
	MaxProcesses     *int `yaml:"max_processes"`
}

type rawPaths struct {
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
	Deny  []string `yaml:"deny"`
}

type rawServices struct {
	Status  []string    `yaml:"status"`
	Control *rawControl `yaml:"control"`
}

type rawControl struct {
	Units []string `yaml:"units"`
	Verbs []string `yaml:"verbs"`
}

type rawJournal struct {
	Units    []string `yaml:"units"`
	MaxLines *int     `yaml:"max_lines"`
}

type rawGit struct {
	Repos []rawRepo `yaml:"repos"`
}

type rawRepo struct {
	Path   string `yaml:"path"`
	Remote string `yaml:"remote"`
}

type rawPrivileged struct {
	Enabled     bool    `yaml:"enabled"`
	Socket      string  `yaml:"socket"`
	BroadSocket string  `yaml:"broad_socket"`
	MaxTier     *string `yaml:"max_tier"`
}

type rawRedact struct {
	Patterns []string `yaml:"patterns"`
}

type rawCommand struct {
	ID             string     `yaml:"id"`
	Path           string     `yaml:"path"`
	Tier           string     `yaml:"tier"`
	Description    string     `yaml:"description"`
	RootEquivalent bool       `yaml:"root_equivalent"`
	Templates      [][]string `yaml:"templates"`
}

// validator accumulates errors and warnings.
type validator struct {
	errs     []error
	warnings []string
}

func (v *validator) fail(field, format string, args ...any) {
	if len(v.errs) < maxErrors {
		v.errs = append(v.errs, &Error{field, fmt.Sprintf(format, args...)})
	}
}

func (v *validator) warn(format string, args ...any) {
	v.warnings = append(v.warnings, fmt.Sprintf(format, args...))
}

// decodeStrict decodes exactly one YAML document with unknown keys rejected.
// go.yaml.in/yaml/v3 rejects duplicate mapping keys itself ("mapping key …
// already defined").
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

func parse(data []byte, files []string, opts LoadOptions) (*Policy, error) {
	var raw rawPolicy
	if err := decodeStrict(data, &raw); err != nil {
		return nil, &Error{"", err.Error()}
	}
	sum := sha256.Sum256(data)
	p := &Policy{SHA256: hex.EncodeToString(sum[:]), ServiceHome: opts.ServiceHome}
	v := &validator{}

	switch {
	case raw.Version == nil:
		v.fail("version", "is required")
	case *raw.Version != SchemaVersion:
		v.fail("version", "is %d; this gate implements %d", *raw.Version, SchemaVersion)
	}
	if raw.MaxTier == nil {
		v.fail("max_tier", "is required")
	} else if t, err := ParseTier(*raw.MaxTier); err != nil {
		v.fail("max_tier", "%v", err)
	} else {
		p.MaxTier = t
	}

	v.sandbox(p, raw.Sandbox)
	v.limits(p, raw.Limits)
	v.paths(p, raw.Paths, files, opts)
	v.services(p, raw.Services)
	v.journal(p, raw.Journal)
	v.git(p, raw.Git)
	v.privileged(p, raw.Privileged)
	v.redact(p, raw.Redact)
	v.commands(p, raw.Commands, opts)
	v.roots(p)

	if len(v.errs) > 0 {
		return nil, errors.Join(v.errs...)
	}
	p.Warnings = v.warnings
	return p, nil
}

func (v *validator) sandbox(p *Policy, raw *rawSandbox) {
	p.Sandbox.Landlock = LandlockRequired
	if raw == nil {
		return
	}
	if raw.Landlock != nil {
		switch m := LandlockMode(*raw.Landlock); m {
		case LandlockRequired, LandlockBestEffort:
			p.Sandbox.Landlock = m
		default:
			v.fail("sandbox.landlock", "is %q; want required or best-effort", *raw.Landlock)
		}
	}
	if len(raw.SystemReadExec) > maxRoots {
		v.fail("sandbox.system_read_exec", "has more than %d entries", maxRoots)
	}
	for i, d := range raw.SystemReadExec {
		field := fmt.Sprintf("sandbox.system_read_exec[%d]", i)
		if err := pathx.CheckClean(d); err != nil {
			v.fail(field, "%v", err)
			continue
		}
		if d == "/" {
			v.fail(field, "/ may not be granted read+execute")
			continue
		}
		p.Sandbox.SystemReadExec = append(p.Sandbox.SystemReadExec, d)
	}
	if len(raw.TCPConnectPorts) > maxPorts {
		v.fail("sandbox.tcp_connect_ports", "has more than %d entries", maxPorts)
	}
	for i, port := range raw.TCPConnectPorts {
		field := fmt.Sprintf("sandbox.tcp_connect_ports[%d]", i)
		if port < 1 || port > 65535 {
			v.fail(field, "%d is not in 1..65535", port)
			continue
		}
		if slices.Contains(p.Sandbox.TCPConnectPorts, uint16(port)) {
			v.fail(field, "duplicate port %d", port)
			continue
		}
		p.Sandbox.TCPConnectPorts = append(p.Sandbox.TCPConnectPorts, uint16(port))
	}
}

func (v *validator) limits(p *Policy, raw *rawLimits) {
	if raw == nil {
		raw = &rawLimits{}
	}
	l := &p.Limits
	set := func(dst *int, src *int, name string, def, lo, hi int) {
		*dst = def
		if src == nil {
			return
		}
		if *src < lo || *src > hi {
			v.fail("limits."+name, "%d is not in %d..%d", *src, lo, hi)
			return
		}
		*dst = *src
	}
	set(&l.MaxTimeoutS, raw.MaxTimeoutS, "max_timeout_s", 300, 1, 600)
	set(&l.DefaultTimeoutS, raw.DefaultTimeoutS, "default_timeout_s", 30, 1, 600)
	set(&l.MaxOutputBytes, raw.MaxOutputBytes, "max_output_bytes", 1<<20, 1, 4<<20)
	set(&l.MaxStdinBytes, raw.MaxStdinBytes, "max_stdin_bytes", 1<<20, 0, 1<<20)
	set(&l.MaxReadBytes, raw.MaxReadBytes, "max_read_bytes", 1<<20, 1, 4<<20)
	set(&l.MaxWriteBytes, raw.MaxWriteBytes, "max_write_bytes", 1<<20, 1, 1<<20)
	set(&l.MaxFindResults, raw.MaxFindResults, "max_find_results", 1000, 1, 10000)
	set(&l.MaxFindDepth, raw.MaxFindDepth, "max_find_depth", 8, 1, 32)
	set(&l.MaxDeleteEntries, raw.MaxDeleteEntries, "max_delete_entries", 1000, 1, 10000)
	set(&l.MaxProcesses, raw.MaxProcesses, "max_processes", 2000, 1, 100000)
	if l.DefaultTimeoutS > l.MaxTimeoutS {
		if raw.DefaultTimeoutS == nil {
			l.DefaultTimeoutS = l.MaxTimeoutS
		} else {
			v.fail("limits.default_timeout_s", "%d exceeds max_timeout_s %d", l.DefaultTimeoutS, l.MaxTimeoutS)
		}
	}
}

// checkRoot applies POLICY §3 to one root.
func checkRoot(p string) error {
	if err := pathx.CheckClean(p); err != nil {
		return err
	}
	if p == "/" {
		return errors.New("/ may not be a root")
	}
	for _, f := range forbiddenRoots {
		if pathx.Within(f, p) {
			return fmt.Errorf("%s may not be a root or contain one", f)
		}
	}
	return nil
}

func (v *validator) paths(p *Policy, raw *rawPaths, files []string, opts LoadOptions) {
	if raw == nil {
		raw = &rawPaths{}
	}
	// Protected set: built-ins plus this host's trust anchors.
	prot, err := pathx.NewMatcher(builtinProtected)
	if err != nil {
		v.fail("", "internal: protected set: %v", err)
		return
	}
	extra := []string{opts.GateExecutable, opts.ServiceHome}
	extra = append(extra, files...)
	for _, e := range extra {
		// A home of "/" (common for system accounts) would make every
		// path protected; "/" can never be a write root anyway.
		if e == "" || e == "/" {
			continue
		}
		g, gerr := pathx.LiteralGlob(e)
		if gerr != nil {
			v.fail("", "trust anchor %q: %v", e, gerr)
			continue
		}
		prot.Add(g)
	}
	if opts.GateExecutable == "" {
		v.fail("", "internal: gate executable path unknown")
	}
	if opts.ServiceHome == "" {
		v.fail("", "service account home directory unknown")
	}
	p.Paths.Protected = prot

	deny, err := pathx.NewMatcher(builtinDeny)
	if err != nil {
		v.fail("", "internal: deny list: %v", err)
		return
	}
	if len(raw.Deny) > maxPatterns {
		v.fail("paths.deny", "has more than %d patterns", maxPatterns)
	}
	for i, d := range raw.Deny {
		g, err := pathx.CompileGlob(d)
		if err != nil {
			v.fail(fmt.Sprintf("paths.deny[%d]", i), "%v", err)
			continue
		}
		deny.Add(g)
		p.Paths.DenyUser = append(p.Paths.DenyUser, d)
	}
	p.Paths.Deny = deny

	for _, list := range []struct {
		name string
		in   []string
		out  *[]string
	}{{"paths.read", raw.Read, &p.Paths.Read}, {"paths.write", raw.Write, &p.Paths.Write}} {
		if len(list.in) > maxRoots {
			v.fail(list.name, "has more than %d roots", maxRoots)
		}
		for i, r := range list.in {
			field := fmt.Sprintf("%s[%d]", list.name, i)
			if err := checkRoot(r); err != nil {
				v.fail(field, "%v", err)
				continue
			}
			if slices.Contains(*list.out, r) {
				v.fail(field, "duplicate root %s", r)
				continue
			}
			*list.out = append(*list.out, r)
		}
	}
	for i, w := range p.Paths.Write {
		field := fmt.Sprintf("paths.write[%d]", i)
		switch {
		case prot.Covers(w):
			v.fail(field, "%s is, or is inside, a protected path", w)
		case prot.MayContain(w, true):
			v.fail(field, "%s contains a protected path", w)
		}
	}
}

// validPattern checks a unit-name glob (fnmatch over names, no "/").
func validPattern(s string) error {
	if s == "" || len(s) > 256 {
		return errors.New("pattern is empty or longer than 256 characters")
	}
	if strings.ContainsAny(s, "/\x00\n\r") {
		return errors.New("pattern may not contain /, NUL or line breaks")
	}
	if _, err := path.Match(s, ""); err != nil {
		return errors.New("pattern is malformed")
	}
	return nil
}

// unitNameRE is an exact unit name (systemd's character set, no leading "-").
var unitNameRE = regexp.MustCompile(`^[A-Za-z0-9:_.\\@][A-Za-z0-9:_.\\@-]{0,254}$`)

var serviceVerbs = []string{"start", "stop", "restart", "reload"}

func (v *validator) services(p *Policy, raw *rawServices) {
	if raw == nil {
		return
	}
	if len(raw.Status) > maxPatterns {
		v.fail("services.status", "has more than %d patterns", maxPatterns)
	}
	for i, s := range raw.Status {
		if err := validPattern(s); err != nil {
			v.fail(fmt.Sprintf("services.status[%d]", i), "%v", err)
			continue
		}
		p.Services.Status = append(p.Services.Status, s)
	}
	if raw.Control == nil {
		return
	}
	c := raw.Control
	if (len(c.Units) == 0) != (len(c.Verbs) == 0) {
		v.fail("services.control", "units and verbs must both be set or both be empty")
	}
	if len(c.Units) > maxPatterns {
		v.fail("services.control.units", "has more than %d units", maxPatterns)
	}
	for i, u := range c.Units {
		field := fmt.Sprintf("services.control.units[%d]", i)
		switch {
		case strings.ContainsAny(u, "*?["):
			v.fail(field, "%q is a glob; exact unit names only", u)
		case !unitNameRE.MatchString(u):
			v.fail(field, "%q is not a unit name", u)
		case slices.Contains(p.Services.ControlUnits, u):
			v.fail(field, "duplicate unit %q", u)
		default:
			p.Services.ControlUnits = append(p.Services.ControlUnits, u)
		}
	}
	for i, verb := range c.Verbs {
		field := fmt.Sprintf("services.control.verbs[%d]", i)
		switch {
		case !slices.Contains(serviceVerbs, verb):
			v.fail(field, "%q is not start, stop, restart or reload", verb)
		case slices.Contains(p.Services.ControlVerbs, verb):
			v.fail(field, "duplicate verb %q", verb)
		default:
			p.Services.ControlVerbs = append(p.Services.ControlVerbs, verb)
		}
	}
}

func (v *validator) journal(p *Policy, raw *rawJournal) {
	if raw == nil {
		return
	}
	if len(raw.Units) > maxPatterns {
		v.fail("journal.units", "has more than %d patterns", maxPatterns)
	}
	for i, s := range raw.Units {
		if err := validPattern(s); err != nil {
			v.fail(fmt.Sprintf("journal.units[%d]", i), "%v", err)
			continue
		}
		p.Journal.Units = append(p.Journal.Units, s)
	}
	p.Journal.MaxLines = 1000
	if raw.MaxLines != nil {
		if *raw.MaxLines < 1 || *raw.MaxLines > 10000 {
			v.fail("journal.max_lines", "%d is not in 1..10000", *raw.MaxLines)
		} else {
			p.Journal.MaxLines = *raw.MaxLines
		}
	}
}

func (v *validator) git(p *Policy, raw *rawGit) {
	if raw == nil {
		return
	}
	if len(raw.Repos) > maxRepos {
		v.fail("git.repos", "has more than %d repos", maxRepos)
	}
	for i, r := range raw.Repos {
		field := fmt.Sprintf("git.repos[%d]", i)
		if err := pathx.CheckClean(r.Path); err != nil {
			v.fail(field+".path", "%v", err)
			continue
		}
		roots := append(append([]string(nil), p.Paths.Read...), p.Paths.Write...)
		if _, ok := pathx.Longest(roots, r.Path); !ok {
			v.fail(field+".path", "%s is not inside a read or write root", r.Path)
			continue
		}
		switch {
		case r.Remote == "":
			v.fail(field+".remote", "is required")
			continue
		case len(r.Remote) > maxRemoteLength, strings.HasPrefix(r.Remote, "-"),
			strings.IndexFunc(r.Remote, func(c rune) bool { return c <= ' ' || c == 0x7f }) >= 0:
			v.fail(field+".remote", "must be at most %d characters, not start with '-', and contain no spaces or control characters", maxRemoteLength)
			continue
		}
		for _, e := range p.Git.Repos {
			if e.Path == r.Path {
				v.fail(field+".path", "duplicate repo %s", r.Path)
			}
		}
		p.Git.Repos = append(p.Git.Repos, Repo(r))
	}
}

func checkSocket(s string) error {
	if err := pathx.CheckClean(s); err != nil {
		return err
	}
	if !strings.HasPrefix(s, runShellMCP) || len(s) == len(runShellMCP) {
		return fmt.Errorf("%s is not beneath %s", s, runShellMCP)
	}
	return nil
}

func (v *validator) privileged(p *Policy, raw *rawPrivileged) {
	p.Privileged.MaxTier = TierRead
	if raw == nil {
		return
	}
	p.Privileged.Enabled = raw.Enabled
	if raw.Socket != "" {
		if err := checkSocket(raw.Socket); err != nil {
			v.fail("privileged.socket", "%v", err)
		} else {
			p.Privileged.Socket = raw.Socket
		}
	} else if raw.Enabled {
		v.fail("privileged.socket", "is required when privileged.enabled is true")
	}
	if raw.BroadSocket != "" {
		if err := checkSocket(raw.BroadSocket); err != nil {
			v.fail("privileged.broad_socket", "%v", err)
		} else {
			p.Privileged.BroadSocket = raw.BroadSocket
		}
	}
	if raw.MaxTier != nil {
		t, err := ParseTier(*raw.MaxTier)
		switch {
		case err != nil:
			v.fail("privileged.max_tier", "%v", err)
		case p.MaxTier != 0 && t > p.MaxTier:
			v.fail("privileged.max_tier", "%s exceeds max_tier %s", t, p.MaxTier)
		default:
			p.Privileged.MaxTier = t
		}
	}
}

func (v *validator) redact(p *Policy, raw *rawRedact) {
	if raw == nil {
		return
	}
	if len(raw.Patterns) > maxRedact {
		v.fail("redact.patterns", "has more than %d patterns", maxRedact)
	}
	for i, s := range raw.Patterns {
		field := fmt.Sprintf("redact.patterns[%d]", i)
		if s == "" || len(s) > maxRedactLen {
			v.fail(field, "is empty or longer than %d characters", maxRedactLen)
			continue
		}
		re, err := regexp.Compile(s)
		if err != nil {
			v.fail(field, "does not compile: %v", err)
			continue
		}
		p.Redact = append(p.Redact, re)
	}
}

var commandIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (v *validator) commands(p *Policy, raw []rawCommand, opts LoadOptions) {
	if len(raw) > maxCommands {
		v.fail("commands", "has more than %d commands", maxCommands)
	}
	for i, rc := range raw {
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
		c := Command{ID: rc.ID, Path: rc.Path, RootEquivalent: rc.RootEquivalent}
		t, err := ParseTier(rc.Tier)
		if err != nil {
			v.fail(field+".tier", "%v", err)
			continue
		}
		c.Tier = t
		if len(rc.Description) > maxDescription || strings.IndexFunc(rc.Description, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 {
			v.fail(field+".description", "must be one line of at most %d characters", maxDescription)
			continue
		}
		c.Description = rc.Description
		resolved, ok := v.resolveCommand(field, &rc, opts)
		if !ok {
			continue
		}
		c.Resolved = resolved
		if len(rc.Templates) == 0 || len(rc.Templates) > template.MaxTemplateCount {
			v.fail(field+".templates", "needs 1..%d templates", template.MaxTemplateCount)
			continue
		}
		bad := false
		for j, tokens := range rc.Templates {
			tpl, err := template.Parse(tokens)
			if err != nil {
				v.fail(fmt.Sprintf("%s.templates[%d]", field, j), "%v", err)
				bad = true
				continue
			}
			c.Templates = append(c.Templates, tpl)
			if tpl.UsesPathWrite() && c.Tier == TierRead {
				v.warn("%s: read-tier command takes a {path:write} placeholder", field)
			}
			if tpl.UsesUnit() && len(p.Services.Status) == 0 {
				v.warn("%s: {unit} placeholder can never match: services.status is empty", field)
			}
		}
		if bad {
			continue
		}
		if p.MaxTier != 0 && c.Tier > p.MaxTier {
			v.warn("%s: tier %s is above max_tier %s and will always be refused", field, c.Tier, p.MaxTier)
		}
		p.Commands = append(p.Commands, c)
	}
}

// resolveCommand resolves the binary, applies the hard-deny list to the
// base name as written and as resolved, requires root_equivalent for
// container CLIs, and checks ownership of the binary and its directories.
func (v *validator) resolveCommand(field string, rc *rawCommand, opts LoadOptions) (resolved string, ok bool) {
	if err := pathx.CheckClean(rc.Path); err != nil {
		v.fail(field+".path", "%v", err)
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(rc.Path)
	if err != nil {
		v.fail(field+".path", "%s cannot be resolved: %v", rc.Path, errReason(err))
		return "", false
	}
	for _, base := range []string{filepath.Base(rc.Path), filepath.Base(resolved)} {
		if g, name, denied := hardDenied(base); denied {
			v.fail(field+".path", "%s resolves to %q, which is hard-denied (group %d: %s)", rc.Path, base, g, name)
			return "", false
		}
		if slices.Contains(builtinOps, base) {
			v.fail(field+".path", "%q may not be a policy command; use the built-in operations", base)
			return "", false
		}
		if slices.Contains(containerCLIs, base) && !rc.RootEquivalent {
			v.fail(field+".root_equivalent", "%q is root-equivalent; set root_equivalent: true to acknowledge it", base)
			return "", false
		}
	}
	if _, err = CheckChain(opts.Trust, resolved); err != nil {
		v.fail(field+".path", "%v", err)
		return "", false
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		v.fail(field+".path", "%s: %v", resolved, errReason(err))
		return "", false
	}
	if err := checkFile(opts.Trust, resolved, fi); err != nil {
		v.fail(field+".path", "%v", err)
		return "", false
	}
	if fi.Mode().Perm()&0o111 == 0 {
		v.fail(field+".path", "%s is not executable", resolved)
		return "", false
	}
	return resolved, true
}

// roots emits warnings that need the whole policy.
func (v *validator) roots(p *Policy) {
	execDirs := append(DefaultReadExec(), p.Sandbox.SystemReadExec...)
	for _, c := range p.Commands {
		if _, ok := pathx.Longest(execDirs, c.Resolved); !ok {
			v.warn("commands[%s]: %s is outside the sandbox's read+execute directories; add its directory to sandbox.system_read_exec", c.ID, c.Resolved)
		}
	}
	for _, d := range p.Sandbox.SystemReadExec {
		for _, w := range p.Paths.Write {
			if pathx.Within(d, w) || pathx.Within(w, d) {
				v.warn("sandbox.system_read_exec: %s overlaps write root %s; files the service user writes would be executable", d, w)
			}
		}
	}
	for _, r := range append(append([]string(nil), p.Paths.Read...), p.Paths.Write...) {
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
			v.warn("root %s does not exist or is not a directory; operations under it will fail", r)
		}
	}
}
