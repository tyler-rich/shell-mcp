package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

// LookupFunc returns the value of an environment variable and whether it is
// set. os.LookupEnv satisfies it.
type LookupFunc func(key string) (string, bool)

// Error is a configuration error. Reason is one line and never contains
// secret material.
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

func errorf(format string, args ...any) *Error {
	return &Error{Reason: oneLine(fmt.Sprintf(format, args...))}
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", "; ")), " ")
}

// Bounds and defaults for settings with numeric ranges.
const (
	MinTokenLength     = 43
	minApprovalTTL     = 30
	maxApprovalTTL     = 600
	maxSecretFileBytes = 64 << 10
	maxTargetsBytes    = 1 << 20
	maxTargets         = 256
	maxRedactPatterns  = 64
	maxListItems       = 256
)

// Config is the validated server configuration. It is built only by Load.
type Config struct {
	Profile              string
	DisableTools         []string
	Transport            string
	Bind                 string
	Port                 int
	Path                 string
	AuthMode             string
	Token                Secret
	AllowUnauthenticated bool
	AllowedHosts         []string
	AllowedOrigins       []string
	TrustProxy           bool
	RateLimitPerMin      int
	Targets              []Target
	DefaultTarget        string
	SSHConnectTimeout    time.Duration
	SSHMaxSessions       int
	DefaultTimeout       time.Duration
	MaxTimeout           time.Duration
	MaxOutputBytes       int
	ApprovalTiers        []string
	ApprovalFallback     string
	ApprovalTTL          time.Duration
	RedactPatterns       []*regexp.Regexp
	LogLevel             string
	LogFormat            string

	// Warnings are non-fatal findings the caller must log at WARN on every
	// start. They never contain secret material.
	Warnings []string
}

// Target is one SSH target.
type Target struct {
	Name     string
	Host     string
	Port     int
	User     string
	HostKeys []string
	Key      *PrivateKey
}

// Load reads the configuration from lookup (and the files it names) and
// validates it against the fail-closed rules in docs/SECURITY.md §6.
func Load(lookup LookupFunc) (*Config, error) {
	l := &loader{lookup: lookup}
	cfg, err := l.load()
	if err != nil {
		return nil, err
	}
	cfg.Warnings = l.warnings
	return cfg, nil
}

type loader struct {
	lookup   LookupFunc
	warnings []string
}

func (l *loader) warnf(format string, args ...any) {
	l.warnings = append(l.warnings, oneLine(fmt.Sprintf(format, args...)))
}

func (l *loader) get(key, def string) string {
	if v, ok := l.lookup(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func (l *loader) isSet(key string) bool {
	_, ok := l.lookup(key)
	return ok
}

// load runs the validation steps in order; the first failure wins, so each
// reason names exactly one problem.
func (l *loader) load() (*Config, error) {
	c := &Config{}
	steps := []func(*Config) error{
		l.general, l.listen, l.auth, l.network, l.timeouts,
		l.approval, l.output, l.targetSet,
	}
	for _, step := range steps {
		if err := step(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (l *loader) general(c *Config) (err error) {
	if c.Profile, err = l.enum("SHELL_MCP_PROFILE", "read-only", "read-only", "operator", "admin"); err != nil {
		return err
	}
	if c.DisableTools, err = l.toolList("SHELL_MCP_DISABLE_TOOLS"); err != nil {
		return err
	}
	c.Transport, err = l.enum("SHELL_MCP_TRANSPORT", "http", "http", "stdio")
	return err
}

func (l *loader) network(c *Config) (err error) {
	c.AllowedHosts = lowerList(l.get("SHELL_MCP_ALLOWED_HOSTS", "localhost,127.0.0.1"))
	c.AllowedOrigins = lowerList(l.get("SHELL_MCP_ALLOWED_ORIGINS", ""))
	if len(c.AllowedHosts) > maxListItems || len(c.AllowedOrigins) > maxListItems {
		return errorf("SHELL_MCP_ALLOWED_HOSTS / SHELL_MCP_ALLOWED_ORIGINS: at most %d entries", maxListItems)
	}
	if c.TrustProxy, err = l.boolean("SHELL_MCP_TRUST_PROXY", false); err != nil {
		return err
	}
	c.RateLimitPerMin, err = l.integer("SHELL_MCP_RATE_LIMIT_PER_MIN", 120, 1, 100000)
	return err
}

func (l *loader) output(c *Config) (err error) {
	if c.RedactPatterns, err = l.redactPatterns(); err != nil {
		return err
	}
	if c.LogLevel, err = l.enum("SHELL_MCP_LOG_LEVEL", "info", "debug", "info", "warn", "error"); err != nil {
		return err
	}
	c.LogFormat, err = l.enum("SHELL_MCP_LOG_FORMAT", "json", "json", "text")
	return err
}

func (l *loader) targetSet(c *Config) (err error) {
	if c.Targets, err = l.targets(); err != nil {
		return err
	}
	c.DefaultTarget = l.get("SHELL_MCP_DEFAULT_TARGET", "")
	if c.DefaultTarget != "" && !slices.ContainsFunc(c.Targets, func(t Target) bool { return t.Name == c.DefaultTarget }) {
		return errorf("SHELL_MCP_DEFAULT_TARGET names unknown target %q", c.DefaultTarget)
	}
	return nil
}

func (l *loader) listen(c *Config) error {
	c.Bind = l.get("SHELL_MCP_BIND", "127.0.0.1")
	if _, err := netip.ParseAddr(c.Bind); err != nil {
		return errorf("SHELL_MCP_BIND must be an IP address (got %q)", c.Bind)
	}
	var err error
	if c.Port, err = l.integer("SHELL_MCP_PORT", 8080, 1, 65535); err != nil {
		return err
	}
	c.Path = l.get("SHELL_MCP_PATH", "/mcp")
	if !validMCPPath(c.Path) {
		return errorf("SHELL_MCP_PATH must be an absolute path of [A-Za-z0-9._/-] other than / and /healthz (got %q)", c.Path)
	}
	return nil
}

var mcpPathRE = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)

func validMCPPath(p string) bool {
	return mcpPathRE.MatchString(p) && p != "/healthz" && !strings.Contains(p, "/../") &&
		!strings.HasSuffix(p, "/..") && !strings.Contains(p, "/./") && !strings.HasSuffix(p, "/.")
}

func (l *loader) auth(c *Config) error {
	var err error
	if c.AuthMode, err = l.enum("SHELL_MCP_AUTH_MODE", "bearer", "bearer", "none"); err != nil {
		return err
	}
	if c.AllowUnauthenticated, err = l.boolean("SHELL_MCP_ALLOW_UNAUTHENTICATED", false); err != nil {
		return err
	}
	token, tokenSet, err := l.secret("SHELL_MCP_TOKEN")
	if err != nil {
		return err
	}

	if c.Transport == "stdio" && c.AuthMode == "bearer" {
		return errorf("SHELL_MCP_TRANSPORT=stdio requires SHELL_MCP_AUTH_MODE=none (bearer has no meaning over stdio)")
	}
	switch c.AuthMode {
	case "bearer":
		if !tokenSet || token == "" {
			return errorf("SHELL_MCP_AUTH_MODE=bearer requires SHELL_MCP_TOKEN or SHELL_MCP_TOKEN_FILE")
		}
		if len(token) < MinTokenLength {
			return errorf("SHELL_MCP_TOKEN must be at least %d characters (got %d)", MinTokenLength, len(token))
		}
		c.Token = Secret{v: token}
	case "none":
		if c.Transport == "http" {
			if !c.AllowUnauthenticated {
				return errorf("SHELL_MCP_AUTH_MODE=none over HTTP requires SHELL_MCP_ALLOW_UNAUTHENTICATED=true")
			}
			if !IsLoopbackBind(c.Bind) {
				return errorf("SHELL_MCP_AUTH_MODE=none over HTTP requires SHELL_MCP_BIND=127.0.0.1 or ::1 (got %q)", c.Bind)
			}
		}
		if tokenSet {
			l.warnf("SHELL_MCP_TOKEN is set but SHELL_MCP_AUTH_MODE=none; the token is ignored")
		}
	}
	return nil
}

// IsLoopbackBind reports whether bind is exactly one of the loopback bind
// addresses allowed for unauthenticated HTTP (docs/SECURITY.md §3).
func IsLoopbackBind(bind string) bool {
	return bind == "127.0.0.1" || bind == "::1"
}

func (l *loader) timeouts(c *Config) error {
	secs, err := l.integer("SHELL_MCP_SSH_CONNECT_TIMEOUT", 10, 1, 120)
	if err != nil {
		return err
	}
	c.SSHConnectTimeout = time.Duration(secs) * time.Second
	if c.SSHMaxSessions, err = l.integer("SHELL_MCP_SSH_MAX_SESSIONS", 4, 1, 64); err != nil {
		return err
	}
	def, err := l.integer("SHELL_MCP_DEFAULT_TIMEOUT", 30, 1, 3600)
	if err != nil {
		return err
	}
	maxT, err := l.integer("SHELL_MCP_MAX_TIMEOUT", 300, 1, 3600)
	if err != nil {
		return err
	}
	if def > maxT {
		return errorf("SHELL_MCP_DEFAULT_TIMEOUT (%d) must not exceed SHELL_MCP_MAX_TIMEOUT (%d)", def, maxT)
	}
	c.DefaultTimeout = time.Duration(def) * time.Second
	c.MaxTimeout = time.Duration(maxT) * time.Second
	c.MaxOutputBytes, err = l.integer("SHELL_MCP_MAX_OUTPUT_BYTES", 262144, 1024, 4<<20)
	return err
}

func (l *loader) approval(c *Config) error {
	raw := l.get("SHELL_MCP_APPROVAL_TIERS", "destructive")
	tiers := []string{}
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if t != "operator" && t != "destructive" {
			return errorf("SHELL_MCP_APPROVAL_TIERS: unknown tier %q (allowed: operator, destructive)", t)
		}
		if !slices.Contains(tiers, t) {
			tiers = append(tiers, t)
		}
	}
	if !slices.Contains(tiers, "destructive") {
		return errorf("SHELL_MCP_APPROVAL_TIERS must include destructive")
	}
	slices.SortFunc(tiers, func(a, b string) int { return tierOrder(a) - tierOrder(b) })
	c.ApprovalTiers = tiers

	c.ApprovalFallback = l.get("SHELL_MCP_APPROVAL_FALLBACK", "deny")
	switch c.ApprovalFallback {
	case "deny":
	case "confirm-argument":
		l.warnf("SHELL_MCP_APPROVAL_FALLBACK=confirm-argument: clients without elicitation support can approve operations with a model-supplied argument; human approval is not enforced for them")
	default:
		return errorf("SHELL_MCP_APPROVAL_FALLBACK must be deny or confirm-argument (got %q)", c.ApprovalFallback)
	}

	rawTTL := l.get("SHELL_MCP_APPROVAL_TTL", "120")
	ttl, err := strconv.Atoi(rawTTL)
	if err != nil || ttl < minApprovalTTL || ttl > maxApprovalTTL {
		return errorf("SHELL_MCP_APPROVAL_TTL must be between %d and %d seconds (got %s)", minApprovalTTL, maxApprovalTTL, rawTTL)
	}
	c.ApprovalTTL = time.Duration(ttl) * time.Second
	return nil
}

func tierOrder(t string) int {
	if t == "operator" {
		return 0
	}
	return 1
}

// redactPatterns reads SHELL_MCP_REDACT_PATTERNS: one RE2 pattern per line
// (a single-line value is one pattern). Newline separation avoids clashing
// with the commas that regex quantifiers such as {20,} contain.
func (l *loader) redactPatterns() ([]*regexp.Regexp, error) {
	raw, ok := l.lookup("SHELL_MCP_REDACT_PATTERNS")
	if !ok {
		return nil, nil
	}
	var out []*regexp.Regexp
	n := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		n++
		if n > maxRedactPatterns {
			return nil, errorf("SHELL_MCP_REDACT_PATTERNS: at most %d patterns", maxRedactPatterns)
		}
		re, err := regexp.Compile(line)
		if err != nil {
			return nil, errorf("SHELL_MCP_REDACT_PATTERNS: pattern %d does not compile: %v", n, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// --- Targets ---------------------------------------------------------------

var singleTargetVars = []string{
	"SHELL_MCP_TARGET_NAME", "SHELL_MCP_TARGET_HOST", "SHELL_MCP_TARGET_PORT",
	"SHELL_MCP_TARGET_USER", "SHELL_MCP_TARGET_HOST_KEYS",
}

const noTargets = "no targets configured: set SHELL_MCP_TARGETS_FILE or the SHELL_MCP_TARGET_* variables"

type targetsFile struct {
	Targets []fileTarget `yaml:"targets"`
}

type fileTarget struct {
	Name     string   `yaml:"name"`
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	User     string   `yaml:"user"`
	HostKeys []string `yaml:"host_keys"`
	KeyFile  string   `yaml:"key_file"`
}

func (l *loader) targets() ([]Target, error) {
	file := l.get("SHELL_MCP_TARGETS_FILE", "")
	single := slices.ContainsFunc(singleTargetVars, l.isSet)
	if file != "" && single {
		return nil, errorf("SHELL_MCP_TARGETS_FILE and the single-target variables (SHELL_MCP_TARGET_*) are mutually exclusive")
	}

	// The shared key is the default for every target without its own key_file.
	sharedKey, err := l.sharedKey()
	if err != nil {
		return nil, err
	}

	var raw []fileTarget
	switch {
	case file != "":
		if raw, err = l.readTargetsFile(file); err != nil {
			return nil, err
		}
	case single:
		port, err := l.integer("SHELL_MCP_TARGET_PORT", 22, 1, 65535)
		if err != nil {
			return nil, err
		}
		raw = []fileTarget{{
			Name:     l.get("SHELL_MCP_TARGET_NAME", ""),
			Host:     l.get("SHELL_MCP_TARGET_HOST", ""),
			Port:     port,
			User:     l.get("SHELL_MCP_TARGET_USER", ""),
			HostKeys: splitList(l.get("SHELL_MCP_TARGET_HOST_KEYS", "")),
		}}
	}
	if len(raw) == 0 {
		return nil, &Error{Reason: noTargets}
	}
	if len(raw) > maxTargets {
		return nil, errorf("at most %d targets are supported", maxTargets)
	}

	out := make([]Target, 0, len(raw))
	seen := map[string]bool{}
	for i := range raw {
		t, err := l.buildTarget(&raw[i], sharedKey)
		if err != nil {
			return nil, err
		}
		if seen[t.Name] {
			return nil, errorf("SHELL_MCP_TARGETS_FILE: duplicate target name %q", t.Name)
		}
		seen[t.Name] = true
		out = append(out, t)
	}
	return out, nil
}

func (l *loader) readTargetsFile(path string) ([]fileTarget, error) {
	data, err := readBounded(path, maxTargetsBytes)
	if err != nil {
		return nil, errorf("SHELL_MCP_TARGETS_FILE: cannot read file")
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var tf targetsFile
	if err := dec.Decode(&tf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, errorf("SHELL_MCP_TARGETS_FILE: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errorf("SHELL_MCP_TARGETS_FILE: must contain exactly one YAML document")
	}
	return tf.Targets, nil
}

var (
	targetNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	userRE       = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	hostRE       = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

func (l *loader) buildTarget(ft *fileTarget, sharedKey *PrivateKey) (Target, error) {
	if !targetNameRE.MatchString(ft.Name) {
		return Target{}, errorf("target name %q must match %s", ft.Name, targetNameRE)
	}
	id := fmt.Sprintf("target %q", ft.Name)
	if !validHost(ft.Host) {
		return Target{}, errorf("%s: host %q is not a hostname or IP address", id, ft.Host)
	}
	if ft.Port == 0 {
		ft.Port = 22
	}
	if ft.Port < 1 || ft.Port > 65535 {
		return Target{}, errorf("%s: port %d out of range", id, ft.Port)
	}
	if !userRE.MatchString(ft.User) {
		return Target{}, errorf("%s: user %q must match %s", id, ft.User, userRE)
	}
	if len(ft.HostKeys) == 0 {
		return Target{}, errorf("%s: no pinned host key", id)
	}
	if len(ft.HostKeys) > 16 {
		return Target{}, errorf("%s: at most 16 pinned host keys", id)
	}
	for _, fp := range ft.HostKeys {
		if !ValidFingerprint(fp) {
			return Target{}, errorf("%s: host key %q is not a SHA256:<base64> fingerprint", id, fp)
		}
	}

	key := sharedKey
	if ft.KeyFile != "" {
		data, err := l.readSecretFile(id+" key_file", ft.KeyFile)
		if err != nil {
			return Target{}, err
		}
		if key, err = parsePrivateKey(id+" key_file", data); err != nil {
			return Target{}, err
		}
	}
	if key == nil {
		return Target{}, errorf("%s: no SSH private key (set SHELL_MCP_SSH_KEY, SHELL_MCP_SSH_KEY_FILE or key_file)", id)
	}
	return Target{
		Name: ft.Name, Host: ft.Host, Port: ft.Port, User: ft.User,
		HostKeys: slices.Clone(ft.HostKeys), Key: key,
	}, nil
}

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return hostRE.MatchString(h) && !strings.Contains(h, "..")
}

// ValidFingerprint reports whether fp is an OpenSSH SHA-256 fingerprint:
// "SHA256:" followed by the unpadded standard base64 of 32 bytes.
func ValidFingerprint(fp string) bool {
	b64, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(b64)
	return err == nil && len(raw) == 32
}

func (l *loader) sharedKey() (*PrivateKey, error) {
	data, ok, err := l.secret("SHELL_MCP_SSH_KEY")
	if err != nil || !ok || data == "" {
		return nil, err
	}
	return parsePrivateKey("SHELL_MCP_SSH_KEY", []byte(data))
}

func parsePrivateKey(source string, data []byte) (*PrivateKey, error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, errorf("%s: private key is passphrase-protected and no passphrase source is supported", source)
		}
		return nil, errorf("%s: private key cannot be parsed", source)
	}
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		priv = k
	case *ed25519.PrivateKey:
		priv = *k
	default:
		return nil, errorf("%s: private key is not Ed25519", source)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, errorf("%s: private key cannot be parsed", source)
	}
	return &PrivateKey{signer: signer, fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}, nil
}

// --- Primitive readers -----------------------------------------------------

// secret returns NAME_FILE's content (one trailing newline stripped) when
// NAME_FILE is set, otherwise NAME's value. ok reports whether either is set.
func (l *loader) secret(name string) (value string, ok bool, err error) {
	fileVar := name + "_FILE"
	if path := l.get(fileVar, ""); path != "" {
		data, err := l.readSecretFile(fileVar, path)
		if err != nil {
			return "", false, err
		}
		return string(data), true, nil
	}
	v, ok := l.lookup(name)
	return v, ok, nil
}

func (l *loader) readSecretFile(source, path string) ([]byte, error) {
	data, err := readBounded(path, maxSecretFileBytes)
	if err != nil {
		return nil, errorf("%s: cannot read file", source)
	}
	if fi, err := os.Stat(filepath.Clean(path)); err == nil && fi.Mode().Perm()&0o044 != 0 {
		l.warnf("%s is readable by group or other (mode %04o); restrict it to the server's user", source, fi.Mode().Perm())
	}
	return stripOneNewline(data), nil
}

func stripOneNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func (l *loader) enum(key, def string, allowed ...string) (string, error) {
	v := l.get(key, def)
	if !slices.Contains(allowed, v) {
		return "", errorf("%s must be one of %s (got %q)", key, strings.Join(allowed, ", "), v)
	}
	return v, nil
}

func (l *loader) boolean(key string, def bool) (bool, error) {
	v := strings.ToLower(l.get(key, strconv.FormatBool(def)))
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errorf("%s must be true or false (got %q)", key, v)
}

func (l *loader) integer(key string, def, lo, hi int) (int, error) {
	raw := l.get(key, strconv.Itoa(def))
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, errorf("%s must be an integer between %d and %d (got %q)", key, lo, hi, raw)
	}
	return n, nil
}

var toolNameRE = regexp.MustCompile(`^shell_[a-z0-9]+(_[a-z0-9]+)+$`)

func (l *loader) toolList(key string) ([]string, error) {
	items := splitList(l.get(key, ""))
	if len(items) > maxListItems {
		return nil, errorf("%s: at most %d entries", key, maxListItems)
	}
	for _, n := range items {
		if !toolNameRE.MatchString(n) {
			return nil, errorf("%s: %q is not a tool name", key, n)
		}
	}
	return items, nil
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func lowerList(s string) []string {
	items := splitList(s)
	for i := range items {
		items[i] = strings.ToLower(items[i])
	}
	return items
}
