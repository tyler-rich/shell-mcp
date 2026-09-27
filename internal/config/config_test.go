package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// All hosts, users, names and keys below are invented test fixtures.

const testToken = "tok-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH" // 48 chars

var testFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))

type testKey struct {
	pem  string
	seed []byte
}

func newEd25519Key(t *testing.T) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	return testKey{pem: string(pem.EncodeToMemory(block)), seed: priv.Seed()}
}

func lookupFrom(m map[string]string) LookupFunc {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// baseEnv is a valid bearer-mode, single-target configuration.
func baseEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"SHELL_MCP_TOKEN":            testToken,
		"SHELL_MCP_TARGET_NAME":      "app-host",
		"SHELL_MCP_TARGET_HOST":      "target-a.example.test",
		"SHELL_MCP_TARGET_USER":      "svc-shell",
		"SHELL_MCP_TARGET_HOST_KEYS": testFingerprint,
		"SHELL_MCP_SSH_KEY":          newEd25519Key(t).pem,
	}
}

func writeFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // the umask may have masked WriteFile's mode
		t.Fatal(err)
	}
	return p
}

func mustLoad(t *testing.T, env map[string]string) *Config {
	t.Helper()
	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	return cfg
}

func wantReason(t *testing.T, env map[string]string, want string) {
	t.Helper()
	_, err := Load(lookupFrom(env))
	if err == nil {
		t.Fatalf("Load: want error %q, got nil", want)
	}
	var cerr *Error
	if !errors.As(err, &cerr) {
		t.Fatalf("Load: error %v is not a *config.Error", err)
	}
	if cerr.Reason != want {
		t.Fatalf("Load: reason\n got: %q\nwant: %q", cerr.Reason, want)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("Load: reason is not one line: %q", err.Error())
	}
}

func TestLoadValidBaseline(t *testing.T) {
	cfg := mustLoad(t, baseEnv(t))
	if cfg.Profile != "read-only" || cfg.Transport != "http" || cfg.Bind != "127.0.0.1" ||
		cfg.Port != 8080 || cfg.Path != "/mcp" || cfg.AuthMode != "bearer" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Name != "app-host" || cfg.Targets[0].Port != 22 {
		t.Fatalf("single target not built: %+v", cfg.Targets)
	}
	if cfg.ApprovalTTL != 120*time.Second || cfg.SSHMaxSessions != 4 || cfg.MaxOutputBytes != 262144 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.Token.Len() != len(testToken) {
		t.Fatalf("token length = %d", cfg.Token.Len())
	}
}

// --- SECURITY §6 server rules, one test each -------------------------------

func TestRuleBearerWithoutToken(t *testing.T) {
	env := baseEnv(t)
	delete(env, "SHELL_MCP_TOKEN")
	wantReason(t, env, "SHELL_MCP_AUTH_MODE=bearer requires SHELL_MCP_TOKEN or SHELL_MCP_TOKEN_FILE")
}

func TestRuleBearerShortToken(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_TOKEN"] = strings.Repeat("a", 42)
	wantReason(t, env, "SHELL_MCP_TOKEN must be at least 43 characters (got 42)")
}

func TestRuleNoneOverHTTPWithoutAllow(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_AUTH_MODE"] = "none"
	wantReason(t, env, "SHELL_MCP_AUTH_MODE=none over HTTP requires SHELL_MCP_ALLOW_UNAUTHENTICATED=true")
}

func TestRuleNoneOverHTTPNonLoopback(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "192.0.2.10", "::"} {
		t.Run(bind, func(t *testing.T) {
			env := baseEnv(t)
			env["SHELL_MCP_AUTH_MODE"] = "none"
			env["SHELL_MCP_ALLOW_UNAUTHENTICATED"] = "true"
			env["SHELL_MCP_BIND"] = bind
			wantReason(t, env, fmt.Sprintf("SHELL_MCP_AUTH_MODE=none over HTTP requires SHELL_MCP_BIND=127.0.0.1 or ::1 (got %q)", bind))
		})
	}
}

func TestRuleNoneOverHTTPLoopbackAccepted(t *testing.T) {
	for _, bind := range []string{"127.0.0.1", "::1"} {
		env := baseEnv(t)
		delete(env, "SHELL_MCP_TOKEN")
		env["SHELL_MCP_AUTH_MODE"] = "none"
		env["SHELL_MCP_ALLOW_UNAUTHENTICATED"] = "true"
		env["SHELL_MCP_BIND"] = bind
		mustLoad(t, env)
	}
}

func TestRuleNoTargets(t *testing.T) {
	env := baseEnv(t)
	for _, k := range []string{"SHELL_MCP_TARGET_NAME", "SHELL_MCP_TARGET_HOST", "SHELL_MCP_TARGET_USER", "SHELL_MCP_TARGET_HOST_KEYS"} {
		delete(env, k)
	}
	wantReason(t, env, "no targets configured: set SHELL_MCP_TARGETS_FILE or the SHELL_MCP_TARGET_* variables")
}

func TestRuleTargetsFileAndSingleTarget(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_TARGETS_FILE"] = writeFile(t, "targets.yaml", validTargetsYAML(t, ""), 0o600)
	wantReason(t, env, "SHELL_MCP_TARGETS_FILE and the single-target variables (SHELL_MCP_TARGET_*) are mutually exclusive")
}

func TestRuleTargetWithoutHostKey(t *testing.T) {
	env := baseEnv(t)
	delete(env, "SHELL_MCP_TARGET_HOST_KEYS")
	wantReason(t, env, `target "app-host": no pinned host key`)
}

func TestRuleTargetBadFingerprint(t *testing.T) {
	for _, fp := range []string{
		"MD5:aa:bb",
		"SHA256:",
		"SHA256:not base64!",
		"SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 20)), // wrong length
		"sha256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
	} {
		t.Run(fp, func(t *testing.T) {
			env := baseEnv(t)
			env["SHELL_MCP_TARGET_HOST_KEYS"] = testFingerprint + "," + fp
			wantReason(t, env, fmt.Sprintf(`target "app-host": host key %q is not a SHA256:<base64> fingerprint`, fp))
		})
	}
}

func TestRuleTargetWithoutKey(t *testing.T) {
	env := baseEnv(t)
	delete(env, "SHELL_MCP_SSH_KEY")
	wantReason(t, env, `target "app-host": no SSH private key (set SHELL_MCP_SSH_KEY, SHELL_MCP_SSH_KEY_FILE or key_file)`)
}

func TestRuleKeyNotEd25519(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	env := baseEnv(t)
	env["SHELL_MCP_SSH_KEY"] = string(pem.EncodeToMemory(block))
	wantReason(t, env, "SHELL_MCP_SSH_KEY: private key is not Ed25519")
}

func TestRuleKeyPassphraseProtected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("invented-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	env := baseEnv(t)
	env["SHELL_MCP_SSH_KEY"] = string(pem.EncodeToMemory(block))
	wantReason(t, env, "SHELL_MCP_SSH_KEY: private key is passphrase-protected and no passphrase source is supported")
}

func TestRuleKeyUnparsable(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_SSH_KEY"] = "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----\n"
	wantReason(t, env, "SHELL_MCP_SSH_KEY: private key cannot be parsed")
}

func TestRuleDefaultTargetUnknown(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_DEFAULT_TARGET"] = "other-host"
	wantReason(t, env, `SHELL_MCP_DEFAULT_TARGET names unknown target "other-host"`)
}

func TestRuleRedactPatternDoesNotCompile(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_REDACT_PATTERNS"] = "token=[A-Za-z0-9]{20,}\nbroken(["
	wantReason(t, env, "SHELL_MCP_REDACT_PATTERNS: pattern 2 does not compile: error parsing regexp: missing closing ]: `[`")
}

func TestRuleStdioWithBearer(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_TRANSPORT"] = "stdio"
	wantReason(t, env, "SHELL_MCP_TRANSPORT=stdio requires SHELL_MCP_AUTH_MODE=none (bearer has no meaning over stdio)")
}

func TestRuleStdioWithNoneAccepted(t *testing.T) {
	env := baseEnv(t)
	delete(env, "SHELL_MCP_TOKEN")
	env["SHELL_MCP_TRANSPORT"] = "stdio"
	env["SHELL_MCP_AUTH_MODE"] = "none"
	mustLoad(t, env)
}

func TestRuleApprovalTiersWithoutDestructive(t *testing.T) {
	for _, v := range []string{"operator", "", " "} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVAL_TIERS"] = v
		wantReason(t, env, "SHELL_MCP_APPROVAL_TIERS must include destructive")
	}
}

func TestRuleApprovalTiersUnknown(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_TIERS"] = "read,destructive"
	wantReason(t, env, `SHELL_MCP_APPROVAL_TIERS: unknown tier "read" (allowed: operator, destructive)`)
}

func TestRuleApprovalTiersAccepted(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_TIERS"] = "operator,destructive"
	cfg := mustLoad(t, env)
	if strings.Join(cfg.ApprovalTiers, ",") != "operator,destructive" {
		t.Fatalf("ApprovalTiers = %v", cfg.ApprovalTiers)
	}
}

func TestRuleApprovalFallbackUnknown(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_FALLBACK"] = "allow"
	wantReason(t, env, `SHELL_MCP_APPROVAL_FALLBACK must be deny or confirm-argument (got "allow")`)
}

func TestRuleApprovalTTLOutOfRange(t *testing.T) {
	for _, v := range []string{"29", "601", "0", "-5"} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVAL_TTL"] = v
		wantReason(t, env, fmt.Sprintf("SHELL_MCP_APPROVAL_TTL must be between 30 and 600 seconds (got %s)", v))
	}
	for _, v := range []string{"30", "600"} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVAL_TTL"] = v
		mustLoad(t, env)
	}
}

// --- Approval defaults and warnings ---------------------------------------

func TestApprovalDefaults(t *testing.T) {
	cfg := mustLoad(t, baseEnv(t))
	if cfg.ApprovalFallback != "deny" {
		t.Fatalf("ApprovalFallback default = %q, want deny", cfg.ApprovalFallback)
	}
	if strings.Join(cfg.ApprovalTiers, ",") != "destructive" {
		t.Fatalf("ApprovalTiers default = %v, want [destructive]", cfg.ApprovalTiers)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "APPROVAL_FALLBACK") {
			t.Fatalf("unexpected fallback warning with default config: %q", w)
		}
	}
}

func TestApprovalFallbackConfirmArgumentWarns(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_FALLBACK"] = "confirm-argument"
	cfg := mustLoad(t, env)
	if !containsWarning(cfg, "SHELL_MCP_APPROVAL_FALLBACK=confirm-argument") {
		t.Fatalf("no WARN for confirm-argument fallback: %v", cfg.Warnings)
	}
}

func containsWarning(cfg *Config, sub string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// --- *_FILE handling --------------------------------------------------------

func TestFileVariableWinsOverPlain(t *testing.T) {
	fileToken := strings.Repeat("f", 50)
	env := baseEnv(t)
	env["SHELL_MCP_TOKEN"] = testToken
	env["SHELL_MCP_TOKEN_FILE"] = writeFile(t, "token", fileToken, 0o600)
	cfg := mustLoad(t, env)
	if cfg.Token.Len() != 50 {
		t.Fatalf("token from file not preferred: len %d", cfg.Token.Len())
	}

	k := newEd25519Key(t)
	env["SHELL_MCP_SSH_KEY"] = "garbage that would not parse"
	env["SHELL_MCP_SSH_KEY_FILE"] = writeFile(t, "key", k.pem, 0o600)
	mustLoad(t, env)
}

func TestFileTrailingNewlineStripped(t *testing.T) {
	tok := strings.Repeat("n", 43)
	for _, content := range []string{tok + "\n", tok + "\r\n"} {
		env := baseEnv(t)
		delete(env, "SHELL_MCP_TOKEN")
		env["SHELL_MCP_TOKEN_FILE"] = writeFile(t, "token", content, 0o600)
		cfg := mustLoad(t, env)
		if cfg.Token.Len() != 43 {
			t.Fatalf("newline not stripped: len %d", cfg.Token.Len())
		}
	}
}

func TestFileOnlyOneTrailingNewlineStripped(t *testing.T) {
	// 42 characters plus two newlines: stripping only one leaves 43 bytes, so
	// the token would pass; stripping both would make it too short. The
	// token is then compared including the remaining newline.
	tok := strings.Repeat("n", 42) + "\n\n"
	env := baseEnv(t)
	delete(env, "SHELL_MCP_TOKEN")
	env["SHELL_MCP_TOKEN_FILE"] = writeFile(t, "token", tok, 0o600)
	cfg := mustLoad(t, env)
	if cfg.Token.Len() != 43 {
		t.Fatalf("want exactly one newline stripped (len 43), got %d", cfg.Token.Len())
	}
}

func TestFileUnreadable(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_TOKEN_FILE"] = filepath.Join(t.TempDir(), "missing")
	wantReason(t, env, "SHELL_MCP_TOKEN_FILE: cannot read file")
}

func TestSecretFileReadableByOthersWarns(t *testing.T) {
	env := baseEnv(t)
	delete(env, "SHELL_MCP_TOKEN")
	p := writeFile(t, "token", testToken, 0o644)
	env["SHELL_MCP_TOKEN_FILE"] = p
	cfg := mustLoad(t, env)
	if !containsWarning(cfg, "SHELL_MCP_TOKEN_FILE is readable by group or other") {
		t.Fatalf("no WARN for group/other-readable secret file: %v", cfg.Warnings)
	}
}

// --- Targets file -----------------------------------------------------------

func validTargetsYAML(t *testing.T, extra string) string {
	t.Helper()
	keyPath := writeFile(t, "key", newEd25519Key(t).pem, 0o600)
	return fmt.Sprintf(`targets:
  - name: app-host
    host: target-a.example.test
    port: 2222
    user: svc-shell
    host_keys: [%q]
    key_file: %s
%s`, testFingerprint, keyPath, extra)
}

func targetsEnv(t *testing.T, yaml string) map[string]string {
	t.Helper()
	return map[string]string{
		"SHELL_MCP_TOKEN":        testToken,
		"SHELL_MCP_TARGETS_FILE": writeFile(t, "targets.yaml", yaml, 0o600),
	}
}

func TestTargetsFileValid(t *testing.T) {
	cfg := mustLoad(t, targetsEnv(t, validTargetsYAML(t, "")))
	if len(cfg.Targets) != 1 || cfg.Targets[0].Port != 2222 || cfg.Targets[0].User != "svc-shell" {
		t.Fatalf("targets = %+v", cfg.Targets)
	}
}

func TestTargetsFileUnknownField(t *testing.T) {
	y := validTargetsYAML(t, "    password: hunter2\n")
	_, err := Load(lookupFrom(targetsEnv(t, y)))
	var cerr *Error
	if !errors.As(err, &cerr) || !strings.HasPrefix(cerr.Reason, "SHELL_MCP_TARGETS_FILE: ") ||
		!strings.Contains(cerr.Reason, `field password not found`) {
		t.Fatalf("unknown field not rejected: %v", err)
	}
}

func TestTargetsFileUnknownTopLevelField(t *testing.T) {
	y := validTargetsYAML(t, "defaults: {}\n")
	_, err := Load(lookupFrom(targetsEnv(t, y)))
	var cerr *Error
	if !errors.As(err, &cerr) || !strings.Contains(cerr.Reason, `field defaults not found`) {
		t.Fatalf("unknown top-level field not rejected: %v", err)
	}
}

func TestTargetsFileDuplicateKey(t *testing.T) {
	y := validTargetsYAML(t, "    host: target-b.example.test\n")
	_, err := Load(lookupFrom(targetsEnv(t, y)))
	var cerr *Error
	if !errors.As(err, &cerr) || !strings.HasPrefix(cerr.Reason, "SHELL_MCP_TARGETS_FILE: ") ||
		!strings.Contains(cerr.Reason, `mapping key "host" already defined`) {
		t.Fatalf("duplicate key not rejected: %v", err)
	}
	if strings.Contains(cerr.Reason, "\n") {
		t.Fatalf("reason is not one line: %q", cerr.Reason)
	}
}

func TestTargetsFileDuplicateTargetName(t *testing.T) {
	keyPath := writeFile(t, "key2", newEd25519Key(t).pem, 0o600)
	extra := fmt.Sprintf("  - name: app-host\n    host: target-b.example.test\n    user: svc-shell\n    host_keys: [%q]\n    key_file: %s\n", testFingerprint, keyPath)
	wantReason(t, targetsEnv(t, validTargetsYAML(t, extra)), `SHELL_MCP_TARGETS_FILE: duplicate target name "app-host"`)
}

func TestTargetsFileMultipleDocuments(t *testing.T) {
	y := validTargetsYAML(t, "---\ntargets: []\n")
	wantReason(t, targetsEnv(t, y), "SHELL_MCP_TARGETS_FILE: must contain exactly one YAML document")
}

func TestTargetsFileEmptyList(t *testing.T) {
	wantReason(t, targetsEnv(t, "targets: []\n"), "no targets configured: set SHELL_MCP_TARGETS_FILE or the SHELL_MCP_TARGET_* variables")
}

// --- Masking ----------------------------------------------------------------

func TestEffectiveNeverContainsSecrets(t *testing.T) {
	k := newEd25519Key(t)
	env := baseEnv(t)
	env["SHELL_MCP_SSH_KEY"] = k.pem
	cfg := mustLoad(t, env)

	eff, err := json.Marshal(cfg.Effective())
	if err != nil {
		t.Fatal(err)
	}
	dumps := []string{
		string(eff),
		fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg),
		fmt.Sprintf("%v", *cfg), fmt.Sprintf("%+v", *cfg), fmt.Sprintf("%#v", *cfg),
		fmt.Sprintf("%s %q %x", cfg.Token, cfg.Token, cfg.Token),
	}
	if b, err := json.Marshal(cfg); err == nil {
		dumps = append(dumps, string(b))
	}
	secrets := assertSecretsAbsentList(k)
	for i, d := range dumps {
		for _, s := range secrets {
			if strings.Contains(d, s) {
				t.Fatalf("dump %d contains secret material %q", i, s)
			}
		}
	}

	var got map[string]any
	if err := json.Unmarshal(eff, &got); err != nil {
		t.Fatal(err)
	}
	if got["token_length"] != float64(len(testToken)) {
		t.Fatalf("token_length = %v", got["token_length"])
	}
	fp := cfg.Targets[0].Key.Fingerprint()
	if !strings.HasPrefix(fp, "SHA256:") || !strings.Contains(string(eff), fp) {
		t.Fatalf("effective config does not show key fingerprint %q: %s", fp, eff)
	}
}

func assertSecretsAbsentList(k testKey) []string {
	body := strings.Join(strings.Split(strings.TrimSpace(k.pem), "\n")[1:], "")
	body = strings.TrimSuffix(body, "-----END OPENSSH PRIVATE KEY-----")
	return []string{
		testToken,
		body[:40],
		string(k.seed),
		base64.StdEncoding.EncodeToString(k.seed),
		fmt.Sprintf("%x", k.seed),
		fmt.Sprintf("%v", k.seed)[:30],
	}
}

func TestBindMustBeIPAddress(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_BIND"] = "localhost"
	wantReason(t, env, `SHELL_MCP_BIND must be an IP address (got "localhost")`)
}
