package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
)

// Approval configuration (docs/handoff/S4B-APPROVAL.md §6.7). Every URL,
// address and name is an invented fixture; seeds and keys are generated at
// test time.

func testSeed(t *testing.T) string {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return approvers.EncodeSeed(b)
}

// needStrictModes skips where a file mode cannot be made private (the
// approvers file must not be group/other-accessible; Windows has no such
// mode and fails closed).
func needStrictModes(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
}

// webEnv is a valid web-method configuration on loopback.
func webEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	needStrictModes(t)
	s := testSeed(t)
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_METHOD"] = "web"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "http://127.0.0.1:8081"
	env["SHELL_MCP_APPROVERS_FILE"] = writeFile(t, "approvers", "alice "+s+"\n", 0o600)
	return env, s
}

func TestApprovalDefaults(t *testing.T) {
	cfg := mustLoad(t, baseEnv(t))
	if cfg.ApprovalMethod != "none" || cfg.ApprovalTTL != 300*time.Second || strings.Join(cfg.ApprovalTiers, ",") != "destructive" ||
		cfg.ApprovalBind != "127.0.0.1" || cfg.ApprovalPort != 8081 || cfg.ApprovalMaxApprovers != 1 {
		t.Fatalf("defaults: method %q ttl %s tiers %v bind %q port %d max %d", cfg.ApprovalMethod, cfg.ApprovalTTL,
			cfg.ApprovalTiers, cfg.ApprovalBind, cfg.ApprovalPort, cfg.ApprovalMaxApprovers)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "APPROVAL") {
			t.Fatalf("unexpected warning: %q", w)
		}
	}
}

func TestRuleApprovalMethodUnknown(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_METHOD"] = "deny"
	wantReason(t, env, `SHELL_MCP_APPROVAL_METHOD must be one of none, web, confirm-argument (got "deny")`)
}

func TestRuleApprovalFallbackRefused(t *testing.T) {
	for _, v := range []string{"deny", "confirm-argument", ""} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVAL_FALLBACK"] = v
		wantReason(t, env, "SHELL_MCP_APPROVAL_FALLBACK was replaced by SHELL_MCP_APPROVAL_METHOD (none, web or confirm-argument)")
	}
}

func TestRuleApproversVariableRefused(t *testing.T) {
	for _, v := range []string{"alice " + testSeed(t), ""} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVERS"] = v
		wantReason(t, env, "SHELL_MCP_APPROVERS is not accepted: approvers live only in a mounted secret file (SHELL_MCP_APPROVERS_FILE)")
	}
}

func TestRuleApprovalTTLOutOfRange(t *testing.T) {
	for _, v := range []string{"59", "901", "0", "-5", "300s", "1e3"} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVAL_TTL"] = v
		wantReason(t, env, fmt.Sprintf("SHELL_MCP_APPROVAL_TTL must be between 60 and 900 seconds (got %s)", v))
	}
	for _, v := range []string{"60", "900"} {
		env := baseEnv(t)
		env["SHELL_MCP_APPROVAL_TTL"] = v
		mustLoad(t, env)
	}
}

func TestConfirmArgumentWarns(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_METHOD"] = "confirm-argument"
	cfg := mustLoad(t, env)
	if cfg.ApprovalMethod != "confirm-argument" ||
		!containsWarning(cfg, "SHELL_MCP_APPROVAL_METHOD=confirm-argument: the model approves its own requests; human approval is not enforced") {
		t.Fatalf("method %q warnings %v", cfg.ApprovalMethod, cfg.Warnings)
	}
}

func TestWebValid(t *testing.T) {
	env, s := webEnv(t)
	cfg := mustLoad(t, env)
	if cfg.ApprovalMethod != "web" || cfg.ApprovalPublicURL != "http://127.0.0.1:8081" || len(cfg.Approvers) != 1 ||
		cfg.Approvers[0].Name != "alice" || approvers.EncodeSeed(cfg.Approvers[0].Seed()) != s {
		t.Fatalf("web config: %+v", cfg)
	}
	// The seed never appears in the effective configuration.
	b, _ := json.Marshal(cfg.Effective())
	if strings.Contains(string(b), s) || strings.Contains(fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), s) {
		t.Fatalf("seed in output: %s", b)
	}
	for _, want := range []string{`"approval_method":"web"`, `"approval_public_url":"http://127.0.0.1:8081"`, `"approvers":["alice"]`,
		`"approval_bind":"127.0.0.1"`, `"approval_port":8081`, `"approval_tls":false`, `"approval_notify":false`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("effective config lacks %s: %s", want, b)
		}
	}
	if strings.Contains(string(b), "approval_fallback") {
		t.Fatalf("effective config still has the fallback: %s", b)
	}
}

func TestWebPublicURLNormalised(t *testing.T) {
	env, _ := webEnv(t)
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "HTTPS://Approve.Example.Test/"
	if cfg := mustLoad(t, env); cfg.ApprovalPublicURL != "https://approve.example.test" {
		t.Fatalf("public URL %q", cfg.ApprovalPublicURL)
	}
}

func TestRuleWebRequiresPublicURLAndApprovers(t *testing.T) {
	env, _ := webEnv(t)
	delete(env, "SHELL_MCP_APPROVAL_PUBLIC_URL")
	wantReason(t, env, "SHELL_MCP_APPROVAL_METHOD=web requires SHELL_MCP_APPROVAL_PUBLIC_URL")
	env, _ = webEnv(t)
	delete(env, "SHELL_MCP_APPROVERS_FILE")
	wantReason(t, env, "SHELL_MCP_APPROVAL_METHOD=web requires SHELL_MCP_APPROVERS_FILE")
}

const publicURLReason = "SHELL_MCP_APPROVAL_PUBLIC_URL must be an absolute https:// URL with no userinfo, path, query or fragment " +
	"(http:// only with a loopback host and a loopback SHELL_MCP_APPROVAL_BIND)"

func TestRuleWebPublicURL(t *testing.T) {
	for _, bad := range []string{
		"approve.example.test", "ftp://approve.example.test", "https://", "https://user@approve.example.test",
		"https://approve.example.test/approvals", "https://approve.example.test/?x=1", "https://approve.example.test/#f",
		"http://approve.example.test", "http://192.0.2.10:8081", "https://approve.example.test:0", "https://approve.example.test:99999",
		"https://" + strings.Repeat("a", 250) + ".example.test",
	} {
		env, _ := webEnv(t)
		env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = bad
		wantReason(t, env, publicURLReason)
	}
	// http with a loopback host but a non-loopback bind.
	env, _ := webEnv(t)
	env["SHELL_MCP_APPROVAL_BIND"] = "0.0.0.0"
	env["SHELL_MCP_TRUSTED_PROXIES"] = "192.0.2.5"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "http://127.0.0.1:8081"
	wantReason(t, env, publicURLReason)
	for _, good := range []string{"https://approve.example.test", "https://approve.example.test:8443", "http://[::1]:8081", "http://localhost:8081"} {
		env, _ := webEnv(t)
		env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = good
		mustLoad(t, env)
	}
}

func TestRuleApproversFile(t *testing.T) {
	needStrictModes(t)
	s1, s2 := testSeed(t), testSeed(t)
	for name, c := range map[string]struct {
		content string
		mode    os.FileMode
		max     string
		reason  string
	}{
		"group-readable": {"alice " + s1 + "\n", 0o640, "", "SHELL_MCP_APPROVERS_FILE: approvers file: accessible by group or other (mode 0640); it must be 0600 or stricter"},
		"other-readable": {"alice " + s1 + "\n", 0o604, "", "SHELL_MCP_APPROVERS_FILE: approvers file: accessible by group or other (mode 0604); it must be 0600 or stricter"},
		"unparsable":     {"alice\n", 0o600, "", "SHELL_MCP_APPROVERS_FILE: approvers file: "},
		"short seed":     {"alice " + approvers.EncodeSeed(make([]byte, 16)) + "\n", 0o600, "", "SHELL_MCP_APPROVERS_FILE: approvers file: "},
		"duplicate":      {"alice " + s1 + "\nalice " + s2 + "\n", 0o600, "8", "SHELL_MCP_APPROVERS_FILE: approvers file: "},
		"empty":          {"", 0o600, "", "SHELL_MCP_APPROVERS_FILE: approvers file: "},
		"two, max 1":     {"alice " + s1 + "\nbob " + s2 + "\n", 0o600, "", "SHELL_MCP_APPROVERS_FILE: approvers file: the file holds 2 approvers, more than SHELL_MCP_APPROVAL_MAX_APPROVERS (1)"},
		"bad max":        {"alice " + s1 + "\n", 0o600, "9", `SHELL_MCP_APPROVAL_MAX_APPROVERS must be an integer between 1 and 8 (got "9")`},
	} {
		t.Run(name, func(t *testing.T) {
			env, _ := webEnv(t)
			env["SHELL_MCP_APPROVERS_FILE"] = writeFile(t, "approvers", c.content, c.mode)
			if c.max != "" {
				env["SHELL_MCP_APPROVAL_MAX_APPROVERS"] = c.max
			}
			_, err := Load(lookupFrom(env))
			if err == nil || !strings.HasPrefix(err.Error(), c.reason) {
				t.Fatalf("error %v, want prefix %q", err, c.reason)
			}
			for _, s := range []string{s1, s2} {
				if strings.Contains(err.Error(), s) {
					t.Fatal("the reason carries a seed")
				}
			}
		})
	}
	// Two approvers with the maximum raised.
	env, _ := webEnv(t)
	env["SHELL_MCP_APPROVERS_FILE"] = writeFile(t, "approvers", "alice "+s1+"\nbob "+s2+"\n", 0o600)
	env["SHELL_MCP_APPROVAL_MAX_APPROVERS"] = "2"
	if cfg := mustLoad(t, env); len(cfg.Approvers) != 2 || cfg.ApprovalMaxApprovers != 2 {
		t.Fatalf("approvers %v", cfg.Approvers)
	}
	env, _ = webEnv(t)
	env["SHELL_MCP_APPROVERS_FILE"] = "/nonexistent/approvers"
	if _, err := Load(lookupFrom(env)); err == nil || !strings.HasPrefix(err.Error(), "SHELL_MCP_APPROVERS_FILE: approvers file: cannot read file") {
		t.Fatalf("missing file: %v", err)
	}
}

func TestRuleApprovalListener(t *testing.T) {
	env, _ := webEnv(t)
	env["SHELL_MCP_APPROVAL_BIND"] = "approve.example.test"
	wantReason(t, env, `SHELL_MCP_APPROVAL_BIND must be an IP address (got "approve.example.test")`)

	env, _ = webEnv(t)
	env["SHELL_MCP_APPROVAL_PORT"] = "8080"
	wantReason(t, env, "SHELL_MCP_APPROVAL_PORT must differ from SHELL_MCP_PORT (both 8080)")

	env, _ = webEnv(t)
	env["SHELL_MCP_APPROVAL_PORT"] = "70000"
	wantReason(t, env, `SHELL_MCP_APPROVAL_PORT must be an integer between 1 and 65535 (got "70000")`)

	for _, bind := range []string{"0.0.0.0", "192.0.2.10", "::"} {
		env, _ = webEnv(t)
		env["SHELL_MCP_APPROVAL_BIND"] = bind
		env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "https://approve.example.test"
		wantReason(t, env, "SHELL_MCP_APPROVAL_BIND="+bind+" is not loopback: set SHELL_MCP_APPROVAL_TLS_CERT_FILE and SHELL_MCP_APPROVAL_TLS_KEY_FILE, "+
			"or SHELL_MCP_TRUSTED_PROXIES naming the TLS-terminating proxy")
	}
	// A trusted proxy makes a non-loopback bind acceptable.
	env, _ = webEnv(t)
	env["SHELL_MCP_APPROVAL_BIND"] = "0.0.0.0"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "https://approve.example.test"
	env["SHELL_MCP_TRUSTED_PROXIES"] = "192.0.2.5"
	mustLoad(t, env)
}

func writeTLSPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "approve.example.test"},
		DNSNames: []string{"approve.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644),
		writeFile(t, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})), 0o600)
}

func TestApprovalTLS(t *testing.T) {
	cert, key := writeTLSPair(t)
	env, _ := webEnv(t)
	env["SHELL_MCP_APPROVAL_BIND"] = "0.0.0.0"
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "https://approve.example.test"
	env["SHELL_MCP_APPROVAL_TLS_CERT_FILE"] = cert
	env["SHELL_MCP_APPROVAL_TLS_KEY_FILE"] = key
	cfg := mustLoad(t, env)
	if cfg.ApprovalTLSCert == nil {
		t.Fatal("no certificate loaded")
	}
	b, _ := json.Marshal(cfg.Effective())
	if !strings.Contains(string(b), `"approval_tls":true`) || strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatalf("effective: %s", b)
	}

	for _, missing := range []string{"SHELL_MCP_APPROVAL_TLS_CERT_FILE", "SHELL_MCP_APPROVAL_TLS_KEY_FILE"} {
		e := map[string]string{}
		for k, v := range env {
			e[k] = v
		}
		delete(e, missing)
		wantReason(t, e, "SHELL_MCP_APPROVAL_TLS_CERT_FILE and SHELL_MCP_APPROVAL_TLS_KEY_FILE must be set together")
	}
	e := map[string]string{}
	for k, v := range env {
		e[k] = v
	}
	e["SHELL_MCP_APPROVAL_TLS_KEY_FILE"] = cert
	wantReason(t, e, "SHELL_MCP_APPROVAL_TLS_CERT_FILE / SHELL_MCP_APPROVAL_TLS_KEY_FILE: cannot load the certificate and key")
	e["SHELL_MCP_APPROVAL_TLS_KEY_FILE"] = "/nonexistent/key.pem"
	wantReason(t, e, "SHELL_MCP_APPROVAL_TLS_CERT_FILE / SHELL_MCP_APPROVAL_TLS_KEY_FILE: cannot load the certificate and key")

	// TLS with an http public URL cannot work.
	env2, _ := webEnv(t)
	env2["SHELL_MCP_APPROVAL_TLS_CERT_FILE"] = cert
	env2["SHELL_MCP_APPROVAL_TLS_KEY_FILE"] = key
	wantReason(t, env2, "SHELL_MCP_APPROVAL_PUBLIC_URL must be https:// when the approval listener serves TLS")
}

func TestApprovalNotify(t *testing.T) {
	env, _ := webEnv(t)
	env["SHELL_MCP_APPROVAL_NOTIFY_URL"] = "https://ntfy.example.test/approvals"
	wantReason(t, env, "SHELL_MCP_APPROVAL_NOTIFY_URL requires SHELL_MCP_APPROVAL_NOTIFY_TOKEN or SHELL_MCP_APPROVAL_NOTIFY_TOKEN_FILE")

	tok := "tk_" + strings.Repeat("n", 30)
	env["SHELL_MCP_APPROVAL_NOTIFY_TOKEN_FILE"] = writeFile(t, "notify", tok+"\n", 0o600)
	cfg := mustLoad(t, env)
	if cfg.ApprovalNotifyURL != "https://ntfy.example.test/approvals" || !cfg.ApprovalNotifyToken.Equal(tok) {
		t.Fatalf("notify %q", cfg.ApprovalNotifyURL)
	}
	b, _ := json.Marshal(cfg.Effective())
	if strings.Contains(string(b), tok) || !strings.Contains(string(b), `"approval_notify":true`) {
		t.Fatalf("effective: %s", b)
	}
	for _, bad := range []string{"http://ntfy.example.test/approvals", "https://ntfy.example.test/", "https://u:p@ntfy.example.test/approvals"} {
		env["SHELL_MCP_APPROVAL_NOTIFY_URL"] = bad
		if _, err := Load(lookupFrom(env)); err == nil || !strings.HasPrefix(err.Error(), "SHELL_MCP_APPROVAL_NOTIFY_URL: ") {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	env["SHELL_MCP_APPROVAL_NOTIFY_URL"] = "http://127.0.0.1:8090/approvals"
	mustLoad(t, env)
}

func TestWebSettingsIgnoredWarnsOutsideWeb(t *testing.T) {
	env := baseEnv(t)
	env["SHELL_MCP_APPROVAL_PUBLIC_URL"] = "https://approve.example.test"
	cfg := mustLoad(t, env)
	if !containsWarning(cfg, "SHELL_MCP_APPROVAL_PUBLIC_URL, SHELL_MCP_APPROVERS_FILE and the other approval page settings are ignored unless SHELL_MCP_APPROVAL_METHOD=web") {
		t.Fatalf("warnings %v", cfg.Warnings)
	}
}
