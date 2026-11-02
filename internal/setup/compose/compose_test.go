package compose_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/setup/compose"
)

// Invented values (TEST-NET addresses, a low-entropy digest and pins); the
// golden files under testdata were produced from deploy/docker-compose.yml
// by an independent string-replacement script, not by this package.
const (
	digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pin1   = "ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	pin2   = "ecdsa-sha2-nistp256 SHA256:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"
	image3 = "ghcr.io/tyler-rich/shell-mcp:0.3.0@sha256:" + digest
)

func deployFile(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTemplateIsDeployFile(t *testing.T) {
	if !bytes.Equal(compose.Template(), deployFile(t)) {
		t.Fatal("internal/setup/compose/docker-compose.yml differs from deploy/docker-compose.yml: copy the file again (it is the template, byte for byte)")
	}
}

func TestReferenceReproducesDeployFile(t *testing.T) {
	ref := compose.Reference()
	got, err := compose.Render(&ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, deployFile(t)) {
		t.Fatalf("rendering the reference values does not reproduce deploy/docker-compose.yml:\n%s", got)
	}
}

func base(extra ...string) []string {
	return append([]string{"--image", image3, "--host-key", pin1, "--target-name", "app-host", "--target-host", "target-a.example.test",
		"--mcp-host", "mcp.example.test", "--subnet", "192.0.2.0/24", "--server-addr", "192.0.2.10", "--proxy-addr", "192.0.2.5"}, extra...)
}

type goldenCase struct {
	file string
	args []string
}

var goldenCases = []goldenCase{
	{"secrets.golden.yml", base()},
	{"secrets-approvals.golden.yml", []string{"--image", image3, "--host-key", pin1, "--host-key", pin2, "--target-name", "target-a",
		"--target-host", "target-a.example.test", "--mcp-host", "mcp.example.test", "--subnet", "192.0.2.0/24", "--server-addr", "192.0.2.10",
		"--proxy-addr", "192.0.2.5", "--profile", "operator", "--approve-host", "approve.example.test", "--form", "secrets"}},
	{"bind.golden.yml", []string{"--form", "bind", "--dir", "/srv/shell-mcp/secrets", "--image", "ghcr.io/tyler-rich/shell-mcp@sha256:" + digest,
		"--host-key", pin1, "--target-name", "app-host", "--target-host", "192.0.2.20", "--target-user", "svc-shell", "--mcp-host", "mcp.example.test",
		"--subnet", "198.51.100.0/24", "--server-addr", "198.51.100.10", "--proxy-addr", "198.51.100.5"}},
	{"bind-approvals.golden.yml", []string{"--image", image3, "--host-key", pin1, "--host-key", pin2, "--target-name", "target-a",
		"--target-host", "target-a.example.test", "--mcp-host", "mcp.example.test", "--subnet", "192.0.2.0/24", "--server-addr", "192.0.2.10",
		"--proxy-addr", "192.0.2.5", "--profile", "admin", "--approve-host", "approve.example.test", "--form", "bind", "--dir", "/srv/shell-mcp/secrets"}},
}

func render(t testing.TB, args []string) []byte {
	t.Helper()
	v, err := compose.ParseFlags(args)
	if err != nil {
		t.Fatalf("ParseFlags(%q): %v", args, err)
	}
	if _, err := v.Check(); err != nil {
		t.Fatalf("Check(%q): %v", args, err)
	}
	out, err := compose.Render(v)
	if err != nil {
		t.Fatalf("Render(%q): %v", args, err)
	}
	return out
}

func TestGolden(t *testing.T) {
	for _, c := range goldenCases {
		t.Run(c.file, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := render(t, c.args); !bytes.Equal(got, want) {
				t.Fatalf("output differs from testdata/%s:\n%s", c.file, got)
			}
		})
	}
}

// doc is the part of a compose file the tests read.
type doc struct {
	Services map[string]map[string]any `yaml:"services"`
	Networks map[string]any            `yaml:"networks"`
	Secrets  map[string]map[string]any `yaml:"secrets"`
}

func parse(t testing.TB, b []byte) doc {
	t.Helper()
	var d doc
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("output is not a compose file: %v\n%s", err, b)
	}
	if len(d.Services) != 1 || d.Services["shell-mcp"] == nil {
		t.Fatalf("services: want exactly shell-mcp, got %v", d.Services)
	}
	return d
}

func env(t testing.TB, d doc) map[string]string {
	t.Helper()
	m, ok := d.Services["shell-mcp"]["environment"].(map[string]any)
	if !ok {
		t.Fatalf("environment is not a map: %#v", d.Services["shell-mcp"]["environment"])
	}
	out := map[string]string{}
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("environment %s is not a string: %#v", k, v)
		}
		out[k] = s
	}
	return out
}

// hardening are the normative keys (SECURITY §7) that are never parameters.
var hardening = []string{"user", "read_only", "cap_drop", "security_opt", "pids_limit", "deploy", "healthcheck", "logging", "restart"}

func TestHardeningKept(t *testing.T) {
	ref := parse(t, deployFile(t)).Services["shell-mcp"]
	for _, c := range goldenCases {
		t.Run(c.file, func(t *testing.T) {
			d := parse(t, render(t, c.args))
			svc := d.Services["shell-mcp"]
			for _, k := range hardening {
				if !reflect.DeepEqual(svc[k], ref[k]) {
					t.Errorf("%s: %#v, want the reference's %#v", k, svc[k], ref[k])
				}
			}
			if _, ok := svc["ports"]; ok {
				t.Error("a published port")
			}
			for _, k := range []string{"privileged", "cap_add", "network_mode", "pid", "devices"} {
				if _, ok := svc[k]; ok {
					t.Errorf("%s present", k)
				}
			}
			e := env(t, d)
			for k, v := range e {
				if !strings.HasPrefix(k, "SHELL_MCP_") {
					t.Errorf("variable %s", k)
				}
				if strings.HasSuffix(k, "_FILE") && !strings.HasPrefix(v, "/run/secrets/") {
					t.Errorf("%s=%s is not under /run/secrets", k, v)
				}
			}
			for _, k := range []string{"SHELL_MCP_TOKEN", "SHELL_MCP_SSH_KEY", "SHELL_MCP_APPROVERS", "SHELL_MCP_APPROVAL_FALLBACK"} {
				if _, ok := e[k]; ok {
					t.Errorf("%s: an environment-store form", k)
				}
			}
			bind := slices.Contains(c.args, "bind")
			if bind {
				if d.Secrets != nil || svc["secrets"] != nil {
					t.Errorf("bind form with secrets: %v %v", d.Secrets, svc["secrets"])
				}
				if want := []any{"/srv/shell-mcp/secrets:/run/secrets:ro"}; !reflect.DeepEqual(svc["volumes"], want) {
					t.Errorf("volumes %#v, want %#v", svc["volumes"], want)
				}
			} else {
				if svc["volumes"] != nil {
					t.Errorf("secrets form with volumes %#v", svc["volumes"])
				}
				for name, s := range d.Secrets {
					if s["file"] != "./secrets/"+name || len(s) != 1 {
						t.Errorf("secret %s: %v", name, s)
					}
				}
			}
		})
	}
}

// TestServerLoadsRendered runs the server's own configuration loader on each
// rendered environment, with the /run/secrets files replaced by test files.
func TestServerLoadsRendered(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "shell-mcp")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"/run/secrets/mcp_token": write("mcp_token", []byte(strings.Repeat("t", 43))),
		"/run/secrets/ssh_key":   write("ssh_key", pem.EncodeToMemory(blk)),
	}
	appr, err := approvers.Append(nil, "alice", bytes.Repeat([]byte{7}, approvers.MinSeedBytes), false)
	if err != nil {
		t.Fatal(err)
	}
	files["/run/secrets/approvers"] = write("approvers", appr)
	for _, c := range goldenCases {
		t.Run(c.file, func(t *testing.T) {
			e := env(t, parse(t, render(t, c.args)))
			for k, v := range e {
				if p, ok := files[v]; ok {
					e[k] = p
				}
			}
			cfg, err := config.Load(func(k string) (string, bool) { v, ok := e[k]; return v, ok })
			if err != nil {
				t.Fatalf("the server refuses the rendered configuration: %v", err)
			}
			if len(cfg.Targets) != 1 || len(cfg.TrustedProxies) != 1 {
				t.Fatalf("targets %d, trusted proxies %v", len(cfg.Targets), cfg.TrustedProxies)
			}
		})
	}
}

func TestVariablesInREADME(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	// A row's first cell names one variable or several ("`A` / `A_FILE`").
	cells := regexp.MustCompile("(?m)^\\| (`SHELL_MCP_[A-Z0-9_]+`(?: / `SHELL_MCP_[A-Z0-9_]+`)*) \\|").FindAllSubmatch(readme, -1)
	table := map[string]bool{}
	for _, c := range cells {
		for _, n := range regexp.MustCompile("SHELL_MCP_[A-Z0-9_]+").FindAll(c[1], -1) {
			table[string(n)] = true
		}
	}
	for _, c := range goldenCases {
		for k := range env(t, parse(t, render(t, c.args))) {
			if !table[k] {
				t.Errorf("%s: %s is not in README's configuration table", c.file, k)
			}
		}
	}
}

func replace(args []string, flag, value string) []string {
	out := slices.Clone(args)
	for i := range out {
		if out[i] == flag {
			out[i+1] = value
			return out
		}
	}
	return append(out, flag, value)
}

func drop(args []string, flag string) []string {
	out := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		usage bool
		want  string
	}{
		{"no image", drop(base(), "--image"), true, "--image"},
		{"tag alone", replace(base(), "--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0"), false, "@sha256:"},
		{"short digest", replace(base(), "--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0@sha256:0123"), false, "@sha256:"},
		{"upper-case digest", replace(base(), "--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0@sha256:"+strings.ToUpper(digest)), false, "@sha256:"},
		{"placeholder digest", replace(base(), "--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0@sha256:"+strings.Repeat("0", 64)), false, "placeholder"},
		{"placeholder text", replace(base(), "--image", "ghcr.io/tyler-rich/shell-mcp:0.3.0@sha256:<digest>"), false, "@sha256:"},
		{"no host key", drop(base(), "--host-key"), true, "--host-key"},
		{"bad pin", replace(base(), "--host-key", "ssh-ed25519 SHA256:placeholder"), false, "--host-key"},
		{"dsa pin", replace(base(), "--host-key", "ssh-dss SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), false, "--host-key"},
		{"duplicate pin", append(base(), "--host-key", pin1), false, "twice"},
		{"no target host", drop(base(), "--target-host"), true, "--target-host"},
		{"target host not a name", replace(base(), "--target-host", "target_a;rm"), false, "--target-host"},
		{"target name", replace(base(), "--target-name", "App Host"), false, "--target-name"},
		{"target user", replace(base(), "--target-user", "-root"), false, "--target-user"},
		{"mcp host an address", replace(base(), "--mcp-host", "192.0.2.30"), false, "--mcp-host"},
		{"mcp host not a name", replace(base(), "--mcp-host", "mcp..example.test"), false, "--mcp-host"},
		{"approve host not a name", append(base(), "--approve-host", "https://approve.example.test"), false, "--approve-host"},
		{"no subnet", drop(base(), "--subnet"), true, "--subnet"},
		{"subnet host bits", replace(base(), "--subnet", "192.0.2.1/24"), false, "--subnet"},
		{"subnet ipv6", replace(base(), "--subnet", "2001:db8::/64"), false, "--subnet"},
		{"subnet too wide", replace(base(), "--subnet", "10.0.0.0/8"), false, "--subnet"},
		{"subnet too narrow", replace(base(), "--subnet", "192.0.2.0/30"), false, "--subnet"},
		{"server outside", replace(base(), "--server-addr", "198.51.100.10"), false, "outside"},
		{"proxy outside", replace(base(), "--proxy-addr", "198.51.100.5"), false, "outside"},
		{"equal addresses", replace(base(), "--proxy-addr", "192.0.2.10"), false, "the same"},
		{"proxy is the gateway", replace(base(), "--proxy-addr", "192.0.2.1"), false, "gateway"},
		{"server is the gateway", replace(base(), "--server-addr", "192.0.2.1"), false, "gateway"},
		{"network address", replace(base(), "--server-addr", "192.0.2.0"), false, "network"},
		{"broadcast address", replace(base(), "--proxy-addr", "192.0.2.255"), false, "broadcast"},
		{"address not ipv4", replace(base(), "--proxy-addr", "proxy.example.test"), false, "--proxy-addr"},
		{"unknown profile", append(base(), "--profile", "root"), false, "--profile"},
		{"admin without approvals", append(base(), "--profile", "admin"), false, "--approve-host"},
		{"unknown form", append(base(), "--form", "env"), true, "--form"},
		{"bind without dir", append(base(), "--form", "bind"), false, "--dir"},
		{"bind relative dir", append(base(), "--form", "bind", "--dir", "secrets"), false, "absolute"},
		{"bind unclean dir", append(base(), "--form", "bind", "--dir", "/srv/shell-mcp/../secrets"), false, "absolute"},
		{"bind root dir", append(base(), "--form", "bind", "--dir", "/"), false, "--dir"},
		{"bind dir with a space", append(base(), "--form", "bind", "--dir", "/srv/shell mcp"), false, "characters"},
		{"bind dir with a colon", append(base(), "--form", "bind", "--dir", "/srv/a:/etc"), false, "characters"},
		{"dir in the secrets form", append(base(), "--dir", "/srv/shell-mcp/secrets"), true, "--form bind"},
		{"extra argument", append(base(), "extra"), true, "extra"},
		{"unknown flag", append(base(), "--token", "x"), true, "token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := compose.ParseFlags(c.args)
			if err == nil {
				_, err = v.Check()
			}
			if err == nil {
				t.Fatal("accepted")
			}
			var ue *compose.UsageError
			if errors.As(err, &ue) != c.usage {
				t.Errorf("usage error %v, want %v (%v)", !c.usage, c.usage, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %q", err, c.want)
			}
		})
	}
}

func TestNotes(t *testing.T) {
	v, err := compose.ParseFlags(append(base(), "--profile", "operator"))
	if err != nil {
		t.Fatal(err)
	}
	notes, err := v.Check()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(notes, func(n string) bool {
		return strings.Contains(n, "without approval") && strings.Contains(n, "SHELL_MCP_APPROVAL_TIERS")
	}) {
		t.Errorf("operator without --approve-host: notes %q", notes)
	}
	v, err = compose.ParseFlags(append(base(), "--profile", "admin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Check(); err == nil || !strings.Contains(err.Error(), "destructive and privileged") {
		t.Errorf("admin without --approve-host: %v", err)
	}
	v, err = compose.ParseFlags(base())
	if err != nil {
		t.Fatal(err)
	}
	if notes, err := v.Check(); err != nil || slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, "approval") }) {
		t.Errorf("read-only: notes %q, err %v", notes, err)
	}
}

func TestParseImage(t *testing.T) {
	for ref, want := range map[string]compose.Image{
		image3: {Repository: "ghcr.io/tyler-rich/shell-mcp", Tag: "0.3.0", Digest: digest},
		"ghcr.io/tyler-rich/shell-mcp@sha256:" + digest:             {Repository: "ghcr.io/tyler-rich/shell-mcp", Digest: digest},
		"registry.example.test:5000/team/app:v1.2@sha256:" + digest: {Repository: "registry.example.test:5000/team/app", Tag: "v1.2", Digest: digest},
	} {
		got, err := compose.ParseImage(ref)
		if err != nil || got != want {
			t.Errorf("ParseImage(%q) = %+v, %v; want %+v", ref, got, err, want)
		}
	}
	for _, ref := range []string{"", "shell-mcp", "shell-mcp:0.3.0", "@sha256:" + digest, "Shell-MCP@sha256:" + digest,
		"a b@sha256:" + digest, "a@sha512:" + digest, "a@sha256:" + digest + "\n", "a:@sha256:" + digest, "a:-x@sha256:" + digest} {
		if _, err := compose.ParseImage(ref); err == nil {
			t.Errorf("ParseImage(%q) accepted", ref)
		}
	}
}

// TestAmbiguousValuesStayStrings: values the server's rules accept that YAML
// would read as a number, a boolean or null are quoted, so Compose passes
// the server exactly what was given.
func TestAmbiguousValuesStayStrings(t *testing.T) {
	args := replace(replace(replace(base(), "--target-name", "00000000"), "--target-host", "true"), "--target-user", "null")
	e := env(t, parse(t, render(t, args)))
	for k, want := range map[string]string{"SHELL_MCP_TARGET_NAME": "00000000", "SHELL_MCP_TARGET_HOST": "true", "SHELL_MCP_TARGET_USER": "null"} {
		if e[k] != want {
			t.Errorf("%s = %q, want %q", k, e[k], want)
		}
	}
}
