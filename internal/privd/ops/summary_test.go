//go:build linux

package ops_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// priv_policy (handoff P-8, S4c-9): the privileged policy summary, built
// from the policy the helper enforces. Every path, name and value below is
// an invented fixture.

type summaryWire struct {
	PolicySHA256 string `json:"policy_sha256"`
	MaxTier      string `json:"max_tier"`
	Limits       struct {
		MaxReadBytes     int `json:"max_read_bytes"`
		MaxWriteBytes    int `json:"max_write_bytes"`
		MaxOutputBytes   int `json:"max_output_bytes"`
		DefaultTimeoutS  int `json:"default_timeout_s"`
		MaxTimeoutS      int `json:"max_timeout_s"`
		MaxDeleteEntries int `json:"max_delete_entries"`
	} `json:"limits"`
	Roots struct {
		Read        []string `json:"read"`
		Write       []string `json:"write"`
		Persistence []string `json:"persistence"`
	} `json:"roots"`
	DenyPatterns int `json:"deny_patterns"`
	Owners       struct {
		Users  []string `json:"users"`
		Groups []string `json:"groups"`
	} `json:"owners"`
	ModesMax             string `json:"modes_max"`
	BackupsKeep          int    `json:"backups_keep"`
	BackupsMaxStoreBytes int64  `json:"backups_max_store_bytes"`
	Commands             []struct {
		ID             string     `json:"id"`
		Tier           string     `json:"tier"`
		Unit           string     `json:"unit"`
		Description    string     `json:"description"`
		Templates      [][]string `json:"templates"`
		RootEquivalent bool       `json:"root_equivalent"`
		Capabilities   []string   `json:"capabilities"`
	} `json:"commands"`
	Packages struct {
		Enabled          bool     `json:"enabled"`
		Install          []string `json:"install"`
		Remove           []string `json:"remove"`
		AllowUpdateIndex bool     `json:"allow_update_index"`
		AllowUpgrade     bool     `json:"allow_upgrade"`
	} `json:"packages"`
	Power struct {
		Allowed []string `json:"allowed"`
	} `json:"power"`
	Ops      []summaryOp `json:"ops"`
	Findings []struct {
		CommandID string `json:"command_id"`
		Category  string `json:"category"`
		Program   string `json:"program"`
		Match     string `json:"match"`
	} `json:"findings"`
}

type summaryOp struct {
	Op   string `json:"op"`
	Tier string `json:"tier"`
	Unit string `json:"unit"`
}

// summary asks for priv_policy and returns its data strictly decoded, the
// raw response line, and the helper block's policy hash.
func (f *fixture) summary() (s summaryWire, raw, helperSHA string) {
	f.t.Helper()
	out, _ := f.serveRaw(request("priv_policy", m{}))
	var r struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error any             `json:"error"`
		// The helper answers with its own block as "gate"; the gate passes
		// it on to the server as "helper" (ARCHITECTURE §4.2).
		Helper struct {
			PolicySHA256 string `json:"policy_sha256"`
			Unit         string `json:"unit"`
		} `json:"gate"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || !r.OK {
		f.t.Fatalf("priv_policy: %s", out)
	}
	dec := json.NewDecoder(strings.NewReader(string(r.Data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		f.t.Fatalf("priv_policy data %s: %v", r.Data, err)
	}
	if r.Helper.Unit != "core" {
		f.t.Fatalf("priv_policy answered by unit %q", r.Helper.Unit)
	}
	return s, out, r.Helper.PolicySHA256
}

func (s *summaryWire) op(name string) (summaryOp, bool) {
	i := slices.IndexFunc(s.Ops, func(o summaryOp) bool { return o.Op == name })
	if i < 0 {
		return summaryOp{}, false
	}
	return s.Ops[i], true
}

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the fixture's policy
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TestPrivPolicySummary: the summary states the policy the core instance
// enforces: its hash (the helper block's), tiers, roots, limits, owners,
// mask, backups, every command with its unit and templates, packages and
// power, and the operations each tier allows in which unit.
func TestPrivPolicySummary(t *testing.T) {
	t.Parallel()
	f := newFixture(t, broadUsers())
	s, _, helperSHA := f.summary()
	if want := fileSHA(t, f.policyPath); s.PolicySHA256 != want || helperSHA != want {
		t.Fatalf("summary hash %s, helper block %s, policy file %s", s.PolicySHA256, helperSHA, want)
	}
	if s.MaxTier != "destructive" || s.Limits.MaxReadBytes != 65536 || s.Limits.MaxOutputBytes != 4096 || s.Limits.MaxTimeoutS != 10 ||
		s.Limits.DefaultTimeoutS != 5 || s.Limits.MaxDeleteEntries != 20 || s.Limits.MaxWriteBytes != 65536 {
		t.Fatalf("tier and limits: %+v %+v", s.MaxTier, s.Limits)
	}
	if !slices.Equal(s.Roots.Read, []string{f.read}) || !slices.Equal(s.Roots.Write, []string{f.write}) || len(s.Roots.Persistence) != 0 || s.DenyPatterns != 1 {
		t.Fatalf("roots %+v, deny patterns %d", s.Roots, s.DenyPatterns)
	}
	if !slices.Equal(s.Owners.Users, []string{"tester", "root"}) || !slices.Equal(s.Owners.Groups, []string{"tester", "root"}) ||
		s.ModesMax != "0755" || s.BackupsKeep != 3 || s.BackupsMaxStoreBytes != 1<<30 {
		t.Fatalf("owners %+v mask %s backups %d %d", s.Owners, s.ModesMax, s.BackupsKeep, s.BackupsMaxStoreBytes)
	}
	units := map[string]string{}
	for _, c := range s.Commands {
		units[c.ID] = c.Unit + "/" + c.Tier
		if c.ID == "probe-echo" && !slices.EqualFunc(c.Templates, [][]string{{"echo", "{regex:^[a-z]+$}"}, {"write", "{path:write}", "{regex:^[a-z]+$}"}}, slices.Equal) {
			t.Fatalf("probe-echo templates %q", c.Templates)
		}
		if c.Capabilities == nil {
			t.Fatalf("%s: capabilities null", c.ID)
		}
	}
	if units["probe-echo"] != "core/read" || units["probe-op"] != "core/operator" || units["probe-broad"] != "broad/read" || len(units) != 3 {
		t.Fatalf("commands %v", units)
	}
	if !s.Packages.Enabled || !slices.Equal(s.Packages.Install, []string{"example-hello"}) || !slices.Equal(s.Packages.Remove, []string{"example-hello"}) ||
		!s.Packages.AllowUpdateIndex || s.Packages.AllowUpgrade || !slices.Equal(s.Power.Allowed, []string{"reboot"}) || len(s.Findings) != 0 {
		t.Fatalf("packages %+v power %+v findings %+v", s.Packages, s.Power, s.Findings)
	}
	for op, want := range map[string]summaryOp{
		"priv_policy":                   {"priv_policy", "read", "core"},
		"priv_read_file":                {"priv_read_file", "read", "core"},
		"priv_write_file":               {"priv_write_file", "operator", "core"},
		"priv_delete":                   {"priv_delete", "destructive", "core"},
		"priv_exec_preview":             {"priv_exec_preview", "read", "core"},
		"priv_exec":                     {"priv_exec", "command", "command"},
		"priv_pkg_update_index":         {"priv_pkg_update_index", "operator", "broad"},
		"priv_pkg_update_index_preview": {"priv_pkg_update_index_preview", "read", "broad"},
		"priv_pkg_install":              {"priv_pkg_install", "operator", "broad"},
		"priv_pkg_remove":               {"priv_pkg_remove", "destructive", "broad"},
		"priv_power_cancel":             {"priv_power_cancel", "read", "broad"},
	} {
		if got, ok := s.op(op); !ok || got != want {
			t.Errorf("op %s: %+v (listed %v), want %+v", op, got, ok, want)
		}
	}
	// What the policy switches off is not listed, as the operations refuse
	// it: no upgrade (allow_upgrade false), and no power action, because
	// limits.max_timeout_s (10) is below the 60 s priv_power waits.
	for _, op := range []string{"priv_pkg_upgrade", "priv_pkg_upgrade_preview", "priv_power", "priv_power_preview"} {
		if _, ok := s.op(op); ok {
			t.Errorf("op %s listed", op)
		}
	}
	broad := newFixture(t, broadUsers(), asBroad())
	broad.fail("priv_pkg_upgrade_preview", m{}, "policy_denied")
	broad.fail("priv_power_preview", m{"action": "reboot"}, "policy_denied")
	if !strings.Contains(f.lastAudit(), `"op":"priv_policy"`) {
		t.Fatalf("audit %s", f.lastAudit())
	}
}

// TestPrivPolicySummaryTiers: under max_tier read only read operations are
// listed, and an operation left out is refused by its tier; commands are
// listed with their own tiers whatever max_tier is.
func TestPrivPolicySummaryTiers(t *testing.T) {
	t.Parallel()
	f := newFixture(t, maxTier("read"))
	s, _, _ := f.summary()
	for _, o := range s.Ops {
		if o.Tier != "read" && o.Op != "priv_exec" {
			t.Errorf("op %+v listed under max_tier read", o)
		}
	}
	for _, op := range []string{"priv_write_file", "priv_delete", "priv_chown", "priv_restore_backup"} {
		if _, ok := s.op(op); ok {
			t.Errorf("%s listed under max_tier read", op)
		}
	}
	// No broad unit in this policy: nothing of it is listed.
	for _, o := range s.Ops {
		if o.Unit == "broad" {
			t.Errorf("broad op %+v listed for a policy without the broad unit", o)
		}
	}
	f.fail("priv_write_file", m{"path": filepath.Join(f.write, "x"), "content_b64": "eA=="}, "tier_denied")
	if len(s.Commands) != 2 {
		t.Fatalf("commands %+v", s.Commands)
	}
}

// TestPrivPolicySummaryNothingPrivate: no deny value and no acknowledge
// text reaches the wire (a sentinel in each), only the deny patterns'
// count; the N-13 findings are reported by command, category, program and
// how it was recognised.
func TestPrivPolicySummaryNothingPrivate(t *testing.T) {
	t.Parallel()
	const (
		canaryDeny    = "canary-deny-5e1f"
		canaryDeny2   = "canary-deny-77b0"
		canaryPkgAck  = "canary-ack-pkg-2c9d"
		canaryPowAck  = "canary-ack-reboot-a41e"
		canaryPersAck = "canary-ack-persistence-0d3b"
		canaryPowerOp = "canary-ack-power-section-9f62"
	)
	var pers string
	f := newFixture(t, broadUsers(), func(f *fixture, y *string) {
		gatetest.WriteFile(f.t, filepath.Join(f.d, "bin", "dpkg"), "invented package tool\n", 0o755)
		gatetest.WriteFile(f.t, filepath.Join(f.d, "bin", "reboot"), "invented power tool\n", 0o755)
		pers = filepath.Join(f.d, "etc", "example-app.d")
		gatetest.Mkdir(f.t, pers, 0o755)
		*y = strings.Replace(*y, `  deny: ["`+f.read+`/secrets/**"]`,
			fmt.Sprintf("  deny: [%q, %q, %q]\n  persistence:\n    - path: %s\n      acknowledge: %q",
				f.read+"/secrets/**", "**/"+canaryDeny+"/**", "/"+canaryDeny2+"/*", pers, canaryPersAck), 1)
		*y = strings.Replace(*y, `acknowledge: "invented test policy"`, "acknowledge: "+strconv.Quote(canaryPowerOp), 1)
		*y = strings.Replace(*y, "packages:\n", fmt.Sprintf(`  - id: x-dpkg
    path: %s
    tier: read
    unit: broad
    acknowledge: %q
    templates: [["--audit"]]
  - id: x-reboot
    path: %s
    tier: operator
    unit: broad
    acknowledge: %q
    templates: [["--help"]]
packages:
`, filepath.Join(f.d, "bin", "dpkg"), canaryPkgAck, filepath.Join(f.d, "bin", "reboot"), canaryPowAck), 1)
	})
	s, raw, _ := f.summary()
	for _, c := range []string{canaryDeny, canaryDeny2, canaryPkgAck, canaryPowAck, canaryPersAck, canaryPowerOp, "secrets/**", "acknowledge"} {
		if strings.Contains(raw, c) {
			t.Errorf("the summary carries %q: %s", c, raw)
		}
	}
	if s.DenyPatterns != 3 || !slices.Equal(s.Roots.Persistence, []string{pers}) {
		t.Fatalf("deny patterns %d persistence %q", s.DenyPatterns, s.Roots.Persistence)
	}
	got := map[string]string{}
	for _, fd := range s.Findings {
		got[fd.CommandID] = fd.Category + " " + fd.Program + " " + fd.Match
	}
	if got["x-dpkg"] != "package dpkg written" || got["x-reboot"] != "power reboot written" || len(got) != 2 {
		t.Fatalf("findings %+v", s.Findings)
	}
}

// TestPrivPolicySummaryBroadRefuses: the summary is a core-unit operation;
// the broad unit's instance refuses it.
func TestPrivPolicySummaryBroadRefuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t, broadUsers(), asBroad())
	f.fail("priv_policy", m{}, "helper_wrong_unit")
}

// TestPrivPolicySummaryMatchesExec (property, against the enforcement
// path): for every command and every template of the policy, a request
// built from the template is previewed by priv_exec_preview, which
// resolves it through priv_exec's own resolution, and the command's tier,
// unit, description, root_equivalent flag, capabilities and template are
// the summary's.
func TestPrivPolicySummaryMatchesExec(t *testing.T) {
	t.Parallel()
	f := newFixture(t, broadUsers(), func(f *fixture, y *string) {
		*y = strings.Replace(*y, "packages:\n", fmt.Sprintf(`  - id: probe-mixed
    path: %s
    tier: operator
    description: "an invented mixed template"
    capabilities: [CAP_KILL]
    templates: [["echo", "{int:1-5}"], ["echo", "{enum:alpha|beta}"], ["read", "{path:read}"]]
packages:
`, f.probe), 1)
	})
	s, _, _ := f.summary()
	if len(s.Commands) != 4 {
		t.Fatalf("commands %+v", s.Commands)
	}
	ph := regexp.MustCompile(`^\{([a-z]+)(?::(.*))?\}$`)
	n := 0
	for _, c := range s.Commands {
		for _, tpl := range c.Templates {
			args := make([]string, len(tpl))
			for i, tok := range tpl {
				mm := ph.FindStringSubmatch(tok)
				switch {
				case mm == nil:
					args[i] = tok
				case mm[1] == "regex":
					args[i] = "abc"
				case mm[1] == "int":
					args[i] = strings.SplitN(mm[2], "-", 2)[0]
				case mm[1] == "enum":
					args[i] = strings.SplitN(mm[2], "|", 2)[0]
				case mm[1] == "path" && mm[2] == "read":
					args[i] = filepath.Join(f.read, "hello.txt")
				case mm[1] == "path" && mm[2] == "write":
					args[i] = filepath.Join(f.write, "app.conf")
				default:
					t.Fatalf("placeholder %s", tok)
				}
			}
			var p struct {
				Tier           string   `json:"tier"`
				Unit           string   `json:"unit"`
				Description    string   `json:"description"`
				RootEquivalent bool     `json:"root_equivalent"`
				Capabilities   []string `json:"capabilities"`
				Template       []string `json:"template"`
				PolicySHA256   string   `json:"policy_sha256"`
			}
			f.ok("priv_exec_preview", m{"command_id": c.ID, "args": args}, &p)
			if p.Tier != c.Tier || p.Unit != c.Unit || p.Description != c.Description || p.RootEquivalent != c.RootEquivalent ||
				!slices.Equal(p.Capabilities, c.Capabilities) || !slices.Equal(p.Template, tpl) || p.PolicySHA256 != s.PolicySHA256 {
				t.Errorf("%s %q: preview %+v, summary %+v", c.ID, tpl, p, c)
			}
			n++
		}
	}
	if n != 9 {
		t.Fatalf("%d templates checked, want 9", n)
	}
}
