//go:build e2e && linux

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// shell_get_policy's privileged section end to end (S4c-9, handoff P-8):
// the real server (admin profile), the real gate and the real helper. The
// summary is served by the core unit, describes the commands of both
// units, and never carries the installed policy's deny patterns or
// acknowledge text; the broad unit refuses priv_policy.

// privPolicySecrets returns the installed privileged policy's deny patterns
// and every acknowledge string in it.
func privPolicySecrets(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if s, ok := e.(string); ok && k == "acknowledge" {
					out = append(out, s)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	if paths, ok := doc["paths"].(map[string]any); ok {
		for _, d := range paths["deny"].([]any) {
			out = append(out, d.(string))
		}
	}
	if len(out) < 2 {
		t.Fatalf("the installed policy has no deny pattern or acknowledge to look for: %q", out)
	}
	return out
}

// TestPrivPolicySummary: shell_get_policy shows the installed privileged
// policy's hash, its declared commands with their units (core and broad)
// and approval, and the operations it allows; no deny value or
// acknowledge text; the core unit's instance answered and the broad unit's
// refuses the op.
func TestPrivPolicySummary(t *testing.T) {
	srv, _ := privWriteServer(t)
	conn := connOf(t, srv.cs)
	raw, err := os.ReadFile("/etc/shell-mcp/privileged.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	env := srv.callTool(t, "shell_get_policy", map[string]any{})
	d := okDataAs(t, env, "e2e-ssh")
	b, _ := json.Marshal(env)
	for _, s := range privPolicySecrets(t, raw) {
		if strings.Contains(string(b), s) {
			t.Errorf("shell_get_policy carries %q", s)
		}
	}
	priv, _ := d["privileged"].(map[string]any)
	p, ok := priv["policy"].(map[string]any)
	if !ok {
		t.Fatalf("no privileged.policy: %s", b)
	}
	if p["policy_sha256"] != hex.EncodeToString(sum[:]) || p["max_tier"] != "destructive" || p["deny_patterns"] != float64(1) {
		t.Fatalf("summary %v", p)
	}
	cmds := map[string]string{}
	for _, c := range p["commands"].([]any) {
		c := c.(map[string]any)
		cmds[c["id"].(string)] = fmt.Sprintf("%s/%s/%v", c["unit"], c["tier"], c["approval"])
	}
	for id, want := range map[string]string{
		"probe-echo": "core/read/false", "probe-root-op": "core/operator/true",
		"probe-broad": "broad/read/false", "probe-broad-op": "broad/operator/true",
	} {
		if cmds[id] != want {
			t.Errorf("command %s: %q, want %q", id, cmds[id], want)
		}
	}
	ops := map[string]string{}
	for _, o := range p["ops"].([]any) {
		o := o.(map[string]any)
		ops[o["op"].(string)] = fmt.Sprintf("%s/%s/%v", o["unit"], o["tier"], o["approval"])
	}
	for op, want := range map[string]string{
		"priv_policy": "core/read/false", "priv_write_file": "core/operator/true", "priv_delete": "core/destructive/true",
		"priv_pkg_install": "broad/operator/true", "priv_power": "broad/destructive/true", "priv_power_cancel": "broad/read/false",
	} {
		if ops[op] != want {
			t.Errorf("op %s: %q, want %q", op, ops[op], want)
		}
	}
	if _, ok := ops["priv_pkg_upgrade"]; ok {
		t.Error("priv_pkg_upgrade listed with allow_upgrade false")
	}
	if !slices.Equal(anyStrings(p["power"].(map[string]any)["allowed"]), []string{"reboot"}) {
		t.Errorf("power %v", p["power"])
	}
	j := conn.waitHelper(t, `"op":"priv_policy"`, `"outcome":"ok"`)
	if helperUnitOf(&j) != "core" {
		t.Fatalf("priv_policy answered by %q", j.Unit)
	}
	line := fmt.Sprintf(`{"v":2,"id":%q,"ceiling":"read","op":"priv_policy","args":{},"timeout_ms":5000}`+"\n", newID())
	if out := directTo(t, svcShell, broadSocket, line); !strings.Contains(out, `"code":"helper_wrong_unit"`) {
		t.Fatalf("the broad unit answered priv_policy: %s", out)
	}
}

func anyStrings(v any) []string {
	out := []string{}
	l, _ := v.([]any)
	for _, e := range l {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}
