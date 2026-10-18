//go:build linux

package ops_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// exec_preview (ARCHITECTURE §4.3): the command resolved exactly as exec
// resolves it, nothing run; and exec's expected_preview_sha256. Commands,
// paths and units are invented.

type execPreview struct {
	CommandID      string   `json:"command_id"`
	Tier           string   `json:"tier"`
	Description    string   `json:"description"`
	RootEquivalent bool     `json:"root_equivalent"`
	Template       []string `json:"template"`
	Argv           []string `json:"argv"`
	Cwd            string   `json:"cwd"`
	PolicySHA256   string   `json:"policy_sha256"`
	PreviewSHA256  string   `json:"preview_sha256"`
}

// wipeCommand is a destructive command appended to the base policy.
const wipeCommand = `  - id: probe-wipe
    path: {BIN}/probe
    tier: destructive
    templates: [["write", "{path:write}"]]
`

func execPreviewFixture(t testing.TB, tier string) *fixture {
	t.Helper()
	f := newFixture(t, tier)
	f.rawPolicy(strings.NewReplacer("{TIER}", tier, "{PRIV}", "", "{R}", f.read, "{W}", f.write, "{BIN}", f.bin).Replace(basePolicy + wipeCommand))
	return f
}

// execCases covers every template of the base policy and every placeholder
// type: literals, regex, path:read, unit, int, enum, path:write, and a cwd.
func execCases(f *fixture) []m {
	return []m{
		{"command_id": "probe-echo", "args": []string{"echo", "hello world"}},
		{"command_id": "probe-echo", "args": []string{"echo", "path", filepath.Join(f.read, "hello.txt")}},
		{"command_id": "probe-echo", "args": []string{"echo", "unit", "example-app.service"}},
		{"command_id": "probe-io", "args": []string{"exit", "7"}},
		{"command_id": "probe-io", "args": []string{"sleep", "5s"}},
		{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": f.write},
		{"command_id": "probe-io", "args": []string{"stdin"}},
		{"command_id": "probe-op", "args": []string{"write", filepath.Join(f.write, "from-probe")}},
	}
}

func TestExecPreviewResolvesAsExec(t *testing.T) {
	f := execPreviewFixture(t, "destructive")
	for _, c := range execCases(f) {
		var pv execPreview
		f.ok("exec_preview", c, &pv)
		if pv.CommandID != c["command_id"] || pv.Argv[0] != f.probe || len(pv.PreviewSHA256) != 64 || pv.PolicySHA256 == "" || len(pv.Template) == 0 {
			t.Fatalf("%v: preview %+v", c, pv)
		}
		cwd, _ := c["cwd"].(string)
		if (cwd == "" && pv.Cwd != "/") || (cwd != "" && pv.Cwd != cwd) {
			t.Fatalf("%v: cwd %q", c, pv.Cwd)
		}
		if c["args"].([]string)[0] == "sleep" {
			continue // exec would wait for it
		}
		var d execData
		f.ok("exec", c, &d)
		if !slices.Equal(d.Argv, pv.Argv) {
			t.Fatalf("%v: exec ran %v, the preview said %v", c, d.Argv, pv.Argv)
		}
		// The same request with the preview's hash runs.
		withHash := m{"expected_preview_sha256": pv.PreviewSHA256}
		for k, v := range c {
			withHash[k] = v
		}
		f.ok("exec", withHash, &d)
	}
	// The preview runs nothing.
	out := filepath.Join(f.write, "from-preview")
	f.ok("exec_preview", m{"command_id": "probe-op", "args": []string{"write", out}}, nil)
	if exists(out) {
		t.Fatal("exec_preview ran the command")
	}
	// It describes the command as the policy does.
	var pv execPreview
	f.ok("exec_preview", m{"command_id": "probe-echo", "args": []string{"echo", "x"}}, &pv)
	if pv.Tier != "read" || pv.Description != "Echo arguments" || pv.RootEquivalent ||
		!slices.Equal(pv.Template, []string{"echo", "{regex:^[A-Za-z0-9 =._-]+$}"}) || !slices.Equal(pv.Argv, []string{f.probe, "echo", "x"}) {
		t.Fatalf("preview %+v", pv)
	}
	// Refusals are exec's own.
	for _, c := range []struct {
		args m
		code string
	}{
		{m{"command_id": "not-declared"}, "policy_denied"},
		{m{"command_id": "probe-echo", "args": []string{"echo", "-rf"}}, "template_mismatch"},
		{m{"command_id": "probe-echo", "args": []string{"echo", "unit", "other.service"}}, "template_mismatch"},
		{m{"command_id": "probe-echo", "args": []string{"echo", "path", filepath.Join(f.secrets, "token")}}, "path_denied"},
		{m{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": f.secrets}, "path_denied"},
		{m{"command_id": "probe-io", "args": []string{"stdin"}, "stdin_b64": "cGluZw=="}, "bad_request"},
	} {
		f.fail("exec_preview", c.args, c.code)
		if c.code != "bad_request" {
			f.fail("exec", c.args, c.code)
		}
	}
}

func TestExecExpectedPreview(t *testing.T) {
	f := execPreviewFixture(t, "destructive")
	out := filepath.Join(f.write, "wiped")
	args := m{"command_id": "probe-wipe", "args": []string{"write", out}}
	var pv execPreview
	f.ok("exec_preview", args, &pv)
	call := func(hash any) response {
		a := m{"expected_preview_sha256": hash}
		for k, v := range args {
			a[k] = v
		}
		return f.call("exec", a)
	}
	for _, bad := range []any{"", strings.ToUpper(pv.PreviewSHA256), pv.PreviewSHA256[:63], 5} {
		if r := call(bad); r.OK || r.Error.Code != "bad_request" {
			t.Fatalf("hash %v: %+v", bad, r.Error)
		}
	}
	if r := call(strings.Repeat("0", 64)); r.OK || r.Error.Code != "exists" {
		t.Fatalf("another hash: %+v", r.Error)
	}
	if exists(out) {
		t.Fatal("a mismatched exec ran")
	}
	// A policy edit between the preview and the exec is refused, and
	// nothing runs: the hash covers the policy.
	before := pv.PolicySHA256
	f.rawPolicy(strings.NewReplacer("{TIER}", "destructive", "{PRIV}", "", "{R}", f.read, "{W}", f.write, "{BIN}", f.bin).
		Replace(basePolicy + strings.Replace(wipeCommand, "tier: destructive", "tier: destructive\n    description: \"edited\"", 1)))
	if r := call(pv.PreviewSHA256); r.OK || r.Error.Code != "exists" || !strings.Contains(r.Error.Message, "preview") {
		t.Fatalf("after a policy edit: %+v", r.Error)
	}
	if exists(out) {
		t.Fatal("the exec ran after the policy changed")
	}
	var again execPreview
	f.ok("exec_preview", args, &again)
	if again.PolicySHA256 == before || again.PreviewSHA256 == pv.PreviewSHA256 {
		t.Fatalf("the policy edit did not change the preview: %+v", again)
	}
	// A path placeholder that resolves elsewhere changes the preview.
	link := filepath.Join(f.write, "via-link")
	if err := os.Symlink(f.write, link); err != nil {
		t.Fatal(err)
	}
	var p1, p2 execPreview
	f.ok("exec_preview", m{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": link}, &p1)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	mkdirOne(t, link)
	f.ok("exec_preview", m{"command_id": "probe-io", "args": []string{"pwd"}, "cwd": link}, &p2)
	if p1.Cwd == p2.Cwd || p1.PreviewSHA256 == p2.PreviewSHA256 {
		t.Fatalf("a retargeted cwd did not change the preview: %+v %+v", p1, p2)
	}
	if r := call(again.PreviewSHA256); !r.OK || contentOf(t, out) != "probe" {
		t.Fatalf("the fresh preview's hash: %+v", r.Error)
	}
}

func mkdirOne(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestExecPreviewTier: the command's tier is checked against max_tier and
// the request's ceiling, as exec checks it: a destructive command is
// refused at ceiling operator (the operator profile's shell_run_command).
func TestExecPreviewTier(t *testing.T) {
	f := execPreviewFixture(t, "destructive")
	args := m{"command_id": "probe-wipe", "args": []string{"write", filepath.Join(f.write, "x")}}
	f.deniedAt("operator", "exec_preview", args, "ceiling operator")
	f.deniedAt("operator", "exec", args, "ceiling operator")
	f.deniedAt("read", "exec_preview", m{"command_id": "probe-op", "args": []string{"write", filepath.Join(f.write, "x")}}, "ceiling read")
	if r := f.callAt("destructive", "exec_preview", args); !r.OK {
		t.Fatalf("at destructive: %+v", r.Error)
	}
	g := execPreviewFixture(t, "operator")
	g.fail("exec_preview", args, "tier_denied")
	// The hello op lists exec_preview next to exec.
	var h struct {
		Ops []string `json:"ops"`
	}
	g.ok("hello", nil, &h)
	if !slices.Contains(h.Ops, "exec_preview") || !slices.Contains(h.Ops, "exec") {
		t.Fatalf("ops %v", h.Ops)
	}
}

// FuzzExecPreviewMatchesExec: for any command id, arguments and cwd,
// exec_preview and exec agree: the same refusal code, or the same resolved
// argv (exec runs the probe, which only echoes, exits or prints its cwd).
func FuzzExecPreviewMatchesExec(f *testing.F) {
	f.Add("probe-echo", "echo", "hello", "", "")
	f.Add("probe-echo", "echo", "path", "hello.txt", "")
	f.Add("probe-echo", "echo", "unit", "example-app.service", "")
	f.Add("probe-io", "exit", "255", "", "")
	f.Add("probe-io", "pwd", "", "", "config")
	f.Add("probe-op", "write", "config/x", "", "")
	f.Add("probe-echo", "echo", "-x", "", "../etc")
	fx := execPreviewFixture(f, "operator")
	f.Fuzz(func(t *testing.T, id, a0, a1, a2, cwd string) {
		fx.t = t
		args := []string{}
		for _, a := range []string{a0, a1, a2} {
			if a == "" {
				break
			}
			// Paths in the corpus are relative to the fixture's read root.
			if strings.HasSuffix(a, ".txt") || strings.HasPrefix(a, "config/") {
				a = filepath.Join(fx.read, a)
			}
			args = append(args, a)
		}
		if a0 == "sleep" || id == "probe-wipe" {
			return // would wait, or write
		}
		if a0 == "write" && id == "probe-op" {
			return // writes on success
		}
		req := m{"command_id": id, "args": args}
		if cwd != "" {
			req["cwd"] = filepath.Join(fx.read, cwd)
			if strings.HasPrefix(cwd, "/") {
				req["cwd"] = cwd
			}
		}
		p := fx.callAt("operator", "exec_preview", req)
		e := fx.callAt("operator", "exec", req)
		switch {
		case p.OK != e.OK:
			t.Fatalf("%v: preview ok=%v (%+v), exec ok=%v (%+v)", req, p.OK, p.Error, e.OK, e.Error)
		case !p.OK:
			if p.Error.Code != e.Error.Code {
				t.Fatalf("%v: preview %s, exec %s", req, p.Error.Code, e.Error.Code)
			}
		default:
			var pv execPreview
			var d execData
			if json.Unmarshal(p.Data, &pv) != nil || json.Unmarshal(e.Data, &d) != nil || !slices.Equal(pv.Argv, d.Argv) {
				t.Fatalf("%v: preview argv %v, exec argv %v", req, pv.Argv, d.Argv)
			}
		}
	})
}
