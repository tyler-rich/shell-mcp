package tools

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/approval"
)

// The package tools (S4c-7; docs/TOOLS.md, privileged tier: packages;
// handoff D5, D9, P-2e, P-3, P-5, P-6, Q7, Q9): shell_priv_preview_packages
// (read) sends the matching preview at ceiling read; the update, install,
// upgrade and remove tools are always approval-gated, their approval
// preview is the helper's simulated transaction bound with both policies'
// hashes, and the approved re-call sends the operation with the fresh
// preview's hash. Every package name, version and hash is invented.

func init() {
	alwaysGated = append(alwaysGated, "shell_priv_update_package_index", "shell_priv_install_packages", "shell_priv_upgrade_packages", "shell_priv_remove_packages")
}

const (
	shaPK  = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
	shaPK2 = "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2"
)

func fakePkgPreview(op, sha string) string {
	tx := `"install":[{"name":"example-hello","version":"1.1"},{"name":"example-lib","version":"2.1-1"}],"upgrade":[],"remove":[]`
	switch op {
	case "upgrade":
		tx = `"install":[],"upgrade":[{"name":"example-hello","from":"1.0","to":"1.1"},{"name":"example-lib","from":"2.0-1","to":"2.1-1"}],"remove":[]`
	case "remove":
		tx = `"install":[],"upgrade":[],"remove":[{"name":"example-hello","version":"1.1","purge":false}]`
	}
	pk := `["example-hello"]`
	if op == "upgrade" {
		pk = `[]`
	}
	return `{"op":"` + op + `","packages":` + pk + `,` + tx + `,"complete":true,"argv":["-q","-s","` + op + `"],"exit_code":0,"signal":null,` +
		`"stderr":"","stderr_truncated":false,"duration_ms":40,"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

func fakePkgResult(op string) string {
	applied := `{"install":[{"name":"example-hello","version":"1.1"},{"name":"example-lib","version":"2.1-1"}],"upgrade":[],"remove":[]}`
	switch op {
	case "upgrade":
		applied = `{"install":[],"upgrade":[{"name":"example-hello","from":"1.0","to":"1.1"},{"name":"example-lib","from":"2.0-1","to":"2.1-1"}],"remove":[]}`
	case "remove":
		applied = `{"install":[],"upgrade":[],"remove":[{"name":"example-hello","version":"1.1","purge":false}]}`
	case "update":
		applied = `null`
	}
	return fmt.Sprintf(`{"op":%q,"packages":["example-hello"],"applied":%s,"exit_code":0,"signal":null,"timed_out":false,"stdout":"Setting up example-hello (1.1) ...\n",`+
		`"stderr":"","stdout_truncated":false,"stderr_truncated":false,"attempts":1,"lock_wait_ms":0,"duration_ms":900}`, op, applied)
}

func fakeUpdatePreview(sha string) string {
	return `{"argv":["-q","update"],"policy_sha256":"` + strings.Repeat("c", 64) + `","preview_sha256":"` + sha + `"}`
}

// pkgTools are the gated package tools: name, operation, preview op, args.
var pkgTools = []struct {
	name, op, previewOp, kind string
	args                      map[string]any
	tier                      Tier
}{
	{"shell_priv_install_packages", "priv_pkg_install", "priv_pkg_install_preview", "install", map[string]any{"packages": []string{"example-hello"}}, TierOperator},
	{"shell_priv_upgrade_packages", "priv_pkg_upgrade", "priv_pkg_upgrade_preview", "upgrade", map[string]any{}, TierOperator},
	{"shell_priv_remove_packages", "priv_pkg_remove", "priv_pkg_remove_preview", "remove", map[string]any{"packages": []string{"example-hello"}}, TierDestructive},
	{"shell_priv_update_package_index", "priv_pkg_update_index", "priv_pkg_update_index_preview", "update", map[string]any{}, TierOperator},
}

func newPrivPkgHarness(t *testing.T, method approval.Method) *approvalHarness {
	t.Helper()
	a := newPrivWriteHarness(t, method)
	for _, k := range []string{"install", "upgrade", "remove"} {
		a.g.set("priv_pkg_"+k+"_preview", gateReply{data: fakePkgPreview(k, shaPK)})
		a.g.set("priv_pkg_"+k, gateReply{data: fakePkgResult(k)})
	}
	a.g.set("priv_pkg_update_index_preview", gateReply{data: fakeUpdatePreview(shaPK)})
	a.g.set("priv_pkg_update_index", gateReply{data: fakePkgResult("update")})
	return a
}

func (a *approvalHarness) count(op string) int {
	n := 0
	for _, o := range a.g.ops() {
		if o == op {
			n++
		}
	}
	return n
}

func TestPrivPackageToolsRegistered(t *testing.T) {
	reg, err := Catalogue(&Deps{})
	if err != nil {
		t.Fatal(err)
	}
	all := append([]string{"shell_priv_preview_packages"}, "shell_priv_update_package_index", "shell_priv_install_packages", "shell_priv_upgrade_packages", "shell_priv_remove_packages")
	for _, p := range []Profile{ProfileReadOnly, ProfileOperator} {
		for _, n := range names(reg.ToolsForProfile(p, nil)) {
			if slices.Contains(all, n) {
				t.Fatalf("%s is registered in the %s profile", n, p)
			}
		}
	}
	admin := reg.ToolsForProfile(ProfileAdmin, nil)
	find := func(name string) Registration {
		i := slices.IndexFunc(admin, func(r Registration) bool { return r.Tool.Def.Name == name })
		if i < 0 {
			t.Fatalf("%s is not registered in admin", name)
		}
		return admin[i]
	}
	r := find("shell_priv_preview_packages")
	if a := r.Tool.Def.Annotations; r.Tier != TierRead || !r.Privileged || !a.ReadOnlyHint || r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != nil {
		t.Fatalf("preview tool: tier %s annotations %+v meta %v", r.Tier, a, r.Tool.Def.Meta)
	}
	if s := schemaOf(t, r); s.Properties["operation"] == nil || s.Properties["packages"] == nil || s.Properties["approval_id"] != nil {
		t.Fatalf("preview schema %s", jsonOf(t, s))
	}
	for _, c := range pkgTools {
		r := find(c.name)
		a := r.Tool.Def.Annotations
		if r.Tier != c.tier || !r.Privileged || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint ||
			r.Tool.Def.Meta["anthropic/requiresUserInteraction"] != true || !strings.Contains(strings.ToLower(r.Tool.Def.Description), "as root") {
			t.Fatalf("%s: tier %s annotations %+v meta %v description %q", c.name, r.Tier, a, r.Tool.Def.Meta, r.Tool.Def.Description)
		}
		s := schemaOf(t, r)
		for _, want := range []string{"target", "timeout_seconds", "approval_id"} {
			if s.Properties[want] == nil {
				t.Fatalf("%s: no %s in %s", c.name, want, jsonOf(t, s))
			}
		}
		if (s.Properties["packages"] != nil) != (c.kind == "install" || c.kind == "remove") {
			t.Fatalf("%s: packages input %s", c.name, jsonOf(t, s))
		}
		for _, never := range []string{"expected_preview_sha256", "options", "version", "source"} {
			if s.Properties[never] != nil {
				t.Fatalf("%s: %s is an input", c.name, never)
			}
		}
	}
}

// TestPrivPreviewPackages: the read tool sends the matching preview at
// ceiling read and returns the transaction with its hash, under every
// approval method; malformed input sends nothing.
func TestPrivPreviewPackages(t *testing.T) {
	for _, method := range []approval.Method{approval.MethodNone, approval.MethodWeb} {
		for _, k := range []string{"install", "upgrade", "remove"} {
			a := newPrivPkgHarness(t, method)
			args := map[string]any{"operation": k}
			if k != "upgrade" {
				args["packages"] = []string{"example-hello"}
			}
			env, _ := a.call("shell_priv_preview_packages", args)
			d := data(t, env)
			if d["op"] != k || d["preview_sha256"] != shaPK || env["approval"] != nil {
				t.Fatalf("%s %s: %v", method, k, env)
			}
			reqs := a.g.requests()
			if len(reqs) != 1 || reqs[0].Op != "priv_pkg_"+k+"_preview" || reqs[0].Ceiling != "read" {
				t.Fatalf("%s: requests %+v", k, reqs)
			}
			if pa := a.g.args(t, "priv_pkg_"+k+"_preview"); (k == "upgrade") != (pa["packages"] == nil) {
				t.Fatalf("%s: preview args %v", k, pa)
			}
		}
	}
	a := newPrivPkgHarness(t, approval.MethodWeb)
	for _, args := range []map[string]any{
		{}, {"operation": "purge", "packages": []string{"example-hello"}}, {"operation": "install"}, {"operation": "upgrade", "packages": []string{"example-hello"}},
		{"operation": "install", "packages": []string{"Example"}}, {"operation": "install", "packages": []string{"example-hello=1.0"}},
		{"operation": "install", "packages": []string{"-oAPT::Get::Purge=true"}}, {"operation": "install", "packages": []string{"/srv/x.deb"}},
		{"operation": "install", "packages": []string{"example-hello", "example-hello"}},
	} {
		if env, _ := a.call("shell_priv_preview_packages", args); errCode(env) != "validation_error" {
			t.Fatalf("%v: %v", args, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

// TestPrivPackagesApprovalFlow: the first call sends only the preview and
// requests an approval showing the transaction; the approved re-call
// previews again and sends the operation once, at the tool's tier, with the
// fresh preview's hash; the result carries what was applied; a second
// re-call is approval_invalid.
func TestPrivPackagesApprovalFlow(t *testing.T) {
	for _, c := range pkgTools {
		t.Run(c.name, func(t *testing.T) {
			a := newPrivPkgHarness(t, approval.MethodWeb)
			id := a.pending(c.name, c.args)
			if ops := a.g.ops(); !slices.Equal(ops, []string{c.previewOp}) {
				t.Fatalf("first call sent %v", ops)
			}
			pm := previewMap(t, a, id)
			if pm["preview_sha256"] != shaPK {
				t.Fatalf("preview %v", pm)
			}
			rec, _ := a.store.Get(id)
			want := map[string]string{
				"install": "As root, install 1 package on app-host", "upgrade": "As root, upgrade 2 packages on app-host",
				"remove": "As root, remove 1 package on app-host", "update": "As root, update the package index on app-host",
			}[c.kind]
			if rec.Description != want {
				t.Fatalf("description %q, want %q", rec.Description, want)
			}
			switch c.kind {
			case "install":
				if pm["install[0].name"] != "example-hello" || pm["install[0].version"] != "1.1" || pm["install[1].name"] != "example-lib" {
					t.Fatalf("install preview %v", pm)
				}
			case "upgrade":
				if pm["upgrade[0].from"] != "1.0" || pm["upgrade[0].to"] != "1.1" {
					t.Fatalf("upgrade preview %v", pm)
				}
			}
			a.approve(id)
			env, _ := a.call(c.name, withID(c.args, id))
			d := data(t, env)
			if c.kind != "update" && d["applied"] == nil {
				t.Fatalf("data %v", d)
			}
			if ops := a.g.ops(); !slices.Equal(ops, []string{c.previewOp, c.previewOp, c.op}) {
				t.Fatalf("ops %v", ops)
			}
			reqs := a.g.requests()
			if reqs[2].Ceiling != c.tier.String() {
				t.Fatalf("%s at ceiling %s", c.op, reqs[2].Ceiling)
			}
			oa := a.g.args(t, c.op)
			if oa["expected_preview_sha256"] != shaPK || fmt.Sprint(oa["packages"]) != fmt.Sprint(c.args["packages"]) {
				t.Fatalf("op args %v", oa)
			}
			if env, _ := a.call(c.name, withID(c.args, id)); errCode(env) != "approval_invalid" || a.count(c.op) != 1 {
				t.Fatalf("second re-call %v", env)
			}
			if strings.Contains(a.logs.String(), shaPK) {
				t.Fatal("the preview hash reached the server's logs")
			}
		})
	}
}

func TestPrivPackagesGatedUnderNone(t *testing.T) {
	for _, c := range pkgTools {
		a := newPrivPkgHarness(t, approval.MethodNone)
		if env, _ := a.call(c.name, c.args); errCode(env) != "approval_unavailable" {
			t.Fatalf("%s: %v", c.name, env)
		}
		if a.count(c.op) != 0 {
			t.Fatalf("%s: sent %v", c.name, a.g.ops())
		}
	}
}

// TestPrivPackagesChangedAfterApproval: a different transaction (its hash),
// the privileged policy or the gate policy changed after approval is
// approval_invalid, and nothing runs.
func TestPrivPackagesChangedAfterApproval(t *testing.T) {
	for _, c := range pkgTools {
		for name, change := range map[string]func(a *approvalHarness){
			"transaction": func(a *approvalHarness) {
				if c.kind == "update" {
					a.g.set(c.previewOp, gateReply{data: fakeUpdatePreview(shaPK2)})
				} else {
					a.g.set(c.previewOp, gateReply{data: fakePkgPreview(c.kind, shaPK2)})
				}
			},
			"helper": func(a *approvalHarness) { a.g.setHelperSHA("f00d") },
			"gate":   func(a *approvalHarness) { a.g.setSHA("f00d") },
		} {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				a := newPrivPkgHarness(t, approval.MethodWeb)
				id := a.pending(c.name, c.args)
				a.approve(id)
				change(a)
				if env, _ := a.call(c.name, withID(c.args, id)); errCode(env) != "approval_invalid" || a.count(c.op) != 0 {
					t.Fatalf("env %v, ops %v", env, a.g.ops())
				}
			})
		}
	}
}

// TestPrivPackagesOutcomeUnknown: the helper's early answer for an
// operation still running (outcome_unknown, naming the request id and the
// time it may run until) is the result, with that text, and the approval is
// used; a lost answer is outcome_unknown too.
func TestPrivPackagesOutcomeUnknown(t *testing.T) {
	early := "apt-get is still running (request id 0b5c0000-0000-4000-8000-000000000042); it may run until 2026-10-21T12:15:00Z"
	for _, reply := range []gateReply{{code: "outcome_unknown", msg: early}, {silent: true}} {
		a := newPrivPkgHarness(t, approval.MethodWeb)
		args := map[string]any{"packages": []string{"example-hello"}}
		id := a.pending("shell_priv_install_packages", args)
		a.approve(id)
		a.g.set("priv_pkg_install", reply)
		env, _ := a.call("shell_priv_install_packages", withID(args, id))
		if errCode(env) != "outcome_unknown" || env["data"] != nil {
			t.Fatalf("env %v", env)
		}
		if msg := errMessage(env); reply.code != "" && !strings.Contains(msg, "2026-10-21T12:15:00Z") {
			t.Fatalf("message %q lost the helper's until-time", msg)
		}
		if ap, _ := env["approval"].(map[string]any); ap["status"] != "used" {
			t.Fatalf("approval %v", env["approval"])
		}
	}
}

// TestPrivPackagesPreviewRefusals: the preview's refusals (an operation in
// progress, an unfinished database, a removal in an install) are the
// result; no approval is requested and nothing runs. A preview without a
// valid hash is internal.
func TestPrivPackagesPreviewRefusals(t *testing.T) {
	args := map[string]any{"packages": []string{"example-hello"}}
	for name, c := range map[string]struct {
		reply gateReply
		code  string
	}{
		"in progress": {gateReply{code: "exec_failed", msg: "package operation in progress (request id 0b5c0000-0000-4000-8000-000000000042, started 2026-10-21T12:00:00Z, may run until 2026-10-21T12:15:00Z)"}, "exec_failed"},
		"unfinished":  {gateReply{code: "exec_failed", msg: "dpkg left example-hello unfinished; an administrator must run dpkg --configure -a on the host"}, "exec_failed"},
		"removes":     {gateReply{code: "policy_denied", msg: "this install would remove 1 package (example-old)"}, "policy_denied"},
		"no hash":     {gateReply{data: fakePkgPreview("install", "nothash")}, "internal"},
	} {
		t.Run(name, func(t *testing.T) {
			a := newPrivPkgHarness(t, approval.MethodWeb)
			a.g.set("priv_pkg_install_preview", c.reply)
			env, _ := a.call("shell_priv_install_packages", args)
			if errCode(env) != c.code || env["approval"] != nil || a.count("priv_pkg_install") != 0 {
				t.Fatalf("env %v ops %v", env, a.g.ops())
			}
		})
	}
}

func TestPrivPackagesValidation(t *testing.T) {
	a := newPrivPkgHarness(t, approval.MethodWeb)
	for name, args := range map[string]map[string]any{
		"shell_priv_install_packages":     {"packages": []string{"example-hello"}, "expected_preview_sha256": shaPK},
		"shell_priv_remove_packages":      {"packages": []string{}},
		"shell_priv_upgrade_packages":     {"packages": []string{"example-hello"}},
		"shell_priv_update_package_index": {"options": []string{"-o", "Acquire::http::Proxy=x"}},
	} {
		if env, _ := a.call(name, args); errCode(env) != "validation_error" {
			t.Fatalf("%s %v: %v", name, args, env)
		}
	}
	for _, names := range [][]string{{"Example"}, {"example-hello=1.0"}, {"./example-hello.deb"}, {"-y"}, {"example-hello", "example-hello"},
		strings.Fields(strings.Repeat("example-hello ", 21))} {
		if env, _ := a.call("shell_priv_install_packages", map[string]any{"packages": names}); errCode(env) != "validation_error" {
			t.Fatalf("%q: %v", names, env)
		}
	}
	if len(a.g.requests()) != 0 {
		t.Fatalf("sent %v", a.g.ops())
	}
}

func errMessage(env map[string]any) string {
	e, _ := env["error"].(map[string]any)
	m, _ := e["message"].(string)
	return m
}
