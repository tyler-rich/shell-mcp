//go:build !shellmcp_diag

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/catalogue*.json from the current tools")

// catalogueVariants: the default schemas, and those under
// SHELL_MCP_APPROVAL_METHOD=confirm-argument (tools gain confirm) with
// operator tools gated (they gain requiresUserInteraction).
var catalogueVariants = map[string]map[string]string{
	"catalogue.json":         nil,
	"catalogue-confirm.json": {"SHELL_MCP_APPROVAL_METHOD": "confirm-argument", "SHELL_MCP_APPROVAL_TIERS": "operator,destructive"},
}

// TestCatalogueSnapshot: any change to a tool's name, title, tier,
// annotations, description or input/output schema changes `shell-mcp
// tools`, and so this snapshot, which review then sees (rug-pull defence,
// SECURITY §2). Regenerate with `go test ./cmd/shell-mcp -run
// TestCatalogueSnapshot -update` and review the diff.
func TestCatalogueSnapshot(t *testing.T) {
	outs := map[string][]byte{}
	for file, env := range catalogueVariants {
		t.Run(file, func(t *testing.T) { outs[file] = checkCatalogue(t, file, env) })
	}
	// The variants differ exactly where they should: destructive tools, and
	// privileged tools of tier operator, are always gated; unprivileged
	// operator tools only when SHELL_MCP_APPROVAL_TIERS lists operator;
	// read tools never (D-006).
	for file, want := range map[string]map[string]bool{
		"catalogue.json":         {"destructive": true},
		"catalogue-confirm.json": {"destructive": true, "operator": true},
	} {
		var rows []struct {
			Name       string `json:"name"`
			Tier       string `json:"tier"`
			Privileged bool   `json:"privileged"`
			Requires   bool   `json:"requires_user_interaction"`
		}
		if err := json.Unmarshal(outs[file], &rows); err != nil {
			t.Fatal(err)
		}
		gated := 0
		for _, r := range rows {
			if r.Requires != (want[r.Tier] || r.Privileged && r.Tier == "operator") {
				t.Fatalf("%s: %s (tier %s) requires_user_interaction %v", file, r.Name, r.Tier, r.Requires)
			}
			if r.Requires {
				gated++
			}
		}
		if gated == 0 {
			t.Fatalf("%s: no tool requires user interaction", file)
		}
	}
	// shell_run_command has a row per registration: operator in the
	// operator profile, destructive (destructiveHint) in admin.
	for file, out := range outs {
		var rows []struct {
			Name        string   `json:"name"`
			Tier        string   `json:"tier"`
			Profiles    []string `json:"profiles"`
			Annotations struct {
				DestructiveHint bool `json:"destructiveHint"`
			} `json:"annotations"`
		}
		if err := json.Unmarshal(out, &rows); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rows {
			if len(r.Profiles) == 0 {
				t.Fatalf("%s: %s has no profiles", file, r.Name)
			}
			if r.Name == "shell_run_command" {
				got = append(got, fmt.Sprintf("%s %v %v", r.Tier, r.Profiles, r.Annotations.DestructiveHint))
			}
		}
		if want := []string{"operator [operator] false", "destructive [admin] true"}; !slices.Equal(got, want) {
			t.Fatalf("%s: shell_run_command rows %v, want %v", file, got, want)
		}
	}
	// The privileged tools so far (S4c-1 to S4c-6): the read tools at read,
	// the write, chown, chmod and restore tools at operator, the delete and
	// command tools at destructive, admin only.
	for file, out := range outs {
		var rows []struct {
			Name       string   `json:"name"`
			Tier       string   `json:"tier"`
			Profiles   []string `json:"profiles"`
			Privileged bool     `json:"privileged"`
		}
		if err := json.Unmarshal(out, &rows); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rows {
			if r.Privileged {
				got = append(got, fmt.Sprintf("%s %s %v", r.Name, r.Tier, r.Profiles))
			}
		}
		want := []string{"shell_priv_cancel_power read [admin]", "shell_priv_change_owner operator [admin]", "shell_priv_copy_path operator [admin]", "shell_priv_delete_path destructive [admin]",
			"shell_priv_install_packages operator [admin]",
			"shell_priv_list_backups read [admin]", "shell_priv_list_directory read [admin]", "shell_priv_make_directory operator [admin]",
			"shell_priv_move_path operator [admin]", "shell_priv_preview_delete read [admin]", "shell_priv_preview_packages read [admin]",
			"shell_priv_read_file read [admin]", "shell_priv_reboot_host destructive [admin]", "shell_priv_remove_packages destructive [admin]", "shell_priv_restore_backup operator [admin]",
			"shell_priv_run_command destructive [admin]", "shell_priv_set_permissions operator [admin]", "shell_priv_stat_path read [admin]",
			"shell_priv_update_package_index operator [admin]", "shell_priv_upgrade_packages operator [admin]",
			"shell_priv_write_file operator [admin]"}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: privileged rows %v, want %v", file, got, want)
		}
	}
}

func checkCatalogue(t *testing.T, file string, env map[string]string) []byte {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(env), &out, &errb); code != 0 {
		t.Fatalf("tools exit %d: %s", code, errb.String())
	}
	golden := filepath.Join("testdata", file)
	if *update {
		if err := os.WriteFile(golden, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // G304: the fixed snapshot path
	if err != nil {
		t.Fatalf("read the snapshot (regenerate with -update): %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("the tool catalogue changed; review it and regenerate the snapshot with -update.\ngot:\n%s\nwant:\n%s", out.Bytes(), want)
	}
	// Deterministic: a second run is byte-identical.
	var again bytes.Buffer
	run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(env), &again, &errb)
	if !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Fatal("tools output is not deterministic")
	}
	for _, field := range []string{`"input_schema_sha256"`, `"output_schema_sha256"`, `"description"`, `"annotations"`, `"tier"`, `"privileged"`, `"requires_user_interaction"`} {
		if !bytes.Contains(out.Bytes(), []byte(field)) {
			t.Fatalf("catalogue lacks %s", field)
		}
	}
	return out.Bytes()
}

// TestCatalogueToolsRefusesBadApprovalSettings: tools reads only the
// approval method and tiers, and refuses values serve would refuse.
func TestCatalogueToolsRefusesBadApprovalSettings(t *testing.T) {
	for _, env := range []map[string]string{
		{"SHELL_MCP_APPROVAL_METHOD": "deny"},
		{"SHELL_MCP_APPROVAL_TIERS": "operator"},
	} {
		var out, errb bytes.Buffer
		if code := run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(env), &out, &errb); code == 0 {
			t.Fatalf("%v accepted", env)
		}
	}
}

func TestNoDiagnosticToolInThisBuild(t *testing.T) {
	var out, errb bytes.Buffer
	run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(nil), &out, &errb)
	if bytes.Contains(out.Bytes(), []byte("shell_diag_")) {
		t.Fatal("a diagnostic tool is in a normal build")
	}
	var v bytes.Buffer
	run(t.Context(), strings.NewReader(""), []string{"version"}, lookup(nil), &v, &errb)
	if strings.Contains(v.String(), "diagnostic") {
		t.Fatalf("version: %q", v.String())
	}
}
