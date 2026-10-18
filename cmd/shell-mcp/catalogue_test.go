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
	// The variants differ exactly where they should: destructive tools are
	// always gated; operator tools only when SHELL_MCP_APPROVAL_TIERS lists
	// operator.
	for file, want := range map[string]map[string]bool{
		"catalogue.json":         {"destructive": true},
		"catalogue-confirm.json": {"destructive": true, "operator": true},
	} {
		var rows []struct {
			Name     string `json:"name"`
			Tier     string `json:"tier"`
			Requires bool   `json:"requires_user_interaction"`
		}
		if err := json.Unmarshal(outs[file], &rows); err != nil {
			t.Fatal(err)
		}
		gated := 0
		for _, r := range rows {
			if r.Requires != want[r.Tier] {
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
