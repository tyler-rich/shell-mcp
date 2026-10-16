//go:build !shellmcp_diag

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/catalogue.json from the current tools")

// TestCatalogueSnapshot: any change to a tool's name, title, tier,
// annotations, description or input/output schema changes `shell-mcp
// tools`, and so this snapshot, which review then sees (rug-pull defence,
// SECURITY §2). Regenerate with `go test ./cmd/shell-mcp -run
// TestCatalogueSnapshot -update` and review the diff.
func TestCatalogueSnapshot(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(nil), &out, &errb); code != 0 {
		t.Fatalf("tools exit %d: %s", code, errb.String())
	}
	golden := filepath.Join("testdata", "catalogue.json")
	if *update {
		if err := os.WriteFile(golden, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read the snapshot (regenerate with -update): %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("the tool catalogue changed; review it and regenerate the snapshot with -update.\ngot:\n%s\nwant:\n%s", out.Bytes(), want)
	}
	// Deterministic: a second run is byte-identical.
	var again bytes.Buffer
	run(t.Context(), strings.NewReader(""), []string{"tools"}, lookup(nil), &again, &errb)
	if !bytes.Equal(out.Bytes(), again.Bytes()) {
		t.Fatal("tools output is not deterministic")
	}
	for _, field := range []string{`"input_schema_sha256"`, `"output_schema_sha256"`, `"description"`, `"annotations"`, `"tier"`, `"privileged"`} {
		if !bytes.Contains(out.Bytes(), []byte(field)) {
			t.Fatalf("catalogue lacks %s", field)
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
