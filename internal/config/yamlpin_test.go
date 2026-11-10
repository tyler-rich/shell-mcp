package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/yamltest"
)

var updateYAMLPins = flag.Bool("update", false, "rewrite testdata/yaml-pins.golden from the current YAML module")

// TestYAMLPins pins the targets file's YAML layer (readTargetsFile: strict
// fields, one document) on the yamltest corpus: what it accepts, refuses
// and decodes with go.yaml.in/yaml/v3. A new YAML module that changes any
// of it fails here (docs/ARCHIVE.md, 2026-11-08).
func TestYAMLPins(t *testing.T) {
	const head = "targets:\n  - name: a\n"
	s := &yamltest.Schema{
		Base:   head,
		Str:    func(v string) string { return "targets:\n  - name: " + v + "\n" },
		Int:    func(v string) string { return head + "    port: " + v + "\n" },
		List:   func(v string) string { return head + "    host_keys: " + v + "\n" },
		Flow:   func(inner string) string { return "targets:\n  - {" + inner + "}\n" },
		MapKey: "name",
	}
	p := filepath.Join(t.TempDir(), "targets.yaml")
	l := &loader{}
	yamltest.Pin(t, "testdata/yaml-pins.golden", *updateYAMLPins, s, nil, func(doc []byte) string {
		if err := os.WriteFile(p, doc, 0o600); err != nil {
			t.Fatal(err)
		}
		return yamltest.Result(l.readTargetsFile(p))
	})
}
