package policy

import (
	"flag"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/yamltest"
)

var updateYAMLPins = flag.Bool("update", false, "rewrite testdata/yaml-pins.golden from the current YAML module")

// TestYAMLPins pins the gate policy's YAML layer (decodeStrict: strict
// fields, one document) on the yamltest corpus: what it accepts, refuses
// and decodes with go.yaml.in/yaml/v3. A new YAML module that changes any
// of it fails here (docs/ARCHIVE.md, 2026-11-08).
func TestYAMLPins(t *testing.T) {
	const head = "version: 1\nmax_tier: read\n"
	s := &yamltest.Schema{
		Base: head,
		Str:  func(v string) string { return "version: 1\nmax_tier: " + v + "\n" },
		Int:  func(v string) string { return "version: " + v + "\nmax_tier: read\n" },
		List: func(v string) string { return head + "redact:\n  patterns: " + v + "\n" },
		Bool: func(v string) string {
			return head + "commands:\n  - id: a\n    root_equivalent: " + v + "\n"
		},
		Flow:   func(inner string) string { return head + "sandbox: {" + inner + "}\n" },
		MapKey: "landlock",
	}
	yamltest.Pin(t, "testdata/yaml-pins.golden", *updateYAMLPins, s, nil, func(doc []byte) string {
		var raw rawPolicy
		if err := decodeStrict(doc, &raw); err != nil {
			return yamltest.Result(nil, err)
		}
		return yamltest.Result(raw, nil)
	})
}
