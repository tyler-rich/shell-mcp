package compose

import (
	"flag"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/yamltest"
)

var updateYAMLPins = flag.Bool("update", false, "rewrite testdata/yaml-pins.golden from the current YAML module")

// TestYAMLPins pins scalar's decisions with go.yaml.in/yaml/v3: a value is
// written plain only when YAML reads it back as the same string. A new YAML
// module that changes any of it fails here (docs/ARCHIVE.md, 2026-11-08).
func TestYAMLPins(t *testing.T) {
	yamltest.PinCases(t, "testdata/yaml-pins.golden", *updateYAMLPins, yamltest.Scalars(), func(s []byte) string {
		return yamltest.Result(scalar(string(s)), nil)
	})
}
