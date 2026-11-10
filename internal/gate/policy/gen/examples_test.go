package gen_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy/gen"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// examples is the repository's examples directory.
var examples = filepath.Join("..", "..", "..", "..", "examples")

func readFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: this repository's own files
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeFile(t *testing.T, p string) *gen.Answers {
	t.Helper()
	a, err := gen.Decode(readFile(t, p))
	if err != nil || a == nil {
		t.Fatalf("%s: %v", p, err)
	}
	return a
}

// TestPresetsAreTheExamples: each embedded preset is the example file it
// names, byte for byte (POLICY §9.2), so the examples and the generator
// cannot drift.
func TestPresetsAreTheExamples(t *testing.T) {
	for _, name := range []string{gen.PresetReadOnly, gen.PresetOperator, gen.PresetAdmin} {
		got, err := gen.Preset(name)
		if err != nil {
			t.Fatal(err)
		}
		if want := readFile(t, filepath.Join(examples, "policies", name+".yaml")); !bytes.Equal(got, want) {
			t.Errorf("internal/gate/policy/gen/presets/%s.yaml differs from examples/policies/%s.yaml: copy the example", name, name)
		}
	}
	if _, err := gen.Preset("root"); err == nil {
		t.Error("an unknown preset was accepted")
	}
}

// TestExamplesReproduced: each example's own answers file renders it byte
// for byte (POLICY §9.2).
func TestExamplesReproduced(t *testing.T) {
	for _, name := range []string{gen.PresetReadOnly, gen.PresetOperator, gen.PresetAdmin} {
		t.Run(name, func(t *testing.T) {
			a := decodeFile(t, filepath.Join(examples, "policies", name+".answers.yaml"))
			got, err := gen.RenderGate(a)
			if err != nil {
				t.Fatal(err)
			}
			want := readFile(t, filepath.Join(examples, "policies", name+".yaml"))
			if !bytes.Equal(got, want) {
				t.Errorf("examples/policies/%s.answers.yaml does not render examples/policies/%s.yaml:\n%s", name, name,
					setupx.UnifiedDiff("example", "rendered", want, got))
			}
		})
	}
}
