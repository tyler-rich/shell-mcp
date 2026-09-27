package policy

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestForTestingOnlyInTests keeps trust injection out of shipped code: every
// identifier ending in "ForTesting" may be referenced only from _test.go
// files or internal/gate/gatetest, and gatetest may be imported only from
// _test.go files. A binary therefore always runs with RootTrust().
func TestForTestingOnlyInTests(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found: %v", err)
	}
	const gatetestPath = "github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	gatetestDir := filepath.Join(root, "internal", "gate", "gatetest")
	checked := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "testdata" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		checked++
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == gatetestPath {
				t.Errorf("%s imports gatetest outside a _test.go file", p)
			}
		}
		if strings.HasPrefix(p, gatetestDir) {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, "ForTesting") || strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			// The definition itself is allowed; any call or reference is not.
			if strings.HasPrefix(line, "func ") && strings.Contains(line, "ForTesting(") && !strings.Contains(line, ".") {
				continue
			}
			t.Errorf("%s:%d references a ForTesting identifier outside test code: %s", p, i+1, strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("only %d files checked; walk is broken", checked)
	}
}
