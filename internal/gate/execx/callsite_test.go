//go:build linux

package execx_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const execxImport = "github.com/tyler-rich/shell-mcp/internal/gate/execx"

// credentialCaller is the only package that may use Spec.Credential:
// shell-mcp-gate install's check-policy step.
const credentialCaller = "internal/gate/setup"

// moduleRoot is the directory holding go.mod, above the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		up := filepath.Dir(d)
		if up == d {
			t.Fatal("no go.mod above the test's directory")
		}
		d = up
	}
}

// credentialUse is one place a non-test file of the module names the
// credential option.
type credentialUse struct {
	file string
	pos  token.Position
	set  bool // a composite-literal key or an assignment: the option is set
}

// credentialUses parses every non-test Go file of the module outside execx
// itself and reports each mention of execx.Credential, of a Credential key in
// a composite literal, and of a .Credential field, in files that import
// execx.
func credentialUses(t *testing.T, root string) []credentialUse {
	t.Helper()
	var uses []credentialUse
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "testdata" || n == "vendor" || rel == "internal/gate/execx" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		alias := ""
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == execxImport {
				alias = "execx"
				if im.Name != nil {
					alias = im.Name.Name
				}
			}
		}
		if alias == "" {
			return nil
		}
		assigned := map[ast.Expr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, l := range as.Lhs {
					assigned[l] = true
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Credential" {
					uses = append(uses, credentialUse{rel, fset.Position(x.Pos()), true})
				}
			case *ast.SelectorExpr:
				if x.Sel.Name == "Credential" {
					uses = append(uses, credentialUse{rel, fset.Position(x.Pos()), assigned[x]})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return uses
}

// TestCredentialCallSites: nothing outside internal/gate/setup names the
// credential option, so serve (cmd/shell-mcp-gate and every other gate
// package), the helper (cmd/shell-mcp-privd, internal/privd) and the server
// (cmd/shell-mcp, the rest of internal) never set it; inside it the option
// is set in exactly one place: the check-policy step's RunAs.
func TestCredentialCallSites(t *testing.T) {
	uses := credentialUses(t, moduleRoot(t))
	sets := 0
	for _, u := range uses {
		if filepath.ToSlash(filepath.Dir(u.file)) != credentialCaller {
			t.Errorf("%s: names execx's credential option; only %s may (TARGET-SETUP §12.1)", u.pos, credentialCaller)
			continue
		}
		if u.set {
			sets++
		}
	}
	if sets != 1 {
		t.Errorf("%s sets the credential option in %d places, want exactly 1 (install's check-policy step)", credentialCaller, sets)
	}
}
