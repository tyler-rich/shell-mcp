//go:build linux

package execx_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
)

// FuzzIgnoreRLimitData: whatever the parameter file holds, the reader never
// panics, reads "set" only for Y or 1 and "not set" only for N or 0
// (surrounding whitespace aside), and is an error otherwise.
func FuzzIgnoreRLimitData(f *testing.F) {
	for _, s := range []string{"Y\n", "N\n", "1", "0", "", "y", "YY", " Y \n", "N\x00", "maybe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		p := filepath.Join(t.TempDir(), "param")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := execx.IgnoreRLimitData(p)
		v := strings.TrimSpace(content)
		if len(content) > 16 {
			v = strings.TrimSpace(content[:16])
		}
		switch v {
		case "Y", "1":
			if err != nil || !set {
				t.Fatalf("%q: %v %v, want set", content, set, err)
			}
		case "N", "0":
			if err != nil || set {
				t.Fatalf("%q: %v %v, want not set", content, set, err)
			}
		default:
			if err == nil {
				t.Fatalf("%q read as %v", content, set)
			}
		}
	})
}
