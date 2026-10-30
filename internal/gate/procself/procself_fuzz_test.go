//go:build linux

package procself_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/procself"
)

// FuzzValidName: an accepted name is local and already clean (it can only
// name something under the directory), and is never "." or "..".
func FuzzValidName(f *testing.F) {
	for _, s := range []string{"status", "task", "task/10/children", "fd/3", "", "..", "../x", "a//b", "/abs", "a/./b", "a\x00b", "a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !procself.ValidName(name) {
			return
		}
		if !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." {
			t.Fatalf("accepted %q", name)
		}
		for _, p := range strings.Split(name, "/") {
			if p == ".." || p == "." || p == "" {
				t.Fatalf("accepted %q", name)
			}
		}
	})
}
