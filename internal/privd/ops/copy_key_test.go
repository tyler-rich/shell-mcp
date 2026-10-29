//go:build linux

package ops_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// priv_copy searches its whole source for a private key, as priv_read_file
// does since S7-1, not only the first 64 KiB (S7-3): a source whose key
// lies past them is refused and nothing is written or backed up. Keys are
// generated for each run; every path is invented.
func TestPrivCopySourceKeyBeyondFirstWindow(t *testing.T) {
	t.Parallel()
	f := newFixture(t, replace("max_read_bytes: 65536", "max_read_bytes: 1048576"))
	key, body := freshKey(t)
	filler := strings.Repeat("log line of ordinary text\n", 4000) // about 100 KiB
	src := filepath.Join(f.read, "late.log")
	dst := filepath.Join(f.write, "late.copy")
	gatetest.WriteFile(t, src, filler+key+"after\n", 0o644)
	f.fail("priv_copy", m{"source": src, "destination": dst}, "path_denied")
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatalf("the destination exists: %v", err)
	}
	// Over an existing file: refused before any backup.
	gatetest.WriteFile(t, dst, "kept\n", 0o640)
	f.fail("priv_copy", m{"source": src, "destination": dst, "overwrite": true}, "path_denied")
	if readFile(t, dst) != "kept\n" {
		t.Fatal("the destination changed")
	}
	for _, n := range f.backupFiles() {
		if strings.HasSuffix(n, ".data") {
			t.Fatalf("a backup was written: %v", f.backupFiles())
		}
	}
	for _, a := range f.auditLines() {
		if leaks(a, body) {
			t.Fatalf("an audit line shows the key: %s", a)
		}
	}
	// The same source without the key is copied.
	gatetest.WriteFile(t, src, filler+filler, 0o644)
	f.ok("priv_copy", m{"source": src, "destination": filepath.Join(f.write, "plain.copy")}, nil)
}
