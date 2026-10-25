//go:build e2e && linux

package e2e

import (
	"os"
	"testing"
)

// Create-only commits in the privileged helper's core unit, with its
// Landlock ruleset and systemd sandbox in force: priv_write_file with
// expect_absent creates (the hard-link commit is allowed there) and refuses
// an existing file; priv_copy and priv_move without overwrite refuse an
// existing destination (renameat2 with RENAME_NOREPLACE for the move).
// Paths are the invented e2e write root.
func TestHelperCreateOnly(t *testing.T) {
	dir := "/etc/example-app/e2e-create"
	mustGate(t, "priv_mkdir", map[string]any{"path": dir, "mode": "0750"}, nil)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := dir + "/created.conf"
	var w struct {
		Created  bool `json:"created"`
		Verified bool `json:"verified"`
	}
	mustGate(t, "priv_write_file", map[string]any{"path": p, "content_b64": "bmV3Cg==", "expect_absent": true}, &w) // "new\n"
	if !w.Created || !w.Verified || readFile(t, p) != "new\n" {
		t.Fatalf("create %+v content %q", w, readFile(t, p))
	}
	wantGate(t, svcShell, "priv_write_file", map[string]any{"path": p, "content_b64": "eAo=", "expect_absent": true}, "exists")
	other := dir + "/other.conf"
	mustGate(t, "priv_write_file", map[string]any{"path": other, "content_b64": "b3RoZXIK"}, nil) // "other\n"
	wantGate(t, svcShell, "priv_copy", map[string]any{"source": p, "destination": other}, "exists")
	wantGate(t, svcShell, "priv_move", map[string]any{"source": p, "destination": other}, "exists")
	if readFile(t, p) != "new\n" || readFile(t, other) != "other\n" {
		t.Fatalf("a refused operation changed a file: %q %q", readFile(t, p), readFile(t, other))
	}
	// Without a destination, both commit.
	mustGate(t, "priv_copy", map[string]any{"source": p, "destination": dir + "/copy.conf"}, nil)
	mustGate(t, "priv_move", map[string]any{"source": dir + "/copy.conf", "destination": dir + "/moved.conf"}, nil)
	if readFile(t, dir+"/moved.conf") != "new\n" {
		t.Fatal("move did not commit")
	}
}
