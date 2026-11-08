//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
)

// check-policy reports the shared-account rule (docs/SECURITY.md §2) as serve
// applies it: a FAIL when the policy has no privileged forwarding and the
// account belongs to the group of one of the helper's sockets. The identity
// and the socket directory are the test's (invented ids; socket nodes made
// with mknod(2), in the test process's group).

const sharedFail = "FAIL install: gate process belongs to group"

// sharedAccount runs check-policy on a policy with the given privileged
// section, as an account in the given groups, with a helper socket directory
// holding the named sockets (dir "" for none), and returns its output. Under
// test trust the policy loads; the identity is not the test process's, so the
// install line may fail for its binary too, which these tests ignore.
func sharedAccount(t *testing.T, priv string, sockets []string, member bool) (code int, out string) {
	t.Helper()
	d := gatetest.SecureDir(t)
	run := filepath.Join(d, "run-shell-mcp")
	gatetest.Mkdir(t, run, 0o711)
	for _, s := range sockets {
		if err := unix.Mknod(filepath.Join(run, s), unix.S_IFSOCK|0o660, 0); err != nil {
			t.Fatal(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(run, &st); err != nil {
		t.Fatal(err)
	}
	gids := []uint32{60123}
	if member {
		gids = append(gids, st.Gid)
	} else if st.Gid == 60123 {
		t.Skip("the test process's gid is the fixture's")
	}
	defer func(f func() (install.Identity, error), r string) { currentIdentity, helperRunDir = f, r }(currentIdentity, helperRunDir)
	currentIdentity = func() (install.Identity, error) {
		return install.Identity{UID: 60123, GIDs: gids, GroupName: func(g uint32) (string, error) {
			if g == 60123 {
				return "svc-shell", nil
			}
			return fmt.Sprintf("svc-shell-priv-%d", g), nil
		}}, nil
	}
	helperRunDir = run
	p := filepath.Join(d, "etc", "policy.yaml")
	gatetest.WriteFile(t, p, "version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\n"+priv, 0o644)
	gatetest.Mkdir(t, filepath.Join(d, "home"), 0o755)
	var o, e bytes.Buffer
	code = checkPolicyWith([]string{"--policy", p}, &o, &e, gatetest.Trust(), filepath.Join(d, "home"))
	return code, o.String()
}

func TestCheckPolicySharedAccountFails(t *testing.T) {
	for _, sock := range install.HelperSockets {
		t.Run(sock, func(t *testing.T) {
			code, out := sharedAccount(t, "", []string{sock}, true)
			if code != 1 || !strings.Contains(out, sharedFail) || !strings.Contains(out, "privileged forwarding") ||
				!strings.Contains(out, "second service account") || !strings.Contains(out, sock) ||
				!strings.Contains(out, "serve would refuse with install_insecure") {
				t.Fatalf("check-policy: %d\n%s", code, out)
			}
		})
	}
	// privileged.enabled: false is no forwarding.
	if code, out := sharedAccount(t, "privileged:\n  enabled: false\n", []string{"privd.sock"}, true); code != 1 || !strings.Contains(out, sharedFail) {
		t.Fatalf("enabled false: %d\n%s", code, out)
	}
}

func TestCheckPolicySharedAccountForwardingOK(t *testing.T) {
	_, out := sharedAccount(t, "privileged:\n  enabled: true\n  socket: /run/shell-mcp/privd.sock\n  max_tier: read\n", install.HelperSockets, true)
	if strings.Contains(out, sharedFail) || !strings.Contains(out, "ok   install: privileged forwarding is enabled") {
		t.Fatalf("check-policy with forwarding:\n%s", out)
	}
}

func TestCheckPolicySharedAccountNotMemberOK(t *testing.T) {
	_, out := sharedAccount(t, "", install.HelperSockets, false)
	if strings.Contains(out, sharedFail) || !strings.Contains(out, "ok   install: this account is not in the group of the helper's sockets") {
		t.Fatalf("check-policy, not a member:\n%s", out)
	}
}

func TestCheckPolicySharedAccountFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches any directory")
	}
	d := gatetest.SecureDir(t)
	run := filepath.Join(d, "run-shell-mcp")
	gatetest.Mkdir(t, run, 0o711)
	if err := unix.Mknod(filepath.Join(run, "privd.sock"), unix.S_IFSOCK|0o660, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(run, 0o711) }) //nolint:gosec // G302: the directory's own mode restored
	defer func(f func() (install.Identity, error), r string) { currentIdentity, helperRunDir = f, r }(currentIdentity, helperRunDir)
	currentIdentity = func() (install.Identity, error) {
		return install.Identity{UID: 60123, GIDs: []uint32{60123}, GroupName: func(uint32) (string, error) { return "svc-shell", nil }}, nil
	}
	helperRunDir = run
	p := filepath.Join(d, "etc", "policy.yaml")
	gatetest.WriteFile(t, p, "version: 1\nmax_tier: read\nsandbox:\n  landlock: best-effort\n", 0o644)
	gatetest.Mkdir(t, filepath.Join(d, "home"), 0o755)
	var o, e bytes.Buffer
	code := checkPolicyWith([]string{"--policy", p}, &o, &e, gatetest.Trust(), filepath.Join(d, "home"))
	if code != 1 || !strings.Contains(o.String(), "FAIL install: cannot tell whether") || !strings.Contains(o.String(), run) {
		t.Fatalf("check-policy, unreadable socket directory: %d\n%s", code, o.String())
	}
}
