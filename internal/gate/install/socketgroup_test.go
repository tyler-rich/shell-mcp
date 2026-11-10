//go:build linux

package install_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
)

// The shared-account rule (docs/SECURITY.md §2, TARGET-SETUP §4): a policy
// without privileged forwarding is refused when the gate's account belongs
// to the group that owns one of the helper's sockets. Socket nodes are made
// with mknod(2) (S_IFSOCK needs no privilege and no listener); their group is
// the test process's, and each case puts that gid in the identity or not.

// runDir makes a secure helper socket directory with the named socket nodes
// and returns it and the nodes' gid.
func runDir(t *testing.T, sockets ...string) (dir string, gid uint32) {
	t.Helper()
	d := filepath.Join(gatetest.SecureDir(t), "run-shell-mcp")
	gatetest.Mkdir(t, d, 0o711)
	for _, s := range sockets {
		if err := unix.Mknod(filepath.Join(d, s), unix.S_IFSOCK|0o660, 0); err != nil {
			t.Fatal(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(d, &st); err != nil {
		t.Fatal(err)
	}
	return d, st.Gid
}

func socketEnv(dir string, forwarding bool, gids ...uint32) *install.SocketGroupEnv {
	return &install.SocketGroupEnv{
		Identity:   install.Identity{UID: serviceUID, GIDs: gids, GroupName: func(uint32) (string, error) { return "svc-shell-priv", nil }},
		RunDir:     dir,
		Forwarding: forwarding,
	}
}

func wantSocketRefusal(t *testing.T, e *install.SocketGroupEnv, detail ...string) {
	t.Helper()
	err := install.CheckSocketGroup(e)
	var ie *install.Error
	if !errors.As(err, &ie) {
		t.Fatalf("CheckSocketGroup = %v, want *install.Error", err)
	}
	for _, d := range detail {
		if !strings.Contains(ie.Detail, d) {
			t.Fatalf("detail %q does not contain %q", ie.Detail, d)
		}
	}
	if ie.Wire == "" || strings.Contains(ie.Wire, "\n") || strings.Contains(ie.Wire, e.RunDir) || strings.Contains(ie.Wire, "svc-shell-priv") {
		t.Fatalf("wire message %q must be one line naming no local path or group", ie.Wire)
	}
}

func TestSocketGroupRefusedWithoutForwarding(t *testing.T) {
	for _, sock := range install.HelperSockets {
		t.Run(sock, func(t *testing.T) {
			d, g := runDir(t, sock)
			e := socketEnv(d, false, 60123, g)
			wantSocketRefusal(t, e, filepath.Join(d, sock), "svc-shell-priv", "privileged forwarding", "second service account", "--user, --uid and --gid")
			ie := new(install.Error)
			_ = errors.As(install.CheckSocketGroup(e), &ie)
			if !strings.Contains(ie.Wire, "second service account") || !strings.Contains(ie.Wire, "shell-mcp-gate install") {
				t.Fatalf("wire message %q must name the fix", ie.Wire)
			}
		})
	}
}

func TestSocketGroupPrimaryGIDRefused(t *testing.T) {
	// The socket's group as the account's own primary group counts as well.
	d, g := runDir(t, "privd.sock")
	wantSocketRefusal(t, socketEnv(d, false, g), "privileged forwarding")
}

func TestSocketGroupAllowedWithForwarding(t *testing.T) {
	d, g := runDir(t, "privd.sock", "privd-broad.sock")
	if err := install.CheckSocketGroup(socketEnv(d, true, 60123, g)); err != nil {
		t.Fatalf("a policy with privileged forwarding: %v", err)
	}
}

func TestSocketGroupAllowedWhenNotMember(t *testing.T) {
	d, g := runDir(t, "privd.sock", "privd-broad.sock")
	if err := install.CheckSocketGroup(socketEnv(d, false, 60123, 101)); err != nil || g == 60123 || g == 101 {
		t.Fatalf("an account in no socket group: %v (socket gid %d)", err, g)
	}
}

func TestSocketGroupNoHelper(t *testing.T) {
	// No socket directory, or one without the helper's sockets: no helper
	// to reach, nothing to refuse.
	d, g := runDir(t)
	if err := install.CheckSocketGroup(socketEnv(filepath.Join(d, "absent"), false, 60123, g)); err != nil {
		t.Fatalf("absent directory: %v", err)
	}
	if err := install.CheckSocketGroup(socketEnv(d, false, 60123, g)); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	// A file of another type under a socket's name is not a socket.
	gatetest.WriteFile(t, filepath.Join(d, "privd.sock"), "not a socket", 0o640)
	if err := install.CheckSocketGroup(socketEnv(d, false, 60123, g)); err != nil {
		t.Fatalf("regular file: %v", err)
	}
}

func TestSocketGroupFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches any directory")
	}
	// The directory exists but cannot be searched: whether a socket in it
	// is reachable cannot be told, so the gate refuses.
	d, g := runDir(t, "privd.sock")
	chmod(t, d, 0o000)
	t.Cleanup(func() { chmod(t, d, 0o711) })
	wantSocketRefusal(t, socketEnv(d, false, 60123, g), d, "cannot")
	// Not even with a group the socket does not have: nothing was read.
	wantSocketRefusal(t, socketEnv(d, false, 60123), d)
	// A policy with forwarding needs no check.
	if err := install.CheckSocketGroup(socketEnv(d, true, 60123, g)); err != nil {
		t.Fatalf("forwarding: %v", err)
	}
}

func TestSocketGroupRunDirNotADirectory(t *testing.T) {
	d, g := runDir(t, "privd.sock")
	link := filepath.Join(filepath.Dir(d), "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	wantSocketRefusal(t, socketEnv(link, false, 60123), link, "not a directory")
	file := filepath.Join(filepath.Dir(d), "file")
	gatetest.WriteFile(t, file, "x", 0o644)
	wantSocketRefusal(t, socketEnv(file, false, 60123, g), file, "not a directory")
}
