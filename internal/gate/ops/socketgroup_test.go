//go:build linux

package ops_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
)

// The shared-account rule at serve (docs/SECURITY.md §2): a policy without
// privileged forwarding, served by an account in the group that owns the
// helper's socket, is refused with install_insecure before the sandbox and
// before the request is read, whatever the op. Socket nodes are made with
// mknod(2); their group is the test process's.

// helperRunDir gives f a helper socket directory holding the named socket
// nodes and returns their gid.
func (f *fixture) helperRunDir(sockets ...string) uint32 {
	f.t.Helper()
	d := filepath.Join(f.dir, "run-shell-mcp")
	gatetest.Mkdir(f.t, d, 0o711)
	for _, s := range sockets {
		if err := unix.Mknod(filepath.Join(d, s), unix.S_IFSOCK|0o660, 0); err != nil {
			f.t.Fatal(err)
		}
	}
	f.opts.HelperRunDir = d
	var st syscall.Stat_t
	if err := syscall.Stat(d, &st); err != nil {
		f.t.Fatal(err)
	}
	// The nodes' group is the test process's: name it as the socket group.
	prev := f.opts.Identity.GroupName
	f.opts.Identity.GroupName = func(g uint32) (string, error) {
		if g == st.Gid {
			return "svc-shell-priv", nil
		}
		return prev(g)
	}
	return st.Gid
}

func (f *fixture) wantRefusedUnread(op string) string {
	f.t.Helper()
	resp, rd := f.serveRaw(`{"v":2,"id":"0b5c0000-0000-4000-8000-000000000001","ceiling":"destructive","op":"` + op + `","args":{}}` + "\n")
	if resp.OK || resp.Error == nil || resp.Error.Code != "install_insecure" || rd.read || f.sandboxCalls != 0 {
		f.t.Fatalf("%s: %+v read=%v sandbox=%d", op, resp.Error, rd.read, f.sandboxCalls)
	}
	if strings.Contains(resp.Error.Message, f.dir) || strings.Contains(resp.Error.Message, "\n") {
		f.t.Fatalf("wire message names a local path or is not one line: %q", resp.Error.Message)
	}
	return resp.Error.Message
}

func TestSharedAccountRefusedAtServe(t *testing.T) {
	for _, sock := range []string{"privd.sock", "privd-broad.sock"} {
		for _, op := range []string{"hello", "policy", "exec", "read_file"} {
			t.Run(sock+"/"+op, func(t *testing.T) {
				f := newFixture(t, "read")
				g := f.helperRunDir(sock)
				f.opts.Identity.GIDs = []uint32{60123, g, 101}
				msg := f.wantRefusedUnread(op)
				if !strings.Contains(msg, "socket group") || !strings.Contains(msg, "second service account") {
					t.Fatalf("refusal must name the cause and the fix: %q", msg)
				}
			})
		}
	}
}

func TestSharedAccountServesWithForwarding(t *testing.T) {
	f := newFixture(t, "operator")
	g := f.helperRunDir("privd.sock", "privd-broad.sock")
	f.opts.Identity.GIDs = []uint32{60123, g, 101}
	f.writePolicy("operator", "privileged:\n  enabled: true\n  socket: /run/shell-mcp/privd.sock\n  max_tier: read\n")
	f.ok("hello", m{}, nil)
	// A policy with the section but forwarding off is refused.
	f.writePolicy("operator", "privileged:\n  enabled: false\n")
	f.sandboxCalls = 0
	f.wantRefusedUnread("hello")
}

func TestSharedAccountNotMemberServes(t *testing.T) {
	f := newFixture(t, "read")
	g := f.helperRunDir("privd.sock", "privd-broad.sock")
	if g == 60123 || g == 101 {
		t.Skipf("the test process's gid %d is one of the fixture's", g)
	}
	f.opts.Identity.GIDs = []uint32{60123, 101}
	f.ok("hello", m{}, nil)
}

func TestSharedAccountNoHelperServes(t *testing.T) {
	f := newFixture(t, "read")
	g := f.helperRunDir()
	f.opts.Identity.GIDs = []uint32{60123, g}
	f.ok("hello", m{}, nil)
	f.opts.HelperRunDir = filepath.Join(f.dir, "absent")
	f.ok("hello", m{}, nil)
}

func TestSharedAccountFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches any directory")
	}
	f := newFixture(t, "read")
	f.helperRunDir("privd.sock")
	if err := os.Chmod(f.opts.HelperRunDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.opts.HelperRunDir, 0o711) }) //nolint:gosec // G302: the directory's own mode restored
	f.opts.Identity.GIDs = []uint32{60123}
	f.wantRefusedUnread("hello")
}
