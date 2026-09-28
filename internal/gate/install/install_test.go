//go:build linux

package install_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gatetest"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Invented group table for the tests.
var groups = map[uint32]string{
	0: "root", 27: "sudo", 10: "wheel", 4: "adm", 999: "docker", 998: "lxd", 997: "incus-admin", 996: "libvirt",
	995: "kvm", 6: "disk", 42: "shadow", 101: "systemd-journal", 60124: "svc-shell-priv", 60123: "svc-shell",
}

func lookup(gid uint32) (string, error) {
	if n, ok := groups[gid]; ok {
		return n, nil
	}
	return "", fmt.Errorf("gid %d unknown", gid)
}

// The fake service uid differs from the test uid, which is trusted.
const serviceUID = 60123

func env(t *testing.T, gids ...uint32) *install.Env {
	t.Helper()
	d := gatetest.SecureDir(t)
	exe := filepath.Join(d, "shell-mcp-gate")
	gatetest.WriteFile(t, exe, "invented", 0o755)
	return &install.Env{
		Identity:   install.Identity{UID: serviceUID, GIDs: gids, GroupName: lookup},
		Trust:      gatetest.Trust(),
		Executable: exe,
	}
}

func wantInsecure(t *testing.T, e *install.Env, detail string) {
	t.Helper()
	err := install.Check(e)
	var ie *install.Error
	if !errors.As(err, &ie) {
		t.Fatalf("Check = %v, want *install.Error", err)
	}
	if !strings.Contains(ie.Detail, detail) {
		t.Fatalf("detail %q does not contain %q", ie.Detail, detail)
	}
	if ie.Wire == "" || strings.Contains(ie.Wire, e.Executable) {
		t.Fatalf("wire message %q must be set and must not name local paths", ie.Wire)
	}
}

func TestAllowed(t *testing.T) {
	// The service group, systemd-journal and the helper socket group are fine.
	if err := install.Check(env(t, 60123, 101, 60124)); err != nil {
		t.Fatal(err)
	}
}

func TestRootRefused(t *testing.T) {
	e := env(t, 60123)
	e.Identity.UID = 0
	wantInsecure(t, e, "uid 0")
}

func TestTrustedUIDRefused(t *testing.T) {
	e := env(t, 60123)
	e.Identity.UID = install.ID(os.Getuid()) // the trusted owner in tests; uid 0 in production
	wantInsecure(t, e, "trusted owner")
}

func TestDeniedGroups(t *testing.T) {
	for gid, name := range groups {
		if !slices.Contains(install.DeniedGroups, name) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			wantInsecure(t, env(t, 60123, gid), name)
		})
	}
	if len(install.DeniedGroups) != 11 {
		t.Fatalf("deny list has %d groups", len(install.DeniedGroups))
	}
}

func TestGID0RefusedWhateverItsName(t *testing.T) {
	e := env(t, 60123, 0)
	e.Identity.GroupName = func(gid uint32) (string, error) {
		if gid == 0 {
			return "renamed", nil
		}
		return lookup(gid)
	}
	wantInsecure(t, e, "gid 0")
}

func TestUnresolvableGroupRefused(t *testing.T) {
	wantInsecure(t, env(t, 60123, 4242), "4242")
}

func TestSSHOriginalCommand(t *testing.T) {
	hello := protocol.Hello
	e := env(t, 60123)
	e.SSHOriginalCommand = &hello
	if err := install.Check(e); err != nil {
		t.Fatalf("hello refused: %v", err)
	}
	for _, v := range []string{"", "shell-mcp-gate/2", "shell-mcp-gate/1 ", "ls -la", "shell-mcp-gate/1;id"} {
		v := v
		e.SSHOriginalCommand = &v
		wantInsecure(t, e, "SSH_ORIGINAL_COMMAND")
	}
}

func TestExecutableOwnership(t *testing.T) {
	e := env(t, 60123)
	chmod(t, e.Executable, 0o775)
	wantInsecure(t, e, "writable")
	chmod(t, e.Executable, 0o755)
	chmod(t, filepath.Dir(e.Executable), 0o777)
	wantInsecure(t, e, "writable")
	chmod(t, filepath.Dir(e.Executable), 0o700)
	e.Executable = filepath.Dir(e.Executable)
	wantInsecure(t, e, "regular")
}

func TestCurrent(t *testing.T) {
	id, err := install.Current()
	if err != nil {
		t.Fatal(err)
	}
	if id.UID != install.ID(os.Getuid()) || !slices.Contains(id.GIDs, install.ID(os.Getgid())) || id.GroupName == nil {
		t.Fatalf("Current() = %+v", id)
	}
}

// chmod sets a fixture mode, including the deliberately insecure ones under test.
func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}
