//go:build linux

package system_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx/system"
)

// TestSystemRunRefusesOtherPrograms: the real host runs only the
// installers' programs, by their absolute paths.
func TestSystemRunRefusesOtherPrograms(t *testing.T) {
	s, err := system.NewSystem()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/bin/sh", "/usr/bin/sudo", "useradd", "/usr/bin/passwd", "/usr/sbin/runuser"} {
		if _, err := s.Run(p); !errors.Is(err, setupx.ErrProgram) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if want := []string{setupx.Systemctl, setupx.SystemdAnalyze, setupx.Groupadd, setupx.Sshd, setupx.Useradd, setupx.Usermod}; !reflect.DeepEqual(setupx.Programs(), want) {
		t.Fatalf("programs %v", setupx.Programs())
	}
}
