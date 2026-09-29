//go:build e2e && linux

// Package e2e runs the gate and the privileged helper against a real
// systemd, journald and polkit on a disposable machine prepared by
// setup.sh. It is built only with -tags e2e and runs as root.
package e2e

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		fmt.Println("the e2e tests run as root on a disposable systemd machine prepared by test/e2e/setup.sh")
		os.Exit(1)
	}
	os.Exit(m.Run())
}
