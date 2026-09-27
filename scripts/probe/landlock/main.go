//go:build linux

// Command landlock reports whether Landlock is usable by this process: the
// ABI version from landlock_create_ruleset(2) and the kernel's active LSM
// list. It is a probe for scripts/ci-local.sh and CI, not part of any binary.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func main() {
	lsm := "unreadable"
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsm = strings.TrimSpace(string(b))
	}

	// With a NULL attr, size 0 and LANDLOCK_CREATE_RULESET_VERSION the
	// syscall returns the highest supported ABI version.
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		reason := errno.Error()
		if errors.Is(errno, unix.EOPNOTSUPP) {
			reason = "compiled in but disabled at boot"
		} else if errors.Is(errno, unix.ENOSYS) {
			reason = "not compiled in, or blocked by seccomp"
		}
		fmt.Printf("landlock: unavailable (%s); lsm=%s\n", reason, lsm)
		os.Exit(3)
	}
	fmt.Printf("landlock: available, ABI %d; lsm=%s\n", abi, lsm)
}
