//go:build linux && (amd64 || arm64)

package execx

import (
	"fmt"
	"syscall"
	"unsafe"
)

// allThreadsFunc is syscall.AllThreadsSyscall's signature; production
// passes syscall.AllThreadsSyscall, tests a stub.
type allThreadsFunc func(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// setIDsWith makes the switch of becomeAccount through sys (production:
// syscall.AllThreadsSyscall): setgroups(2), setgid(2), setuid(2), each on
// every thread of the process. It is what syscall.Setgroups, Setgid
// and Setuid do in a binary without cgo (AllThreadsSyscall), with the ids
// passed as the kernel's 32-bit values widened to a register, never
// narrowed through int. On amd64 and arm64, D-018's architectures,
// SYS_SETGROUPS, SYS_SETGID and SYS_SETUID are the 32-bit-id calls. In a
// binary with cgo AllThreadsSyscall returns ENOTSUP, and the switch
// refuses.
func setIDsWith(c *Credential, sys allThreadsFunc) (step string, err error) {
	// setgroups(2) exactly as syscall.Setgroups passes it (Go 1.27.3,
	// syscall_linux.go): no groups is (0, NULL); otherwise a fresh gid_t
	// array whose pointer is converted to uintptr in the argument list
	// itself (unsafe.Pointer rule 4). AllThreadsSyscall is
	// //go:uintptrescapes, so the compiler keeps the array on the heap and
	// alive until the call returns; setgroups(2) copies it, and nothing
	// reads it after. syscall.Setgroups needs no runtime.KeepAlive for the
	// same reason.
	if len(c.Groups) == 0 {
		if _, _, e := sys(syscall.SYS_SETGROUPS, 0, 0, 0); e != 0 {
			return "setgroups", e
		}
	} else {
		a := make([]uint32, len(c.Groups)) // _Gid_t is uint32 on amd64 and arm64
		copy(a, c.Groups)
		if _, _, e := sys(syscall.SYS_SETGROUPS, uintptr(len(a)), uintptr(unsafe.Pointer(&a[0])), 0); e != 0 { //nolint:gosec // G103: the gid_t array setgroups(2) reads, as in syscall.Setgroups
			return "setgroups", e
		}
	}
	if _, _, e := sys(syscall.SYS_SETGID, uintptr(c.GID), 0, 0); e != 0 {
		return "setgid", e
	}
	if _, _, e := sys(syscall.SYS_SETUID, uintptr(c.UID), 0, 0); e != 0 {
		return "setuid", e
	}
	return "", nil
}

// credentialSupported says whether this binary can make the switch.
func credentialSupported() error { return credentialSupportedWith(syscall.AllThreadsSyscall) }

// credentialSupportedWith is credentialSupported through sys.
func credentialSupportedWith(sys allThreadsFunc) error {
	// getpid(2) changes nothing; AllThreadsSyscall runs it on every thread,
	// or returns ENOTSUP at once when cgo is linked (its threads are not
	// the runtime's to reach).
	switch _, _, e := sys(syscall.SYS_GETPID, 0, 0, 0); {
	case e == syscall.ENOTSUP:
		return fmt.Errorf("this binary links cgo, so syscall.AllThreadsSyscall cannot reach every thread (%w); the credential option needs a CGO_ENABLED=0 build, as every release build is", e)
	case e != 0:
		return fmt.Errorf("syscall.AllThreadsSyscall cannot be used here: %w", e)
	}
	return nil
}
