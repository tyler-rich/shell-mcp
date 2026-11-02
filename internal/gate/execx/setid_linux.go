//go:build linux && (amd64 || arm64)

package execx

import (
	"syscall"
	"unsafe"
)

// allThreadsFunc is syscall.AllThreadsSyscall's signature; production
// passes syscall.AllThreadsSyscall, tests a stub.
type allThreadsFunc func(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// setIDs makes the switch of becomeAccount: setgroups(2), setgid(2),
// setuid(2), each on every thread of the process.
func setIDs(c *Credential) (step string, err error) { return setIDsWith(c, syscall.AllThreadsSyscall) }

// setIDsWith is setIDs through sys. It is what syscall.Setgroups, Setgid
// and Setuid do in a binary without cgo (AllThreadsSyscall), with the ids
// passed as the kernel's 32-bit values widened to a register, never
// narrowed through int. On amd64 and arm64, D-018's architectures,
// SYS_SETGROUPS, SYS_SETGID and SYS_SETUID are the 32-bit-id calls. In a
// binary with cgo AllThreadsSyscall returns ENOTSUP, and the switch
// refuses.
func setIDsWith(c *Credential, sys allThreadsFunc) (step string, err error) {
	gs := append(append([]uint32(nil), c.Groups...), 0)
	if _, _, e := sys(syscall.SYS_SETGROUPS, uintptr(len(c.Groups)), uintptr(unsafe.Pointer(&gs[0])), 0); e != 0 { //nolint:gosec // G103: the gid_t array setgroups(2) reads
		return "setgroups", e
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
func credentialSupportedWith(allThreadsFunc) error { return nil } // stub
