//go:build linux && (amd64 || arm64)

package execx

import (
	"syscall"
	"unsafe"
)

// setIDs makes the switch of becomeAccount: setgroups(2), setgid(2),
// setuid(2), each on every thread of the process. It is what
// syscall.Setgroups, Setgid and Setuid do in a binary without cgo
// (AllThreadsSyscall), with the ids passed as the kernel's 32-bit values
// widened to a register, never narrowed through int. On amd64 and arm64,
// D-018's architectures, SYS_SETGROUPS, SYS_SETGID and SYS_SETUID are the
// 32-bit-id calls. In a binary with cgo AllThreadsSyscall returns ENOTSUP,
// and the switch refuses.
func setIDs(c *Credential) (step string, err error) {
	// The kernel's gid_t array, converted inline as syscall.Setgroups does;
	// never empty, so that &gs[0] exists (setgroups(2) reads none of it when
	// the count is 0).
	gs := append(append([]uint32(nil), c.Groups...), 0)
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_SETGROUPS, uintptr(len(c.Groups)), uintptr(unsafe.Pointer(&gs[0])), 0); e != 0 { //nolint:gosec // G103: the gid_t array setgroups(2) reads
		return "setgroups", e
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_SETGID, uintptr(c.GID), 0, 0); e != 0 {
		return "setgid", e
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_SETUID, uintptr(c.UID), 0, 0); e != 0 {
		return "setuid", e
	}
	return "", nil
}
