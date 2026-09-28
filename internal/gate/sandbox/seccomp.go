//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// MPTCP handling. Landlock's TCP rights apply only to IPPROTO_TCP sockets
// (kernel Erratum 1; tracked upstream), so a Multipath TCP socket — the
// default for Go's net.Listen since Go 1.24 — would escape "no TCP bind;
// connect only to listed ports". After Landlock, the gate installs a
// seccomp filter that makes socket(AF_INET|AF_INET6, *, IPPROTO_MPTCP) fail
// with EPROTONOSUPPORT, which programs (Go included) treat as "MPTCP not
// supported" and fall back to plain TCP, which Landlock governs. Nothing
// else is filtered, except syscalls from other ABIs that could reach
// socket() without passing the native check: x32 on x86_64 (all denied),
// i386 on x86_64 (socket, socketcall) and ARM EABI on aarch64 (socket; EABI
// has no socketcall) get EPERM. An architecture value these kernels cannot
// produce gets EPERM for every syscall (fail closed).

// Constants verified at the source (golang.org/x/sys/unix zerrors and
// zsysnum files; Go's net/mptcpsock_linux.go has IPPROTO_MPTCP = 0x106).
const (
	x32SyscallBit  = 0x40000000 // __X32_SYSCALL_BIT
	nrSocketX86_64 = 41
	nrSocketARM64  = 198
	nrSocketI386   = 359
	nrSocketcall   = 102 // i386
	nrSocketARM    = 281 // ARM EABI compat
	offNR          = 0   // seccomp_data.nr
	offArch        = 4   // seccomp_data.arch
	offArg0        = 16  // low 32 bits of args[0] (little endian)
	offArg2        = 32  // low 32 bits of args[2]
)

// Return values: errno is in the low 16 bits of SECCOMP_RET_ERRNO.
const (
	retEPERM   = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retNoProto = unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT)
)

// MPTCPStatus is how hello reports MPTCP handling.
const MPTCPStatus = "blocked by seccomp"

// insn is one instruction of the tiny assembler below: jumps name labels,
// an empty jump label means "the next instruction".
type insn struct {
	label  string
	op     unix.SockFilter
	jt, jf string
}

func ld(off uint32) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off}
}

func ret(k uint32) unix.SockFilter { return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k} }

func jeq(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k}
}

func jset(k uint32) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: k}
}

// assemble resolves labels to relative jump offsets.
func assemble(src []insn) []unix.SockFilter {
	pos := map[string]int{}
	for i, in := range src {
		if in.label != "" {
			pos[in.label] = i
		}
	}
	rel := func(from int, label string) uint8 {
		if label == "" {
			return 0
		}
		target, ok := pos[label]
		d := target - from - 1
		if !ok || d < 0 || d > math.MaxUint8 {
			panic("seccomp: bad jump to " + label) // a programming error, caught by TestMPTCPFilter
		}
		return uint8(d)
	}
	out := make([]unix.SockFilter, len(src))
	for i, in := range src {
		out[i] = in.op
		out[i].Jt = rel(i, in.jt)
		out[i].Jf = rel(i, in.jf)
	}
	return out
}

// mptcpFilter returns the seccomp program described above.
func mptcpFilter() []unix.SockFilter {
	return assemble([]insn{
		{op: ld(offArch)},
		{op: jeq(unix.AUDIT_ARCH_X86_64), jt: "x86_64"},
		{op: jeq(unix.AUDIT_ARCH_AARCH64), jt: "aarch64"},
		{op: jeq(unix.AUDIT_ARCH_I386), jt: "i386"},
		{op: jeq(unix.AUDIT_ARCH_ARM), jt: "arm"},
		{op: ret(retEPERM)}, // an architecture these kernels cannot produce

		{label: "x86_64", op: ld(offNR)},
		{op: jset(x32SyscallBit), jt: "deny"},
		{op: jeq(nrSocketX86_64), jt: "args", jf: "allow"},

		{label: "aarch64", op: ld(offNR)},
		{op: jeq(nrSocketARM64), jt: "args", jf: "allow"},

		{label: "i386", op: ld(offNR)},
		{op: jeq(nrSocketI386), jt: "deny"},
		{op: jeq(nrSocketcall), jt: "deny", jf: "allow"},

		{label: "arm", op: ld(offNR)},
		{op: jeq(nrSocketARM), jt: "deny", jf: "allow"},

		// socket(domain, type, protocol): the kernel reads int arguments,
		// so only the low 32 bits are compared.
		{label: "args", op: ld(offArg0)},
		{op: jeq(unix.AF_INET), jt: "proto"},
		{op: jeq(unix.AF_INET6), jt: "proto", jf: "allow"},
		{label: "proto", op: ld(offArg2)},
		{op: jeq(unix.IPPROTO_MPTCP), jt: "noproto", jf: "allow"},

		{label: "allow", op: ret(unix.SECCOMP_RET_ALLOW)},
		{label: "deny", op: ret(retEPERM)},
		{label: "noproto", op: ret(retNoProto)},
	})
}

// errSeccomp wraps a failure to install the filter.
var errSeccomp = errors.New("seccomp filter could not be installed")

// applySeccomp installs the filter on every thread with the same all-thread
// mechanism as no_new_privs (psx: syscall.AllThreadsSyscall with
// CGO_ENABLED=0). no_new_privs must already be set. Children inherit it.
func applySeccomp() error {
	f := mptcpFilter()
	n := len(f)
	if n == 0 || n > math.MaxUint16 {
		return fmt.Errorf("%w: program has %d instructions", errSeccomp, n)
	}
	prog := unix.SockFprog{Len: uint16(n), Filter: &f[0]}
	err := llsys.AllThreadsPrctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)), 0, 0) //nolint:gosec // G103: prctl(PR_SET_SECCOMP) takes a pointer to the sock_fprog; both are kept alive below
	runtime.KeepAlive(&prog)
	runtime.KeepAlive(f)
	if err != nil {
		return fmt.Errorf("%w: %w", errSeccomp, err)
	}
	return nil
}
