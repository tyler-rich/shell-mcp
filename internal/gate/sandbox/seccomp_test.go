//go:build linux

package sandbox

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// runBPF interprets a classic-BPF seccomp program over a seccomp_data
// record (nr, arch, instruction_pointer, args[6]; little endian). It
// supports exactly the instructions a seccomp filter of this shape uses and
// fails the test on anything else, or on falling off the end.
func runBPF(t *testing.T, prog []unix.SockFilter, arch, nr uint32, args [6]uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if int(in.K)+4 > len(data) {
				t.Fatalf("load past seccomp_data at %d", in.K)
			}
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if acc&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JA:
			pc += int(in.K)
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unexpected instruction %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

const (
	allow    = unix.SECCOMP_RET_ALLOW
	noProto  = unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT)
	eperm    = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	x32Bit   = 0x40000000
	i386Sock = 359
	i386Call = 102
	armSock  = 281
	x86Sock  = 41
)

func TestMPTCPFilter(t *testing.T) {
	prog := mptcpFilter()
	if len(prog) == 0 || len(prog) > 64 {
		t.Fatalf("program has %d instructions", len(prog))
	}
	sock := func(domain, typ, proto uint64) [6]uint64 { return [6]uint64{domain, typ, proto} }
	cases := []struct {
		name     string
		arch, nr uint32
		args     [6]uint64
		want     uint32
	}{
		{"x86_64 inet mptcp", unix.AUDIT_ARCH_X86_64, x86Sock, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), noProto},
		{"x86_64 inet6 mptcp cloexec", unix.AUDIT_ARCH_X86_64, x86Sock, sock(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_MPTCP), noProto},
		{"x86_64 mptcp high bits ignored like the kernel's int", unix.AUDIT_ARCH_X86_64, x86Sock, sock(unix.AF_INET|1<<40, unix.SOCK_STREAM, unix.IPPROTO_MPTCP|1<<33), noProto},
		{"x86_64 inet tcp", unix.AUDIT_ARCH_X86_64, x86Sock, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP), allow},
		{"x86_64 inet default proto", unix.AUDIT_ARCH_X86_64, x86Sock, sock(unix.AF_INET6, unix.SOCK_STREAM, 0), allow},
		{"x86_64 unix with mptcp number", unix.AUDIT_ARCH_X86_64, x86Sock, sock(unix.AF_UNIX, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), allow},
		{"x86_64 other syscall with the same args", unix.AUDIT_ARCH_X86_64, 0, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), allow},
		{"x86_64 x32 socket", unix.AUDIT_ARCH_X86_64, x32Bit | x86Sock, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), eperm},
		{"x86_64 x32 read", unix.AUDIT_ARCH_X86_64, x32Bit, [6]uint64{}, eperm},
		{"aarch64 inet mptcp", unix.AUDIT_ARCH_AARCH64, 198, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), noProto},
		{"aarch64 inet tcp", unix.AUDIT_ARCH_AARCH64, 198, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP), allow},
		{"aarch64 x86 socket number is another syscall", unix.AUDIT_ARCH_AARCH64, 41, sock(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), allow},
		{"i386 socket", unix.AUDIT_ARCH_I386, i386Sock, sock(unix.AF_INET, unix.SOCK_STREAM, 0), eperm},
		{"i386 socketcall", unix.AUDIT_ARCH_I386, i386Call, [6]uint64{1}, eperm},
		{"i386 read", unix.AUDIT_ARCH_I386, 3, [6]uint64{}, allow},
		{"arm compat socket", unix.AUDIT_ARCH_ARM, armSock, sock(unix.AF_INET, unix.SOCK_STREAM, 0), eperm},
		{"arm compat read", unix.AUDIT_ARCH_ARM, 3, [6]uint64{}, allow},
		{"unknown arch", 0x12345678, 0, [6]uint64{}, eperm},
	}
	for _, c := range cases {
		if got := runBPF(t, prog, c.arch, c.nr, c.args); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
}
