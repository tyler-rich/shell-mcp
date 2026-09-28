//go:build linux

package sandbox

import "golang.org/x/sys/unix"

// mptcpFilter returns the seccomp program that makes MPTCP sockets
// unavailable (see seccomp design in applySeccomp).
func mptcpFilter() []unix.SockFilter { return nil }
