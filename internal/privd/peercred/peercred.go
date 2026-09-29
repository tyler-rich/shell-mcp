//go:build linux

// Package peercred authenticates the privileged helper's caller by the
// kernel's SO_PEERCRED on the accepted connection (PRIVILEGED §3). unix(7):
// the credentials are those of the peer process "in effect at the time of
// the call to connect(2)", captured by the kernel — so they identify the
// process that connected to the socket systemd accepted, whoever holds the
// descriptor now, and cannot be supplied by the caller.
package peercred

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Cred is the peer's credentials.
type Cred struct {
	PID      int32
	UID, GID uint32
}

// ErrWrongPeer is returned when the peer's uid is not the policy's
// client_uid.
var ErrWrongPeer = errors.New("peer uid is not the policy's client_uid")

// Peer returns SO_PEERCRED of the connected AF_UNIX socket fd.
func Peer(fd int) (Cred, error) {
	u, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Cred{}, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	return Cred{PID: u.Pid, UID: u.Uid, GID: u.Gid}, nil
}

// Authenticate returns the peer's credentials, and ErrWrongPeer unless its
// uid is want.
func Authenticate(fd int, want uint32) (Cred, error) {
	c, err := Peer(fd)
	if err != nil {
		return Cred{}, err
	}
	if c.UID != want {
		return c, ErrWrongPeer
	}
	return c, nil
}
