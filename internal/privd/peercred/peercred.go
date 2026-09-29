//go:build linux

// Package peercred authenticates the privileged helper's caller by the
// kernel's SO_PEERCRED on the accepted connection (PRIVILEGED §3): the
// credentials of the process that called connect(2), captured by the
// kernel at that time (unix(7)), whoever holds the socket now.
package peercred

import "errors"

// Cred is the peer's credentials.
type Cred struct {
	PID      int32
	UID, GID uint32
}

// ErrWrongPeer is returned when the peer's uid is not the policy's
// client_uid.
var ErrWrongPeer = errors.New("peer uid is not the policy's client_uid")

// Peer returns SO_PEERCRED of the connected AF_UNIX socket fd.
func Peer(fd int) (Cred, error) { return Cred{}, errors.New("not implemented") }

// Authenticate returns the peer's credentials, and ErrWrongPeer unless its
// uid is want.
func Authenticate(fd int, want uint32) (Cred, error) { return Cred{}, errors.New("not implemented") }
