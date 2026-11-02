//go:build linux && !(amd64 || arm64)

package execx

import (
	"errors"
	"syscall"
)

type allThreadsFunc func(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

var errArch = errors.New("the credential option is built for amd64 and arm64 only")

// setIDs refuses: the credential option is built for D-018's architectures,
// amd64 and arm64, whose set*id system calls take the 32-bit ids directly.
func setIDs(*Credential) (string, error) { return "setgroups", errArch }

func setIDsWith(*Credential, allThreadsFunc) (string, error) { return "setgroups", errArch }

func credentialSupported() error { return errArch }

func credentialSupportedWith(allThreadsFunc) error { return errArch }
