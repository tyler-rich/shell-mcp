//go:build linux

package main

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether w is a terminal: a file whose descriptor
// answers TCGETS. Character devices that are not terminals (/dev/null), pipes
// and regular files are not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var termErr error
	if err := rc.Control(func(fd uintptr) {
		_, termErr = unix.IoctlGetTermios(int(fd), unix.TCGETS)
	}); err != nil {
		return false
	}
	return termErr == nil
}
