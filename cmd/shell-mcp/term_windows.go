//go:build windows

package main

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether w is a console: a file whose handle answers
// GetConsoleMode. Pipes, NUL and regular files are not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var mode uint32
	var termErr error
	if err := rc.Control(func(fd uintptr) {
		termErr = windows.GetConsoleMode(windows.Handle(fd), &mode)
	}); err != nil {
		return false
	}
	return termErr == nil
}
