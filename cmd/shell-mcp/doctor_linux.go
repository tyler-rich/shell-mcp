//go:build linux

package main

import (
	"os"
	"syscall"
)

// fileOwner is the uid that owns fi.
func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
