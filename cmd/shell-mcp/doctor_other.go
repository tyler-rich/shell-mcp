//go:build !linux

package main

import "os"

// fileOwner is unknown off Linux.
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }
