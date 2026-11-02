//go:build !linux

package main

import "io"

type initEnv struct{}

var processInitEnv = initEnv{}

// initSecrets refuses: init writes with the Linux write helper, and the
// server's image and release binaries are Linux only.
func initSecrets(_ []string, _, stderr io.Writer, _ initEnv) int {
	_, _ = io.WriteString(stderr, "shell-mcp init: runs on Linux only (on the server host, or in the image)\n")
	return 1
}
