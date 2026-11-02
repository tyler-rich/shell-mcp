//go:build linux

package main

import (
	"io"

	"github.com/tyler-rich/shell-mcp/internal/setup/serverinit"
)

type initEnv struct{}

var processInitEnv = initEnv{}

func initSecrets(args []string, stdout, stderr io.Writer, env initEnv) int {
	_, _ = serverinit.ParseFlags(args)
	return 0
}
