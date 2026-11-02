package main

import (
	"io"

	"github.com/tyler-rich/shell-mcp/internal/setup/compose"
)

// cmdInit runs `shell-mcp init` and `shell-mcp init compose`.
func cmdInit(args []string, stdout, stderr io.Writer, env initEnv) int {
	if len(args) > 0 && args[0] == "compose" {
		_, _ = compose.ParseFlags(args[1:])
		return 0
	}
	return initSecrets(args, stdout, stderr, env)
}
