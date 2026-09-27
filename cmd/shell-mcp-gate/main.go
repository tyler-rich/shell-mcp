// Command shell-mcp-gate is the SSH forced command on each target. It enforces the host's root-owned gate policy; the implementation arrives in Session 1.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// Set with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "dev"
)

const usage = `usage: shell-mcp-gate <command> [flags]

commands:
  serve         serve one request (the SSH forced command)
  check-policy  lint a gate policy
  polkit        generate the polkit rule for a policy
  version       print version information
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		_, _ = fmt.Fprintf(stdout, "shell-mcp-gate %s (commit %s, %s)\n", version, commit, runtime.Version())
		return 0
	case "serve", "check-policy", "polkit":
		_, _ = fmt.Fprintf(stderr, "shell-mcp-gate: %s arrives in Session 1\n", args[0])
		return 2
	case "-h", "--help", "help":
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "shell-mcp-gate: unknown command %q\n%s", args[0], usage)
	return 2
}
