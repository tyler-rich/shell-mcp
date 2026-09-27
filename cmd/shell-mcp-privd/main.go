// Command shell-mcp-privd is the socket-activated privileged helper on each target. It performs declared root actions under its own policy; the implementation arrives in Session 1c.
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

const usage = `usage: shell-mcp-privd <command> [flags]

commands:
  serve         serve one request (started by systemd only)
  check-policy  lint a privileged policy
  units         generate the systemd units for a policy
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
		_, _ = fmt.Fprintf(stdout, "shell-mcp-privd %s (commit %s, %s)\n", version, commit, runtime.Version())
		return 0
	case "serve", "check-policy", "units":
		_, _ = fmt.Fprintf(stderr, "shell-mcp-privd: %s arrives in Session 1c\n", args[0])
		return 2
	case "-h", "--help", "help":
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "shell-mcp-privd: unknown command %q\n%s", args[0], usage)
	return 2
}
