package main

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/setup/compose"
)

// cmdInit runs `shell-mcp init` (the server's secrets, handoff §4.C) and
// `shell-mcp init compose` (the reference compose with a deployment's
// values, printed).
func cmdInit(args []string, stdout, stderr io.Writer, env initEnv) int {
	if len(args) > 0 && args[0] == "compose" {
		return initCompose(args[1:], stdout, stderr)
	}
	return initSecrets(args, stdout, stderr, env)
}

func helpRequested(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool { return a == "-h" || a == "-help" || a == "--help" })
}

// initCompose prints the compose file on stdout and nothing else there:
// notes and refusals go to stderr, so the output can be redirected to a
// file. It reads no secret.
func initCompose(args []string, stdout, stderr io.Writer) int {
	if helpRequested(args) {
		_, _ = io.WriteString(stdout, compose.Usage)
		return 0
	}
	v, err := compose.ParseFlags(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp init compose: %v\n%s", err, compose.Usage)
		return 2
	}
	notes, err := v.Check()
	for _, n := range notes {
		_, _ = fmt.Fprintf(stderr, "NOTE %s\n", n)
	}
	if err == nil {
		var out []byte
		if out, err = compose.Render(v); err == nil {
			_, _ = stdout.Write(out)
			return 0
		}
	}
	for _, l := range strings.Split(err.Error(), "\n") {
		_, _ = fmt.Fprintf(stderr, "FAIL %s\n", l)
	}
	_, _ = io.WriteString(stderr, "init compose: refused; nothing printed\n")
	return 1
}
