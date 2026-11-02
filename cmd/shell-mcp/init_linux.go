//go:build linux

package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/setup/serverinit"
)

// initEnv is what init takes from the process; tests replace it.
type initEnv struct {
	rand       io.Reader
	isTerminal func(io.Writer) bool
}

var processInitEnv = initEnv{rand: rand.Reader, isTerminal: isTerminal}

func initSecrets(args []string, stdout, stderr io.Writer, env initEnv) int {
	if helpRequested(args) {
		_, _ = io.WriteString(stdout, serverinit.Usage)
		return 0
	}
	o, err := serverinit.ParseFlags(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp init: %v\n%s", err, serverinit.Usage)
		return serverinit.ExitUsage
	}
	groups, err := os.Getgroups()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shell-mcp init: cannot read this process's groups: %v\n", err)
		return serverinit.ExitFail
	}
	e := &serverinit.Env{Euid: os.Geteuid(), Egid: os.Getegid(), Groups: groups, Rand: env.rand, IsTerminal: env.isTerminal}
	return serverinit.Run(o, serverinit.RealFiles(uint32(os.Geteuid())), e, stdout, stderr) //nolint:gosec // G115: this process's uid
}
