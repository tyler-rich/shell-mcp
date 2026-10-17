package main

import (
	"crypto/rand"
	"io"
)

// approverEnv is what the approver command takes from the process; tests
// replace it.
type approverEnv struct {
	rand       io.Reader
	isTerminal func(io.Writer) bool
}

var processApproverEnv = approverEnv{rand: rand.Reader, isTerminal: isTerminal}

func cmdApprover(_ []string, _, stderr io.Writer, _ approverEnv) int {
	_, _ = io.WriteString(stderr, "shell-mcp: approver: not implemented\n")
	return 2
}

func isTerminal(io.Writer) bool { return true }
