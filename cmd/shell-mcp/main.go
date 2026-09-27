// Command shell-mcp is the MCP server.
package main

import (
	"context"
	"errors"
	"io"
	"os"
)

func healthcheck(_ context.Context, _ string) int { return 99 }

func healthcheckURL(_ func(string) (string, bool)) (string, error) {
	return "", errors.New("not implemented")
}

func run(_ context.Context, _ []string, _ func(string) (string, bool), _, _ io.Writer) int {
	return 99
}

func main() { os.Exit(run(context.Background(), os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)) }
