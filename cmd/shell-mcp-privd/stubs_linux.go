//go:build linux

package main

import (
	"io"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
)

type loadEnv struct {
	trust         gpolicy.Trust
	executable    string
	systemBinDirs []string
	lookups       func(*policy.LoadOptions)
}

func unitsWith(_ []string, _, _ io.Writer, _ *loadEnv) int       { return 2 }
func checkPolicyWith(_ []string, _, _ io.Writer, _ *loadEnv) int { return 2 }
