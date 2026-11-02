//go:build linux

// Package serverinit is `shell-mcp init` (handoff §4.C): the server's bearer
// token, SSH key pair and approvers file, created in one directory owned by
// the server's uid, through the setup tools' write helper, never overwritten
// and never printed.
package serverinit

import (
	"io"
	"io/fs"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// The files init manages, under --dir.
const (
	TokenFile     = "mcp_token"
	KeyFile       = "ssh_key"
	PubFile       = "ssh_key.pub"
	ApproversFile = "approvers"
)

// Options are init's flags.
type Options struct {
	Dir      string
	UID, GID uint32
	Approver string
	DryRun   bool
}

// Usage is init's usage text.
const Usage = "usage: shell-mcp init --dir <dir> [--uid <n>] [--gid <n>] [--approver <name>] [--dry-run]\n"

// ParseFlags parses init's flags.
func ParseFlags(args []string) (*Options, error) { return &Options{}, nil }

// Files is what init reads and changes on the filesystem.
type Files interface {
	State(path string, limit int64) (setupx.FileState, error)
	WriteFile(path string, data []byte, mode fs.FileMode, owner setupx.Owner) error
	Mkdir(path string, mode fs.FileMode, owner setupx.Owner) error
	Remove(path string) error
	RemoveLeftovers(target string) ([]string, error)
}

// RealFiles is the real filesystem; tempOwner owns a killed run's temp files.
func RealFiles(tempOwner uint32) Files { return nil }

// Env is what init takes from the process.
type Env struct {
	Euid, Egid int
	Groups     []int
	Rand       io.Reader
	IsTerminal func(io.Writer) bool
}

// Run is shell-mcp init.
func Run(o *Options, h Files, env *Env, stdout, stderr io.Writer) int { return ExitOK }

func checkToken(data []byte) error { return nil }

func checkPublicKey(data, want []byte) error { return nil }
