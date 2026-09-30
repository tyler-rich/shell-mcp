//go:build linux

package pkg

import (
	"context"
	"errors"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
)

// Op is an apt operation (stub).
type Op string

// Operations.
const (
	OpUpdate  Op = "update"
	OpInstall Op = "install"
	OpUpgrade Op = "upgrade"
	OpRemove  Op = "remove"
)

// Bounds.
const (
	MaxNames   = 20
	MaxChanges = 5000
)

// ErrLockHeld (stub).
var ErrLockHeld = errors.New("lock held")

// Version, Upgrade, Removal, Simulation (stubs).
type (
	Version struct{ Name, Version string }
	Upgrade struct{ Name, From, To string }
	Removal struct {
		Name, Version string
		Purge         bool
	}
	Simulation struct {
		Install  []Version
		Upgrade  []Upgrade
		Remove   []Removal
		Unparsed int
	}
)

// Args (stub).
func Args(Op, bool, []string) ([]string, error) { return nil, errors.New("stub") }

// ValidName (stub).
func ValidName(string) bool { return false }

// Env (stub).
func Env(string) []string { return nil }

// ParseSimulation (stub).
func ParseSimulation([]byte) Simulation { return Simulation{} }

// LockHeld (stub).
func LockHeld([]byte) bool { return false }

// Runner (stub).
type Runner struct {
	AptGet    string
	Env       []string
	MaxOutput int
	LockWait  time.Duration
	Retry     time.Duration
}

// Result (stub).
type Result struct {
	execx.Result
	LockWait time.Duration
	Attempts int
}

// Run (stub).
func (r *Runner) Run(context.Context, time.Duration, []string) (Result, error) {
	return Result{}, errors.New("stub")
}
