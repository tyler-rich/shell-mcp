//go:build linux

// Package selfcheck implements the helper's fail-closed startup checks
// (PRIVILEGED §7).
package selfcheck

import (
	"errors"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
)

// Error is a failed self-check. Check names it for the audit line; Detail
// may name local paths and never reaches the wire.
type Error struct {
	Check  string
	Detail string
}

func (e *Error) Error() string { return e.Check + ": " + e.Detail }

// Status is what the checks read from /proc/self/status.
type Status struct {
	UIDs       [4]uint32 // real, effective, saved, filesystem
	NoNewPrivs bool
	CapBnd     uint64
}

var errNotImplemented = errors.New("not implemented")

// ParseStatus parses /proc/self/status (proc_pid_status(5)).
func ParseStatus(b []byte) (Status, error) { return Status{}, errNotImplemented }

// Process requires uid 0 (real, effective, saved and filesystem) and
// NoNewPrivs 1.
func Process(s *Status) error { return errNotImplemented }

// CapabilityMask returns the bit mask of capability names.
func CapabilityMask(names []string) (uint64, error) { return 0, errNotImplemented }

// Capabilities requires the bounding set to be a subset of the unit's.
func Capabilities(s *Status, unit []string) error { return errNotImplemented }

// Stdin requires fd to be a connected AF_UNIX stream socket.
func Stdin(fd int) error { return errNotImplemented }

// Binary requires the helper binary and its directories to be owned by a
// trusted uid and not group/other-writable.
func Binary(t gpolicy.Trust, exe string) error { return errNotImplemented }

// Hash requires the policy's SHA-256 to equal the unit's
// SHELL_MCP_PRIVD_POLICY_SHA256.
func Hash(policySHA256, env string) error { return errNotImplemented }
