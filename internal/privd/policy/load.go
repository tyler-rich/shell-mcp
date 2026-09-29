//go:build linux

package policy

import "errors"

var errNotImplemented = errors.New("not implemented")

// Load checks the ownership of the policy file and its parent directories,
// reads it (bounded), and parses and validates it.
func Load(file string, opts *LoadOptions) (*Policy, error) { return nil, errNotImplemented }

// Parse validates policy bytes; file is the policy's path.
func Parse(data []byte, file string, opts *LoadOptions) (*Policy, error) {
	return nil, errNotImplemented
}

// ProductionLookups fills the user and group lookups from the local
// databases.
func ProductionLookups(o *LoadOptions) {}
