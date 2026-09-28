// Package gitx parses the output of the fixed git invocations the gate
// runs and decides which repository-local configuration it accepts.
package gitx

import "errors"

// Status is git status --porcelain=v2 --branch -z.
type Status struct {
	OID      string
	Branch   string
	Upstream string
	Ahead    int
	Behind   int
	Entries  []Entry
}

// Entry is one status entry.
type Entry struct {
	Kind     string `json:"kind"`
	XY       string `json:"xy"`
	Path     string `json:"path"`
	OrigPath string `json:"orig_path,omitempty"`
}

// Commit is one log entry.
type Commit struct {
	Hash    string `json:"hash"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Subject string `json:"subject"`
}

// KV is one configuration entry.
type KV struct {
	Key   string
	Value string
}

var errTODO = errors.New("not implemented")

// ParseStatus is not implemented yet.
func ParseStatus(_ []byte, _ int) (Status, bool, error) { return Status{}, false, errTODO }

// ParseLog is not implemented yet.
func ParseLog(_ []byte) ([]Commit, error) { return nil, errTODO }

// Unquote is not implemented yet.
func Unquote(_ string) (string, error) { return "", errTODO }

// ParseClean is not implemented yet.
func ParseClean(_ []byte) (remove, skipped []string, err error) { return nil, nil, errTODO }

// ParseConfig is not implemented yet.
func ParseConfig(_ []byte) ([]KV, error) { return nil, errTODO }

// CheckConfig is not implemented yet.
func CheckConfig(_ []KV) (string, bool) { return "", false }

// Value is not implemented yet.
func Value(_ []KV, _ string) (string, bool) { return "", false }
