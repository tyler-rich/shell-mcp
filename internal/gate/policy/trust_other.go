//go:build !linux

package policy

import (
	"errors"
	"io/fs"
)

var errLinuxOnly = errors.New("the gate runs on Linux only")

// CheckChain is Linux-only; see trust_linux.go.
func CheckChain(_ Trust, _ string) (string, error) { return "", errLinuxOnly }

func checkFile(_ Trust, _ string, _ fs.FileInfo) error { return errLinuxOnly }

func errReason(err error) string { return err.Error() }

// Load is Linux-only.
func Load(_ string, _ LoadOptions) (*Policy, error) { return nil, errLinuxOnly }

// Parse is Linux-only.
func Parse(_ []byte, _ string, _ LoadOptions) (*Policy, error) { return nil, errLinuxOnly }
