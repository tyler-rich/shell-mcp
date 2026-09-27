//go:build linux

package policy

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
)

// Load checks the ownership of the policy file and every parent directory,
// reads it (bounded), and parses and validates it.
//
// The chain is checked by path first; the file is then opened without
// following a final symlink and its owner, mode and type are re-checked on
// the open descriptor, so the bytes validated are the bytes of the file
// that passed the check.
func Load(file string, opts LoadOptions) (*Policy, error) {
	if err := pathx.CheckClean(file); err != nil {
		return nil, &Error{"--policy", err.Error()}
	}
	real, err := CheckChain(opts.Trust, file)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &OwnershipError{real, "cannot be opened: " + errReason(err)}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, &OwnershipError{real, "cannot be inspected: " + errReason(err)}
	}
	if err := checkFile(opts.Trust, real, fi); err != nil {
		return nil, err
	}
	if fi.Size() > MaxPolicyBytes {
		return nil, &Error{"", fmt.Sprintf("policy file is larger than %d bytes", MaxPolicyBytes)}
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return nil, &OwnershipError{real, "cannot be read: " + errReason(err)}
	}
	if len(data) > MaxPolicyBytes {
		return nil, &Error{"", fmt.Sprintf("policy file is larger than %d bytes", MaxPolicyBytes)}
	}
	p, err := parse(data, []string{file, real}, opts)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Parse validates policy bytes. file is the policy's path (it joins the
// protected set). Command binaries are still resolved and ownership-checked
// on this host.
func Parse(data []byte, file string, opts LoadOptions) (*Policy, error) {
	return parse(data, []string{file}, opts)
}
