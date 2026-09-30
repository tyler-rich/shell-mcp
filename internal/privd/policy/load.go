//go:build linux

package policy

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
)

// Load checks the ownership of the policy file and every parent directory,
// reads it (bounded), and parses and validates it.
//
// The chain is checked by path first; the file is then opened without
// following a final symlink and its owner, mode and type are re-checked on
// the open descriptor, so the bytes validated (and hashed) are the bytes of
// the file that passed the check.
func Load(file string, opts *LoadOptions) (*Policy, error) {
	if err := pathx.CheckClean(file); err != nil {
		return nil, &Error{"--policy", err.Error()}
	}
	rp, err := gpolicy.CheckChain(opts.Trust, file)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(rp, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the administrator-chosen policy path, ownership-checked by CheckChain and re-checked on the descriptor
	if err != nil {
		return nil, &gpolicy.OwnershipError{Path: rp, Reason: "cannot be opened: " + gpolicy.ErrReason(err)}
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, &gpolicy.OwnershipError{Path: rp, Reason: "cannot be inspected: " + gpolicy.ErrReason(err)}
	}
	if cerr := gpolicy.CheckFile(opts.Trust, rp, fi); cerr != nil {
		return nil, cerr
	}
	if fi.Size() > MaxPolicyBytes {
		return nil, &Error{"", fmt.Sprintf("policy file is larger than %d bytes", MaxPolicyBytes)}
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return nil, &gpolicy.OwnershipError{Path: rp, Reason: "cannot be read: " + gpolicy.ErrReason(err)}
	}
	if len(data) > MaxPolicyBytes {
		return nil, &Error{"", fmt.Sprintf("policy file is larger than %d bytes", MaxPolicyBytes)}
	}
	return parse(data, []string{file, rp}, opts)
}

// Parse validates policy bytes. file is the policy's path (it joins the
// never list and becomes the units' --policy argument). Command binaries
// are still resolved and ownership-checked on this host.
func Parse(data []byte, file string, opts *LoadOptions) (*Policy, error) {
	return parse(data, []string{file}, opts)
}

// ProductionLookups fills the user and group lookups from the local user
// and group databases (pure Go with CGO_ENABLED=0: /etc/passwd and
// /etc/group only, as for the gate's groups, D-020).
func ProductionLookups(o *LoadOptions) {
	o.LookupUser = func(name string) (uint32, error) {
		u, err := user.Lookup(name)
		if err != nil {
			return 0, err
		}
		return parseID(u.Uid)
	}
	o.LookupGroup = func(name string) (uint32, error) {
		g, err := user.LookupGroup(name)
		if err != nil {
			return 0, err
		}
		return parseID(g.Gid)
	}
	o.UserName = func(uid uint32) string {
		u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil {
			return ""
		}
		return u.Username
	}
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("id %q: %w", s, err)
	}
	return uint32(n), nil
}
