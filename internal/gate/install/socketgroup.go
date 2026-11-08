//go:build linux

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
)

// HelperRunDir is the directory that holds the privileged helper's sockets:
// the generated units listen on HelperSockets in it (PRIVILEGED §2, §5.1),
// and a gate policy's privileged.socket and broad_socket lie beneath it.
const HelperRunDir = "/run/shell-mcp"

// HelperSockets are the helper's socket files in HelperRunDir: the core
// unit's and the broad unit's. internal/privd/units tests that they are the
// names its units listen on (the gate never links the helper's packages).
var HelperSockets = []string{"privd.sock", "privd-broad.sock"}

// SocketGroupEnv is what the shared-account check looks at.
type SocketGroupEnv struct {
	Identity Identity
	// RunDir is the helper's socket directory (production: HelperRunDir).
	RunDir string
	// Forwarding is the policy's privileged.enabled.
	Forwarding bool
}

// sharedWire is the refusal's one-line message for the response: the cause
// and the fix, naming no local path or group.
const sharedWire = "this account is in the privileged helper's socket group and this policy has no privileged forwarding: " +
	"serve the keys without forwarding from a second service account outside that group " +
	"(shell-mcp-gate install with its own --user, --uid and --gid; TARGET-SETUP §4) and move their key lines to it"

// CheckSocketGroup is the shared-account rule (docs/SECURITY.md §2, handoff
// of the 0.3.0 security fix): a gate whose policy has no privileged
// forwarding refuses to serve when its process belongs to the group that
// owns one of the helper's sockets. Below Landlock ABI 9 nothing but the
// socket's permissions and the helper's peer-UID check governs a command's
// connect to that socket, and for the account the helper serves both pass,
// so a read command able to open a Unix socket could ask the helper for
// root actions that no approval covers (approval is the server's, PRIVILEGED
// §3). The group is read from the socket files themselves (lstat, never
// followed), so no configuration is needed and the privileged policy is
// never read. A socket directory that exists but cannot be inspected fails
// closed. A policy with forwarding enabled is not checked: its account is
// the helper's client by design.
func CheckSocketGroup(env *SocketGroupEnv) error {
	if env.Forwarding {
		return nil
	}
	cannot := func(why string) error {
		return &Error{
			"gate cannot tell whether its account can reach the privileged helper's socket (run shell-mcp-gate check-policy on the host)",
			fmt.Sprintf("cannot tell whether this account can reach the privileged helper's sockets: %s; a policy without privileged forwarding is refused until it can (TARGET-SETUP §4)", why),
		}
	}
	fi, err := os.Lstat(env.RunDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil // no helper on this host
	case err != nil:
		return cannot(fmt.Sprintf("%s: %v", env.RunDir, err))
	case !fi.IsDir():
		return cannot(fmt.Sprintf("%s is not a directory (%s)", env.RunDir, fi.Mode().Type()))
	}
	for _, name := range HelperSockets {
		p := filepath.Join(env.RunDir, name)
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return cannot(fmt.Sprintf("%s exists but %s cannot be inspected: %v", env.RunDir, p, err))
		case fi.Mode().Type() != fs.ModeSocket:
			continue // not a socket: nothing listens there
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return cannot(fmt.Sprintf("%s: no owner information", p))
		}
		if !slices.Contains(env.Identity.GIDs, st.Gid) {
			continue
		}
		name := strconv.FormatUint(uint64(st.Gid), 10)
		if env.Identity.GroupName != nil {
			if n, err := env.Identity.GroupName(st.Gid); err == nil {
				name = strconv.Quote(n)
			}
		}
		return &Error{sharedWire, fmt.Sprintf(
			"gate process belongs to group %s (gid %d), which owns the privileged helper's socket %s, and this policy has no privileged forwarding (privileged.enabled): "+
				"below Landlock ABI 9 a command it runs could connect to the helper as the helper's client account, which no approval covers. "+
				"Serve the keys whose policy has no privileged forwarding from a second service account that is not in that group "+
				"(shell-mcp-gate install with its own --user, --uid and --gid; TARGET-SETUP §4), and move their key lines to it",
			name, st.Gid, p)}
	}
	return nil
}
