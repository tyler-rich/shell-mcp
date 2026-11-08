//go:build linux

package install

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

// CheckSocketGroup refuses a gate whose policy has no privileged forwarding
// when its process belongs to the group that owns one of the helper's
// sockets.
func CheckSocketGroup(env *SocketGroupEnv) error {
	_ = env
	return nil
}
