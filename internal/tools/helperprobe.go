package tools

import (
	"context"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
)

// HelperProbe is what the privileged helper answered through one of its
// sockets to a read request of `shell-mcp doctor`.
type HelperProbe struct {
	// Op is the read operation sent.
	Op string
	// Version, PolicySHA256 and Unit are the answer's helper block.
	Version      string
	PolicySHA256 string
	Unit         string
	// Summary is the policy summary (priv_policy only).
	Summary *PrivPolicy
	// Refusal is set when the helper of the expected unit answered and
	// refused the operation itself (a blocker, a rule of its policy): the
	// socket works, and the refusal is reported as it is.
	Refusal  *envelope.Error
	Warnings []string
}

// ProbeHelper asks the helper for its policy summary through the core
// socket (priv_policy at the read ceiling).
func ProbeHelper(_ context.Context, _ *Deps, _ string) (*HelperProbe, *envelope.Error) {
	return nil, nil
}

// BroadProbeOp picks the read operation that reaches the broad socket for
// the policy summary s: the index update's preview, else a power action's
// preview. op is empty when neither is allowed; reason then says why the
// socket is not probed, or that the policy has no broad unit.
func BroadProbeOp(_ *PrivPolicy) (op string, args any, reason string) {
	return "", nil, ""
}

// ProbeHelperBroad sends op, a read operation of the broad unit, through
// the broad socket.
func ProbeHelperBroad(_ context.Context, _ *Deps, _, _ string, _ any) (*HelperProbe, *envelope.Error) {
	return nil, nil
}
