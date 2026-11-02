package tools

import (
	"context"
	"slices"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/envelope"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
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

// The helper's units, as its block names them (protocol.GateInfo.Unit).
const (
	unitCore  = "core"
	unitBroad = "broad"
)

// ProbeHelper asks the helper for its policy summary through the core
// socket (priv_policy at the read ceiling).
func ProbeHelper(ctx context.Context, d *Deps, target string) (*HelperProbe, *envelope.Error) {
	resp, e := d.call(withCeiling(ctx, TierRead), target, protocol.OpPrivPolicy, nil, d.budget())
	if e != nil {
		return nil, e
	}
	env := envelope.FromGate[privPolicyWire](target, resp)
	if !env.OK {
		return nil, env.Error
	}
	if e := helperBlock(resp, unitCore); e != nil {
		return nil, e
	}
	if env.Data.PolicySHA256 != resp.Helper.PolicySHA256 {
		return nil, envelope.Errorf(protocol.CodeInternal, "the policy summary's hash is not the helper block's")
	}
	return &HelperProbe{Op: protocol.OpPrivPolicy, Version: resp.Helper.Version, PolicySHA256: resp.Helper.PolicySHA256,
		Unit: resp.Helper.Unit, Summary: privPolicyOf(env.Data), Warnings: env.Warnings}, nil
}

// helperBlock refuses an answer without the helper block, or from another
// unit than want: the gate policy's socket then names the other unit's.
func helperBlock(resp *protocol.Response, want string) *envelope.Error {
	if resp.Helper == nil {
		return envelope.Errorf(envelope.CodeProtocolMismatch, "the gate's answer carries no helper block (an older gate)")
	}
	if resp.Helper.Unit != want {
		return envelope.Errorf(protocol.CodeHelperWrongUnit, "the helper of the %q unit answered on the %s socket", resp.Helper.Unit, want)
	}
	return nil
}

// notProbed is the broad socket's line when doctor has no operation for it
// (handoff §7 Q9; the wording as decided in S8-4: the package previews are
// read operations too, which doctor does not use).
const notProbed = "not probed: doctor uses only the index-update or power preview on it, and this policy allows neither"

// BroadProbeOp picks the read operation that reaches the broad socket for
// the policy summary s: the index update's preview, else a power action's
// preview. op is empty when neither is allowed; reason then says why the
// socket is not probed, or that the policy has no broad unit.
func BroadProbeOp(s *PrivPolicy) (op string, args any, reason string) {
	switch {
	case s == nil:
		return "", nil, "not probed: the helper's policy summary is unknown"
	case s.Packages.AllowUpdateIndex:
		return protocol.OpPrivPkgUpdateIndexPreview, noArgsWire{}, ""
	case len(s.Power.Allowed) > 0:
		return protocol.OpPrivPowerPreview, powerActionWire{Action: s.Power.Allowed[0]}, ""
	case usesBroad(s):
		return "", nil, notProbed
	}
	return "", nil, "this policy uses no broad unit"
}

// usesBroad reports whether the policy needs the broad unit: packages,
// power, or a command or operation that runs there.
func usesBroad(s *PrivPolicy) bool {
	return s.Packages.Enabled || len(s.Power.Allowed) > 0 ||
		slices.ContainsFunc(s.Commands, func(c PrivCommand) bool { return c.Unit == unitBroad }) ||
		slices.ContainsFunc(s.Ops, func(o PrivOp) bool { return o.Unit == unitBroad })
}

// ProbeHelperBroad sends op, a read operation of the broad unit, through
// the broad socket.
func ProbeHelperBroad(ctx context.Context, d *Deps, target, op string, args any) (*HelperProbe, *envelope.Error) {
	resp, e := d.call(withCeiling(ctx, TierRead), target, op, args, d.budget())
	if e != nil {
		return nil, e
	}
	if !resp.OK && resp.Error != nil && (resp.Helper == nil || helperCode(resp.Error.Code)) {
		return nil, &envelope.Error{Code: resp.Error.Code, Message: resp.Error.Message}
	}
	if e := helperBlock(resp, unitBroad); e != nil {
		return nil, e
	}
	p := &HelperProbe{Op: op, Version: resp.Helper.Version, PolicySHA256: resp.Helper.PolicySHA256, Unit: resp.Helper.Unit,
		Warnings: slices.Clone(resp.Warnings)}
	if !resp.OK {
		p.Refusal = envelope.FromGate[struct{}](target, resp).Error
	}
	return p, nil
}

// helperCode reports whether code is about the socket or the helper's
// install rather than the operation: such an answer is never "the socket
// works".
func helperCode(code string) bool {
	return strings.HasPrefix(code, "helper_") || code == protocol.CodeProtocolMismatch || code == protocol.CodePrivilegedDisabled
}
