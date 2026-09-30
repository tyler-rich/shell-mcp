//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/privd/policy"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/template"
)

// opError is an op failure with a gate error code.
type opError struct {
	code, msg string
}

func (e *opError) Error() string { return e.code + ": " + e.msg }

func errf(code, format string, a ...any) error {
	return &opError{code: code, msg: fmt.Sprintf(format, a...)}
}

func badArgs() error {
	return errf(protocol.CodeBadRequest, "args are not a strict object of known fields with the expected types")
}

func decode(raw jsontext.Value, v any) error {
	if err := protocol.DecodeArgs(raw, v); err != nil {
		return badArgs()
	}
	return nil
}

type opFunc func(s *server, args jsontext.Value) (any, []string, error)

type opSpec struct {
	tier policy.Tier
	run  opFunc
}

// ops are the core unit's operations and their tiers (PRIVILEGED §6).
// priv_exec's tier is the command's.
func opTable() map[string]opSpec {
	return map[string]opSpec{
		protocol.OpPrivReadFile:      {policy.TierRead, (*server).readFile},
		protocol.OpPrivListDir:       {policy.TierRead, (*server).listDir},
		protocol.OpPrivStat:          {policy.TierRead, (*server).stat},
		protocol.OpPrivListBackups:   {policy.TierRead, (*server).listBackups},
		protocol.OpPrivWriteFile:     {policy.TierOperator, (*server).writeFile},
		protocol.OpPrivMkdir:         {policy.TierOperator, (*server).mkdir},
		protocol.OpPrivChown:         {policy.TierOperator, (*server).chown},
		protocol.OpPrivChmod:         {policy.TierOperator, (*server).chmod},
		protocol.OpPrivCopy:          {policy.TierOperator, (*server).copy},
		protocol.OpPrivMove:          {policy.TierOperator, (*server).move},
		protocol.OpPrivRestoreBackup: {policy.TierOperator, (*server).restoreBackup},
		protocol.OpPrivDelete:        {policy.TierDestructive, (*server).delete},
	}
}

// broadOps are the operations that run in the broad unit (PRIVILEGED §6);
// priv_exec runs in its command's unit and every other operation in the
// core unit.
var broadOps = []string{
	protocol.OpPrivPkgUpdateIndex, protocol.OpPrivPkgInstall, protocol.OpPrivPkgUpgrade, protocol.OpPrivPkgRemove,
	protocol.OpPrivPkgInstallPreview, protocol.OpPrivPkgUpgradePreview, protocol.OpPrivPkgRemovePreview, protocol.OpPrivPower,
}

// wrongUnit is the refusal of an operation meant for the other unit's
// instance. The helper is authoritative for routing: whatever the gate sent
// where, nothing meant for the other unit runs here.
func (s *server) wrongUnit(want policy.Unit) error {
	return errf(protocol.CodeHelperWrongUnit, "this operation runs in the %s unit; this is the %s unit's helper, so it was not executed (the gate routes it to privileged.%s)",
		want, s.unit, map[policy.Unit]string{policy.UnitCore: "socket", policy.UnitBroad: "broad_socket"}[want])
}

func (s *server) dispatch() *protocol.Response {
	op := s.req.Op
	if op == protocol.OpPrivExec {
		data, warnings, err := s.exec(s.req.Args)
		return s.result(data, warnings, err)
	}
	spec, ok := opTable()[op]
	if !ok {
		spec, ok = extraOps[op]
	}
	if !ok && !slices.Contains(broadOps, op) {
		return s.errResp(errf(protocol.CodeUnknownOp, "operation is not available in this helper version"))
	}
	// The unit first: an operation meant for the other unit is refused
	// before anything else about it is looked at.
	want := policy.UnitCore
	if slices.Contains(broadOps, op) {
		want = policy.UnitBroad
	}
	if want != s.unit {
		return s.errResp(s.wrongUnit(want))
	}
	if !ok {
		return s.errResp(errf(protocol.CodeUnknownOp, "operation is not available in this helper version"))
	}
	// Tier first, before any other processing.
	if spec.tier > s.p.MaxTier {
		return s.errResp(errf(protocol.CodeTierDenied, "operation tier %s exceeds the privileged policy's max_tier %s", spec.tier, s.p.MaxTier))
	}
	data, warnings, err := spec.run(s, s.req.Args)
	return s.result(data, warnings, err)
}

func (s *server) result(data any, warnings []string, err error) *protocol.Response {
	if err != nil {
		return s.errResp(err)
	}
	raw, err := protocol.Marshal(data)
	if err != nil {
		return s.errResp(errf(protocol.CodeInternal, "result could not be encoded"))
	}
	if warnings == nil {
		warnings = []string{}
	}
	return &protocol.Response{OK: true, Data: raw, Warnings: warnings}
}

// errResp maps an op failure to a response. Messages never carry content.
func (s *server) errResp(err error) *protocol.Response {
	code, msg := protocol.CodeInternal, "internal error"
	var oe *opError
	var fe *fsx.Error
	var pe *template.PathError
	var ve *template.ValueError
	switch {
	case errors.As(err, &oe):
		code, msg = oe.code, oe.msg
	case errors.As(err, &pe) && errors.As(pe.Err, &fe):
		code, msg = fe.Code, "path argument: "+fe.Msg
	case errors.As(err, &fe):
		code, msg = fe.Code, fe.Msg
	case errors.As(err, &ve):
		code, msg = protocol.CodeTemplateMismatch, ve.Error()
	case errors.Is(err, template.ErrNoMatch):
		code, msg = protocol.CodeTemplateMismatch, "arguments match no template of this command"
	case errors.Is(err, execx.ErrStart):
		code, msg = protocol.CodeExecFailed, "command could not be started"
	}
	return failure(code, msg)
}
