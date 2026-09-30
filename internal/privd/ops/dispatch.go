//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"

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

func (s *server) dispatch() *protocol.Response {
	op := s.req.Op
	switch {
	case op == protocol.OpPrivExec:
		data, warnings, err := s.exec(s.req.Args)
		return s.result(data, warnings, err)
	case strings.HasPrefix(op, "priv_pkg_"):
		return s.errResp(errf(protocol.CodeUnknownOp, "package operations arrive with the broad unit (S1d)"))
	}
	spec, ok := opTable()[op]
	if !ok {
		spec, ok = extraOps[op]
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
