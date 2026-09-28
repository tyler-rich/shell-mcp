//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
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

type opFunc func(s *server, args jsontext.Value) (any, []string, error)

type opSpec struct {
	tier policy.Tier
	run  opFunc
}

// opOrder is the order ops are listed in by hello.
var opOrder = []string{
	protocol.OpHello, protocol.OpPolicy, protocol.OpListDir, protocol.OpStat, protocol.OpReadFile,
	protocol.OpFind, protocol.OpDeletePreview, protocol.OpWriteFile, protocol.OpMkdir, protocol.OpCopy,
	protocol.OpMove, protocol.OpChmod, protocol.OpDelete,
}

// ops implemented in this version, with their tiers (ARCHITECTURE §4.3).
func opTable() map[string]opSpec {
	return map[string]opSpec{
		protocol.OpHello:         {policy.TierRead, (*server).hello},
		protocol.OpPolicy:        {policy.TierRead, (*server).policySummary},
		protocol.OpListDir:       {policy.TierRead, (*server).listDir},
		protocol.OpStat:          {policy.TierRead, (*server).stat},
		protocol.OpReadFile:      {policy.TierRead, (*server).readFile},
		protocol.OpFind:          {policy.TierRead, (*server).find},
		protocol.OpDeletePreview: {policy.TierRead, (*server).deletePreview},
		protocol.OpWriteFile:     {policy.TierOperator, (*server).writeFile},
		protocol.OpMkdir:         {policy.TierOperator, (*server).mkdir},
		protocol.OpCopy:          {policy.TierOperator, (*server).copy},
		protocol.OpMove:          {policy.TierOperator, (*server).move},
		protocol.OpChmod:         {policy.TierOperator, (*server).chmod},
		protocol.OpDelete:        {policy.TierDestructive, (*server).delete},
	}
}

// privTiers are the helper's op tiers (PRIVILEGED §6). priv_exec is per
// command and the gate cannot know the helper's command tiers; it is
// checked as read here and the helper enforces its own tier (S1c).
var privTiers = map[string]policy.Tier{
	protocol.OpPrivReadFile: policy.TierRead, protocol.OpPrivListDir: policy.TierRead,
	protocol.OpPrivStat: policy.TierRead, protocol.OpPrivListBackups: policy.TierRead,
	protocol.OpPrivExec:      policy.TierRead,
	protocol.OpPrivWriteFile: policy.TierOperator, protocol.OpPrivMkdir: policy.TierOperator,
	protocol.OpPrivChown: policy.TierOperator, protocol.OpPrivChmod: policy.TierOperator,
	protocol.OpPrivCopy: policy.TierOperator, protocol.OpPrivMove: policy.TierOperator,
	protocol.OpPrivRestoreBackup: policy.TierOperator, protocol.OpPrivPkgUpdateIndex: policy.TierOperator,
	protocol.OpPrivPkgInstall: policy.TierOperator, protocol.OpPrivPkgUpgrade: policy.TierOperator,
	protocol.OpPrivDelete: policy.TierDestructive, protocol.OpPrivPkgRemove: policy.TierDestructive,
}

func (s *server) dispatch() *protocol.Response {
	op := s.req.Op
	switch {
	case strings.HasPrefix(op, "priv_"):
		return s.errResp(s.priv(op))
	case op == protocol.OpExec:
		data, warnings, err := s.exec(s.req.Args)
		return s.result(data, warnings, err)
	}
	spec, ok := opTable()[op]
	if !ok {
		return s.errResp(errf(protocol.CodeUnknownOp, "operation is not available in this gate version"))
	}
	// Tier first, before any other processing.
	if spec.tier > s.p.MaxTier {
		return s.errResp(errf(protocol.CodeTierDenied, "operation tier %s exceeds the policy's max_tier %s", spec.tier, s.p.MaxTier))
	}
	data, warnings, err := spec.run(s, s.req.Args)
	return s.result(data, warnings, err)
}

// priv gates privileged forwarding; the forwarding itself arrives in S1c.
func (s *server) priv(op string) error {
	tier, known := privTiers[op]
	switch {
	case !known:
		return errf(protocol.CodeUnknownOp, "operation is not available in this gate version")
	case !s.p.Privileged.Enabled:
		return errf(protocol.CodePrivilegedDisabled, "privileged forwarding is disabled in this gate policy")
	case tier > s.p.Privileged.MaxTier || tier > s.p.MaxTier:
		return errf(protocol.CodeTierDenied, "operation tier %s exceeds the policy's privileged.max_tier %s", tier, s.p.Privileged.MaxTier)
	}
	return errf(protocol.CodeUnknownOp, "privileged forwarding is not implemented in this gate version")
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
	return Failure("", code, msg)
}
