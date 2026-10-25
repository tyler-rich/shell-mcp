package envelope

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Server error codes (closed set, ARCHITECTURE §6). Every gate code
// (protocol.Codes) is passed through unchanged as well.
const (
	CodeValidationError     = "validation_error"
	CodeUnknownTarget       = "unknown_target"
	CodeTargetUnreachable   = "target_unreachable"
	CodeHostKeyMismatch     = "host_key_mismatch"
	CodeAuthFailedSSH       = "auth_failed_ssh"
	CodeGateUnavailable     = "gate_unavailable"
	CodeProtocolMismatch    = "protocol_mismatch"
	CodeApprovalPending     = "approval_pending"
	CodeApprovalDeclined    = "approval_declined"
	CodeApprovalInvalid     = "approval_invalid"
	CodeApprovalUnavailable = "approval_unavailable"
	CodeTimeout             = "timeout"
	// CodeOutcomeUnknown is a privileged request that can change the host
	// whose answer was lost after it was sent: it may have run (handoff
	// must-fix (b)). The gate and the helper answer it too
	// (protocol.CodeOutcomeUnknown).
	CodeOutcomeUnknown = protocol.CodeOutcomeUnknown
	// CodeProfileDenied exists for defence in depth only: tools outside the
	// profile are not registered.
	CodeProfileDenied = "profile_denied"
)

// ServerCodes lists the server's own codes in ARCHITECTURE §6 order.
var ServerCodes = []string{
	CodeValidationError, CodeUnknownTarget, CodeTargetUnreachable, CodeHostKeyMismatch, CodeAuthFailedSSH,
	CodeGateUnavailable, CodeProtocolMismatch, CodeApprovalPending, CodeApprovalDeclined, CodeApprovalInvalid, CodeApprovalUnavailable,
	CodeTimeout, CodeOutcomeUnknown, CodeProfileDenied,
}

// MaxMessageBytes bounds an error message; messages are one line.
const MaxMessageBytes = 512

var allCodes = func() []string {
	all := slices.Concat(ServerCodes, protocol.Codes)
	slices.Sort(all)
	return slices.Compact(all)
}()

// Codes returns the closed code set, sorted.
func Codes() []string { return slices.Clone(allCodes) }

// IsCode reports whether c is in the closed set.
func IsCode(c string) bool {
	_, ok := slices.BinarySearch(allCodes, c)
	return ok
}

// Error is a tool failure: a code from the closed set and a one-line
// message that never carries file contents, command output or secrets.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf returns an Error with a formatted message.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError returns the *Error in err's chain, or an internal error.
func AsError(err error) *Error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	return &Error{Code: protocol.CodeInternal, Message: "internal error"}
}

// Exec reports a process result (exec operations).
type Exec struct {
	ExitCode        *int    `json:"exit_code"`
	Signal          *string `json:"signal"`
	TimedOut        bool    `json:"timed_out"`
	StdoutTruncated bool    `json:"stdout_truncated"`
	StderrTruncated bool    `json:"stderr_truncated"`
}

// Gate identifies the gate that answered.
type Gate struct {
	Version      string `json:"version"`
	Principal    string `json:"principal"`
	MaxTier      string `json:"max_tier"`
	PolicySHA256 string `json:"policy_sha256"`
}

// Envelope is the uniform tool result (ARCHITECTURE §6). A success carries
// data and warnings (always present, possibly empty); a failure carries
// only ok, target and error.
type Envelope[T any] struct {
	OK       bool     `json:"ok"`
	Target   string   `json:"target"`
	Data     *T       `json:"data,omitempty"`
	Exec     *Exec    `json:"exec,omitempty"`
	Verified *bool    `json:"verified,omitempty"`
	Warnings []string `json:"warnings,omitzero"`
	Gate     *Gate    `json:"gate,omitempty"`
	Error    *Error   `json:"error,omitempty"`
	// Approval is set on envelopes of approval-gated tools (D-006).
	Approval *Approval `json:"approval,omitempty"`
}

// Approval is an approval record's state as a tool result shows it. Every
// string is server-generated: the URL from SHELL_MCP_APPROVAL_PUBLIC_URL and
// the id, the summary from the tool and the canonical arguments.
type Approval struct {
	ID        string `json:"id" jsonschema:"The approval id (26 characters); pass it as approval_id when calling the tool again."`
	Status    string `json:"status" jsonschema:"pending, approved, declined, expired or used."`
	URL       string `json:"url,omitempty" jsonschema:"The approval page for this request (out-of-band approval only)."`
	ExpiresAt string `json:"expires_at" jsonschema:"When the approval request expires, RFC 3339."`
	Summary   string `json:"summary" jsonschema:"The server's one-line description of the operation."`
}

// Success returns a successful envelope for target with data d.
func Success[T any](target string, d T) Envelope[T] {
	return Envelope[T]{OK: true, Target: target, Data: &d, Warnings: []string{}}
}

// Failure returns a failed envelope. A code outside the closed set becomes
// "internal"; the message becomes one line of at most MaxMessageBytes.
func Failure[T any](target string, e *Error) Envelope[T] {
	out := &Error{Code: e.Code, Message: oneLine(e.Message)}
	if !IsCode(out.Code) {
		out.Code = protocol.CodeInternal
	}
	return Envelope[T]{Target: target, Error: out}
}

// FromGate converts a decoded gate response. A failure keeps the gate's
// code; a success's data must decode strictly into T (unknown fields are a
// protocol mismatch: the server describes only what it knows).
func FromGate[T any](target string, r *protocol.Response) Envelope[T] {
	if !r.OK {
		if r.Error == nil {
			return Failure[T](target, Errorf(CodeProtocolMismatch, "the gate's failure carries no error"))
		}
		return Failure[T](target, &Error{Code: r.Error.Code, Message: r.Error.Message})
	}
	var d T
	raw := r.Data
	if len(raw) == 0 {
		raw = jsontext.Value("{}")
	}
	if err := json.Unmarshal(raw, &d, json.RejectUnknownMembers(true)); err != nil {
		return Failure[T](target, Errorf(CodeProtocolMismatch, "the gate's response data does not match this server version"))
	}
	e := Success(target, d)
	if len(r.Warnings) > 0 {
		e.Warnings = slices.Clone(r.Warnings)
	}
	e.Gate = GateOf(r)
	return e
}

// GateOf returns the gate block of a response, or nil.
func GateOf(r *protocol.Response) *Gate {
	if r.Gate == nil {
		return nil
	}
	return &Gate{Version: r.Gate.Version, Principal: r.Gate.Principal, MaxTier: r.Gate.MaxTier, PolicySHA256: r.Gate.PolicySHA256}
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= MaxMessageBytes {
		return s
	}
	s = s[:MaxMessageBytes]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
