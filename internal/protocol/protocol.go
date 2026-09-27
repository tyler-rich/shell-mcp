// Package protocol holds the shared gate/helper wire types (docs/ARCHITECTURE.md
// §4), the protocol version and size limits, and strict request decoding. It
// is shared by the server, the gate and the helper and has no Linux-only code.
package protocol

import (
	"encoding/json/jsontext"
	"errors"
	"io"
)

// Version is the wire protocol version. A request with any other "v" is
// answered with CodeProtocolMismatch.
const Version = 1

// Hello is the exec request the server sends; sshd passes it to the forced
// command in SSH_ORIGINAL_COMMAND.
const Hello = "shell-mcp-gate/1"

// Size limits.
const (
	MaxRequestBytes  = 2 << 20
	MaxResponseBytes = 4 << 20
	// MaxIDBytes bounds the request id echoed back in the response.
	MaxIDBytes = 64
)

// Gate error codes (closed set, ARCHITECTURE §4.2).
const (
	CodeProtocolMismatch   = "protocol_mismatch"
	CodeBadRequest         = "bad_request"
	CodeUnknownOp          = "unknown_op"
	CodeTierDenied         = "tier_denied"
	CodePolicyDenied       = "policy_denied"
	CodePathDenied         = "path_denied"
	CodeNotFound           = "not_found"
	CodeNotADirectory      = "not_a_directory"
	CodeIsADirectory       = "is_a_directory"
	CodeTooLarge           = "too_large"
	CodeExists             = "exists"
	CodeTemplateMismatch   = "template_mismatch"
	CodeNotAuthorized      = "not_authorized"
	CodeSandboxUnavailable = "sandbox_unavailable"
	CodePrivilegedDisabled = "privileged_disabled"
	CodeHelperUnavailable  = "helper_unavailable"
	CodeHelperRefused      = "helper_refused"
	CodeBackupFailed       = "backup_failed"
	CodeExecFailed         = "exec_failed"
	CodeTimeout            = "timeout"
	CodeVerifyFailed       = "verify_failed"
	CodeInstallInsecure    = "install_insecure"
	CodeInternal           = "internal"
)

// Codes lists every gate error code.
var Codes = []string{
	CodeProtocolMismatch, CodeBadRequest, CodeUnknownOp, CodeTierDenied, CodePolicyDenied,
	CodePathDenied, CodeNotFound, CodeNotADirectory, CodeIsADirectory, CodeTooLarge, CodeExists,
	CodeTemplateMismatch, CodeNotAuthorized, CodeSandboxUnavailable, CodePrivilegedDisabled,
	CodeHelperUnavailable, CodeHelperRefused, CodeBackupFailed, CodeExecFailed, CodeTimeout,
	CodeVerifyFailed, CodeInstallInsecure, CodeInternal,
}

// Gate operations (ARCHITECTURE §4.3).
const (
	OpHello             = "hello"
	OpPolicy            = "policy"
	OpSysinfo           = "sysinfo"
	OpDisk              = "disk"
	OpProcesses         = "processes"
	OpServiceStatus     = "service_status"
	OpServiceList       = "service_list"
	OpJournal           = "journal"
	OpListDir           = "list_dir"
	OpStat              = "stat"
	OpReadFile          = "read_file"
	OpFind              = "find"
	OpCertInspect       = "cert_inspect"
	OpGitStatus         = "git_status"
	OpGitLog            = "git_log"
	OpGitDiff           = "git_diff"
	OpServiceControl    = "service_control"
	OpWriteFile         = "write_file"
	OpMkdir             = "mkdir"
	OpCopy              = "copy"
	OpMove              = "move"
	OpChmod             = "chmod"
	OpGitPull           = "git_pull"
	OpDelete            = "delete"
	OpDeletePreview     = "delete_preview"
	OpGitDiscard        = "git_discard"
	OpGitDiscardPreview = "git_discard_preview"
	OpExec              = "exec"
)

// Privileged operations forwarded to the helper (PRIVILEGED.md §6).
const (
	OpPrivReadFile       = "priv_read_file"
	OpPrivListDir        = "priv_list_dir"
	OpPrivStat           = "priv_stat"
	OpPrivWriteFile      = "priv_write_file"
	OpPrivMkdir          = "priv_mkdir"
	OpPrivChown          = "priv_chown"
	OpPrivChmod          = "priv_chmod"
	OpPrivCopy           = "priv_copy"
	OpPrivMove           = "priv_move"
	OpPrivListBackups    = "priv_list_backups"
	OpPrivRestoreBackup  = "priv_restore_backup"
	OpPrivDelete         = "priv_delete"
	OpPrivExec           = "priv_exec"
	OpPrivPkgUpdateIndex = "priv_pkg_update_index"
	OpPrivPkgInstall     = "priv_pkg_install"
	OpPrivPkgUpgrade     = "priv_pkg_upgrade"
	OpPrivPkgRemove      = "priv_pkg_remove"
)

// PrivOps lists every privileged operation.
var PrivOps = []string{
	OpPrivReadFile, OpPrivListDir, OpPrivStat, OpPrivWriteFile, OpPrivMkdir, OpPrivChown,
	OpPrivChmod, OpPrivCopy, OpPrivMove, OpPrivListBackups, OpPrivRestoreBackup, OpPrivDelete,
	OpPrivExec, OpPrivPkgUpdateIndex, OpPrivPkgInstall, OpPrivPkgUpgrade, OpPrivPkgRemove,
}

// Request is one gate or helper request.
type Request struct {
	V         int            `json:"v"`
	ID        string         `json:"id"`
	Op        string         `json:"op"`
	Args      jsontext.Value `json:"args,omitzero"`
	TimeoutMS int64          `json:"timeout_ms,omitzero"`
}

// Response is one gate or helper response.
type Response struct {
	V        int            `json:"v"`
	ID       string         `json:"id"`
	OK       bool           `json:"ok"`
	Data     jsontext.Value `json:"data,omitzero"`
	Error    *Error         `json:"error,omitempty"`
	Warnings []string       `json:"warnings"`
	Gate     *GateInfo      `json:"gate,omitempty"`
}

// Error is the failure detail of a response. Message is one line and never
// carries file contents or command output.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// GateInfo identifies the gate that answered.
type GateInfo struct {
	Version      string `json:"version"`
	Principal    string `json:"principal"`
	PolicySHA256 string `json:"policy_sha256,omitempty"`
	MaxTier      string `json:"max_tier,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
}

// DecodeError is returned by DecodeRequest; Code is CodeTooLarge,
// CodeProtocolMismatch or CodeBadRequest.
type DecodeError struct {
	Code string
	Msg  string
}

func (e *DecodeError) Error() string { return e.Code + ": " + e.Msg }

// DecodeRequest reads exactly one request from r. It reads at most
// MaxRequestBytes+1 bytes; unknown fields, duplicate object keys, invalid
// UTF-8, trailing data and more than one JSON value are errors.
func DecodeRequest(r io.Reader) (*Request, error) {
	return nil, errors.New("not implemented")
}

// DecodeArgs strictly decodes op arguments into v (a pointer to a struct).
// Absent arguments decode as an empty object.
func DecodeArgs(raw jsontext.Value, v any) error {
	return errors.New("not implemented")
}

// EncodeResponse writes resp followed by a newline. It fails without writing
// anything if the encoding exceeds MaxResponseBytes.
func EncodeResponse(w io.Writer, resp *Response) error {
	return errors.New("not implemented")
}

// ErrResponseTooLarge is returned by EncodeResponse.
var ErrResponseTooLarge = errors.New("response exceeds 4 MiB")

// Marshal encodes v as JSON with the protocol's options.
func Marshal(v any) (jsontext.Value, error) {
	return nil, errors.New("not implemented")
}
