// Package protocol holds the shared gate/helper wire types (docs/ARCHITECTURE.md
// §4), the protocol version and size limits, and strict request decoding. It
// is shared by the server, the gate and the helper and has no Linux-only code.
package protocol

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"syscall"
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
	// IDBytes is the length of a request id: a UUID v4 in lowercase
	// canonical form (ARCHITECTURE §4.1). The id is echoed in the response
	// and written into the gate's and the helper's audit lines, which join
	// on it, so nothing else is accepted.
	IDBytes = 36
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

// The privileged helper's self-check codes (PRIVILEGED §7): answered only
// to a peer that passed the SO_PEERCRED check, before the request is read,
// so the response has no id. The gate passes them through unchanged.
const (
	// CodeHelperInstallInsecure: the helper is not root under its unit, runs
	// without NoNewPrivs, or its binary or policy file is missing, not
	// root-owned or group/other-writable.
	CodeHelperInstallInsecure = "helper_install_insecure"
	// CodeHelperPolicyInvalid: the privileged policy does not parse or fails
	// validation.
	CodeHelperPolicyInvalid = "helper_policy_invalid"
	// CodeHelperPolicyMismatch: the policy's SHA-256 is not the one the
	// units were generated from.
	CodeHelperPolicyMismatch = "helper_policy_mismatch"
	// CodeHelperClientUIDMismatch: the policy's client_uid is not the unit's
	// SHELL_MCP_PRIVD_CLIENT_UID.
	CodeHelperClientUIDMismatch = "helper_client_uid_mismatch"
	// CodeHelperCapabilitiesBroad: the capability bounding set is broader
	// than the unit declares.
	CodeHelperCapabilitiesBroad = "helper_capabilities_broad"
	// CodeHelperSandboxUnavailable: the helper could not apply its Landlock
	// sandbox in the core unit under sandbox.landlock: required (distinct from
	// the gate's own CodeSandboxUnavailable).
	CodeHelperSandboxUnavailable = "helper_sandbox_unavailable"
)

// Codes lists every gate error code.
var Codes = []string{
	CodeProtocolMismatch, CodeBadRequest, CodeUnknownOp, CodeTierDenied, CodePolicyDenied,
	CodePathDenied, CodeNotFound, CodeNotADirectory, CodeIsADirectory, CodeTooLarge, CodeExists,
	CodeTemplateMismatch, CodeNotAuthorized, CodeSandboxUnavailable, CodePrivilegedDisabled,
	CodeHelperUnavailable, CodeHelperRefused, CodeBackupFailed, CodeExecFailed, CodeTimeout,
	CodeVerifyFailed, CodeInstallInsecure, CodeInternal,
	CodeHelperInstallInsecure, CodeHelperPolicyInvalid, CodeHelperPolicyMismatch,
	CodeHelperClientUIDMismatch, CodeHelperCapabilitiesBroad, CodeHelperSandboxUnavailable,
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
//
// encoding/json/v2 (stable in Go 1.27) rejects duplicate object names and
// invalid UTF-8 by default, matches names case-sensitively, and requires the
// input to be exactly one JSON value; RejectUnknownMembers adds unknown
// fields. Messages are fixed strings and never echo request content.
func DecodeRequest(r io.Reader) (*Request, error) {
	data, err := readLine(r, MaxRequestBytes+1)
	if err != nil {
		return nil, &DecodeError{CodeBadRequest, "request could not be read"}
	}
	if len(data) > MaxRequestBytes {
		return nil, &DecodeError{CodeTooLarge, "request exceeds 2 MiB"}
	}
	var req Request
	if err := json.Unmarshal(data, &req, json.RejectUnknownMembers(true)); err != nil {
		// A request from a different protocol version may carry fields this
		// version does not know; report the version, not the field.
		var peek struct {
			V *int `json:"v"`
		}
		if json.Unmarshal(data, &peek) == nil && peek.V != nil && *peek.V != Version {
			return nil, &DecodeError{CodeProtocolMismatch, "unsupported protocol version"}
		}
		return nil, &DecodeError{CodeBadRequest, "request is not one strict JSON object with known fields"}
	}
	if req.V != Version {
		return nil, &DecodeError{CodeProtocolMismatch, "unsupported protocol version"}
	}
	if !validID(req.ID) {
		return nil, &DecodeError{CodeBadRequest, "id must be a lowercase UUID v4"}
	}
	if !validOp(req.Op) {
		return nil, &DecodeError{CodeBadRequest, "op is missing or malformed"}
	}
	if req.TimeoutMS < 0 {
		return nil, &DecodeError{CodeBadRequest, "timeout_ms must not be negative"}
	}
	if len(req.Args) > 0 {
		switch req.Args.Kind() {
		case '{':
		case 'n':
			req.Args = nil
		default:
			return nil, &DecodeError{CodeBadRequest, "args must be an object"}
		}
	}
	return &req, nil
}

// readLine reads up to and including the first newline, or to EOF, or until
// limit bytes have been read. The request is one newline-terminated line
// (ARCHITECTURE §4), so the gate never waits for EOF from a client that
// keeps its stdin open; anything after the newline is not consumed as part
// of the request.
func readLine(r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 32<<10)
	for len(buf) < limit {
		n, err := r.Read(chunk[:min(len(chunk), limit-len(buf))])
		if i := bytes.IndexByte(chunk[:n], '\n'); i >= 0 {
			return append(buf, chunk[:i+1]...), nil
		}
		buf = append(buf, chunk[:n]...)
		if errors.Is(err, io.EOF) {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

// validID accepts exactly a lowercase canonical UUID v4:
// xxxxxxxx-xxxx-4xxx-Nxxx-xxxxxxxxxxxx with lowercase hex digits, version
// nibble 4 and variant nibble N in 8, 9, a, b (RFC 9562 §4.1, §5.4).
func validID(s string) bool {
	if len(s) != IDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		case 14:
			if c != '4' {
				return false
			}
		case 19:
			if c != '8' && c != '9' && c != 'a' && c != 'b' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

func validOp(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

// DecodeArgs strictly decodes op arguments into v (a pointer to a struct).
// Absent arguments decode as an empty object.
func DecodeArgs(raw jsontext.Value, v any) error {
	if len(raw) == 0 || raw.Kind() == 'n' {
		raw = jsontext.Value("{}")
	}
	if err := json.Unmarshal(raw, v, json.RejectUnknownMembers(true)); err != nil {
		return errors.New("args are not a strict object of known fields with the expected types")
	}
	return nil
}

// marshalOpts: deterministic output; invalid UTF-8 in host data (file
// names, command output) is replaced with U+FFFD rather than failing.
var marshalOpts = json.JoinOptions(json.Deterministic(true), jsontext.AllowInvalidUTF8(true))

// EncodeResponse writes resp followed by a newline. It fails without writing
// anything if the encoding exceeds MaxResponseBytes.
func EncodeResponse(w io.Writer, resp *Response) error {
	if resp.Warnings == nil {
		resp.Warnings = []string{}
	}
	out, err := json.Marshal(resp, marshalOpts)
	if err != nil {
		return err
	}
	if len(out)+1 > MaxResponseBytes {
		return ErrResponseTooLarge
	}
	_, err = w.Write(append(out, '\n'))
	return err
}

// ErrResponseTooLarge is returned by EncodeResponse.
var ErrResponseTooLarge = errors.New("response exceeds 4 MiB")

// Marshal encodes v as JSON with the protocol's options.
func Marshal(v any) (jsontext.Value, error) {
	out, err := json.Marshal(v, marshalOpts)
	return jsontext.Value(out), err
}

// ErrNoResponse is returned by DecodeResponse when the peer closed the
// connection without sending anything (the privileged helper's refusal).
var ErrNoResponse = errors.New("the peer closed the connection without a response")

// maxMessageBytes bounds an error message in a decoded response.
const maxMessageBytes = 1024

// DecodeResponse reads exactly one newline-terminated response (at most
// MaxResponseBytes) and decodes it strictly: unknown fields, duplicate
// keys, trailing data, another version, an error code outside the closed
// set, a multi-line or oversized message, and an inconsistent ok/error pair
// are errors. The id must be a valid request id, except on a failure
// answered before the request was read (it is then empty). A peer that
// closes without sending anything gives ErrNoResponse.
func DecodeResponse(r io.Reader) (*Response, error) {
	data, err := readLine(r, MaxResponseBytes+1)
	switch {
	case len(data) == 0 && errors.Is(err, syscall.ECONNRESET):
		// A peer that closes with our request unread resets the
		// connection: it sent nothing, as with a plain close.
		return nil, ErrNoResponse
	case err != nil:
		// Wrapped, so a caller can tell a deadline from a broken peer.
		return nil, fmt.Errorf("response could not be read: %w", err)
	case len(data) == 0:
		return nil, ErrNoResponse
	case len(data) > MaxResponseBytes:
		return nil, &DecodeError{CodeTooLarge, "response exceeds 4 MiB"}
	}
	var resp Response
	if err := json.Unmarshal(data, &resp, json.RejectUnknownMembers(true)); err != nil {
		return nil, &DecodeError{CodeBadRequest, "response is not one strict JSON object with known fields"}
	}
	switch {
	case resp.V != Version:
		return nil, &DecodeError{CodeProtocolMismatch, "unsupported protocol version"}
	case resp.OK && resp.Error != nil, !resp.OK && resp.Error == nil:
		return nil, &DecodeError{CodeBadRequest, "response has an inconsistent ok and error"}
	case resp.OK && !validID(resp.ID), resp.ID != "" && !validID(resp.ID):
		return nil, &DecodeError{CodeBadRequest, "response id is malformed"}
	}
	if e := resp.Error; e != nil {
		if !slices.Contains(Codes, e.Code) {
			return nil, &DecodeError{CodeBadRequest, "response error code is not in the closed set"}
		}
		if len(e.Message) > maxMessageBytes || strings.ContainsAny(e.Message, "\r\n") {
			return nil, &DecodeError{CodeBadRequest, "response error message is not one bounded line"}
		}
	}
	return &resp, nil
}
