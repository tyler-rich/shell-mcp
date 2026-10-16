package envelope

import (
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Server codes. (stub)
const (
	CodeTargetUnreachable = "target_unreachable"
	CodeHostKeyMismatch   = "host_key_mismatch"
	CodeProtocolMismatch  = "protocol_mismatch"
)

// ServerCodes (stub).
var ServerCodes = []string{}

// MaxMessageBytes (stub).
const MaxMessageBytes = 512

// Codes (stub).
func Codes() []string { return nil }

// IsCode (stub).
func IsCode(string) bool { return false }

// Error (stub).
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf (stub).
func Errorf(code, format string, _ ...any) *Error { return &Error{Code: code, Message: format} }

// AsError (stub).
func AsError(error) *Error { return &Error{} }

// Gate (stub).
type Gate struct {
	Version      string `json:"version"`
	Principal    string `json:"principal"`
	MaxTier      string `json:"max_tier"`
	PolicySHA256 string `json:"policy_sha256"`
}

// Envelope (stub).
type Envelope[T any] struct {
	OK       bool     `json:"ok"`
	Target   string   `json:"target"`
	Data     *T       `json:"data,omitempty"`
	Verified *bool    `json:"verified,omitempty"`
	Warnings []string `json:"warnings"`
	Gate     *Gate    `json:"gate,omitempty"`
	Error    *Error   `json:"error,omitempty"`
}

// Success (stub).
func Success[T any](target string, d T) Envelope[T] { return Envelope[T]{OK: true, Target: target, Data: &d} }

// Failure (stub).
func Failure[T any](target string, e *Error) Envelope[T] { return Envelope[T]{Target: target, Error: e} }

// FromGate (stub).
func FromGate[T any](target string, _ *protocol.Response) Envelope[T] { return Envelope[T]{Target: target} }
