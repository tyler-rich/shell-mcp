// Package totp verifies the one-time codes approvers enter on the approval
// page: RFC 6238 with HMAC-SHA-1, six digits and 30-second steps, ±1 step of
// clock skew, each step accepted once per approver, and per-approver
// wrong-code lockouts (docs/handoff/S4B-APPROVAL.md §6.4).
package totp

import (
	"errors"
	"time"
)

// Parameters of the scheme (handoff §6.4). They are not configurable.
const (
	Digits       = 6
	Period       = 30 * time.Second
	Skew         = 1
	MaxWrong     = 3
	WrongWindow  = time.Minute
	FirstLockout = 15 * time.Minute
	MaxLockout   = 24 * time.Hour
	MinSeedBytes = 20
)

// Result is the outcome of one verification.
type Result int

// Results of Verify.
const (
	Accepted Result = iota + 1
	BadCode
	ReusedCode
	Locked
)

const maxCodeInput = 16

func (Result) String() string { return "" }

// Lockout describes an approver's lockout.
type Lockout struct {
	Until       time.Time
	Consecutive int
	Started     bool
}

// Outcome is what Verify returns.
type Outcome struct {
	Result  Result
	Lockout *Lockout
}

// Verifier holds every approver's TOTP state.
type Verifier struct{}

// New returns a verifier for the given approvers.
func New(_ map[string][]byte, _ func() time.Time) (*Verifier, error) {
	return nil, errors.New("totp: not implemented")
}

// Verify checks code for approver.
func (*Verifier) Verify(_, _ string) Outcome { return Outcome{} }

// Generate returns the code for seed at t.
func Generate(_ []byte, _ time.Time) string { return "" }

// ParseCode normalises a typed code.
func ParseCode(_ string) (string, bool) { return "", false }

func hotp(_ []byte, _ uint64, _ int) string { return "" }

func stepAt(_ time.Time) int64 { return 0 }
