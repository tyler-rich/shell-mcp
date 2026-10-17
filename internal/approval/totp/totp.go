// Package totp verifies the one-time codes approvers enter on the approval
// page: RFC 6238 with HMAC-SHA-1, six digits and 30-second steps, ±1 step of
// clock skew, each step accepted once per approver, and per-approver
// wrong-code lockouts (docs/handoff/S4B-APPROVAL.md §6.4).
//
// Approve and decline share one Verify and one state per approver, so a code
// accepted for either decision is refused for the next. Nothing here logs,
// and no error or result carries a code or a seed.
package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 with HMAC-SHA-1 is what authenticators implement (handoff §6.4); collisions do not affect HMAC.
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Parameters of the scheme (handoff §6.4). They are not configurable.
const (
	// Digits is the code length.
	Digits = 6
	// Period is the time step.
	Period = 30 * time.Second
	// Skew is how many steps either side of the current one are accepted.
	Skew = 1
	// MaxWrong is how many wrong codes an approver may enter within
	// WrongWindow; the next wrong one starts a lockout.
	MaxWrong = 3
	// WrongWindow is the rolling window for MaxWrong.
	WrongWindow = time.Minute
	// FirstLockout is the first lockout's length; each consecutive one
	// doubles, up to MaxLockout.
	FirstLockout = 15 * time.Minute
	// MaxLockout caps a lockout.
	MaxLockout = 24 * time.Hour
	// MinSeedBytes is the shortest seed accepted: 160 bits.
	MinSeedBytes = 20
)

// maxCodeInput bounds what ParseCode looks at.
const maxCodeInput = 16

// Result is the outcome of one verification.
type Result int

// Results of Verify.
const (
	// Accepted: the code is correct for a step after the last accepted one.
	Accepted Result = iota + 1
	// BadCode: the code is malformed, wrong, outside the skew window, or
	// for an unknown approver. A known approver's bad code counts towards
	// a lockout.
	BadCode
	// ReusedCode: the code is correct for a step at or before the last
	// accepted one (which at start is the start step). It is not counted.
	ReusedCode
	// Locked: the approver is locked out; the code was not checked.
	Locked
)

// String returns the audit reason for r.
func (r Result) String() string {
	switch r {
	case Accepted:
		return "accepted"
	case BadCode:
		return "bad_code"
	case ReusedCode:
		return "reused_code"
	case Locked:
		return "locked"
	}
	return "unknown"
}

// Lockout describes an approver's lockout.
type Lockout struct {
	// Until is when it ends.
	Until time.Time
	// Consecutive counts lockouts since the approver's last success,
	// this one included.
	Consecutive int
	// Started is true on the wrong code that started it.
	Started bool
}

// Outcome is what Verify returns. Lockout is set when Result is Locked, and
// when a BadCode started a lockout.
type Outcome struct {
	Result  Result
	Lockout *Lockout
}

// Verifier holds every approver's TOTP state, in memory only. It is safe for
// concurrent use.
type Verifier struct {
	now       func() time.Time
	mu        sync.Mutex
	approvers map[string]*state
}

type state struct {
	seed []byte
	// last is the last accepted step; no code for it or an earlier step
	// is accepted.
	last int64
	// wrong holds the times of the wrong codes inside the window, at most
	// MaxWrong of them.
	wrong       []time.Time
	lockedUntil time.Time
	consecutive int
}

// New returns a verifier for the given approvers (name to seed), reading the
// time from now. Each approver's last accepted step starts as the current
// step, so no code seen before the process started is accepted. The seeds
// are copied.
func New(seeds map[string][]byte, now func() time.Time) (*Verifier, error) {
	if now == nil {
		return nil, errors.New("totp: a clock is required")
	}
	if len(seeds) == 0 {
		return nil, errors.New("totp: no approvers")
	}
	start := stepAt(now())
	v := &Verifier{now: now, approvers: make(map[string]*state, len(seeds))}
	for name, seed := range seeds {
		if name == "" {
			return nil, errors.New("totp: an approver has no name")
		}
		if len(seed) < MinSeedBytes {
			return nil, errors.New("totp: a seed is shorter than 160 bits")
		}
		v.approvers[name] = &state{seed: append([]byte(nil), seed...), last: start, wrong: make([]time.Time, 0, MaxWrong)}
	}
	return v, nil
}

// Verify checks a code typed by the named approver, at the verifier's
// current time. During a lockout every code is refused unchecked. An
// accepted code records its step and clears the approver's wrong-code and
// lockout counts.
func (v *Verifier) Verify(approver, code string) Outcome {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	a, ok := v.approvers[approver]
	if !ok {
		return Outcome{Result: BadCode}
	}
	if now.Before(a.lockedUntil) {
		return Outcome{Result: Locked, Lockout: &Lockout{Until: a.lockedUntil, Consecutive: a.consecutive}}
	}

	digits, wellFormed := ParseCode(code)
	if !wellFormed {
		digits = "------" // compared like any code, matches none
	}
	cur := stepAt(now)
	matched, reused := int64(-1), false
	// Every step in the window is computed and compared in constant time.
	for s := cur - Skew; s <= cur+Skew; s++ {
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(a.seed, uint64(s), Digits)), []byte(digits)) == 1 {
			if s > a.last {
				matched = s
			} else {
				reused = true
			}
		}
	}
	switch {
	case matched >= 0:
		a.last = matched
		a.wrong = a.wrong[:0]
		a.consecutive = 0
		return Outcome{Result: Accepted}
	case reused:
		return Outcome{Result: ReusedCode}
	}
	return Outcome{Result: BadCode, Lockout: a.countWrong(now)}
}

// countWrong records a wrong code at now and returns the lockout it starts,
// if it is more than MaxWrong within WrongWindow.
func (a *state) countWrong(now time.Time) *Lockout {
	kept := a.wrong[:0]
	for _, t := range a.wrong {
		if now.Sub(t) < WrongWindow {
			kept = append(kept, t)
		}
	}
	a.wrong = kept
	if len(a.wrong) < MaxWrong {
		a.wrong = append(a.wrong, now)
		return nil
	}
	a.wrong = a.wrong[:0]
	a.consecutive++
	a.lockedUntil = now.Add(lockoutLength(a.consecutive))
	return &Lockout{Until: a.lockedUntil, Consecutive: a.consecutive, Started: true}
}

// lockoutLength is FirstLockout doubled for each earlier consecutive
// lockout, capped at MaxLockout.
func lockoutLength(consecutive int) time.Duration {
	d := FirstLockout
	for i := 1; i < consecutive && d < MaxLockout; i++ {
		d *= 2
	}
	return min(d, MaxLockout)
}

// Generate returns the code an authenticator shows for seed at t. The server
// never needs it; tests and simulated approvers do.
func Generate(seed []byte, t time.Time) string {
	s := stepAt(t)
	if s < 0 {
		return ""
	}
	return hotp(seed, uint64(s), Digits)
}

// ParseCode returns the six digits of a typed code. Spaces anywhere are
// dropped (authenticators show "123 456"); anything else but six ASCII
// digits, or more than 16 bytes, is refused.
func ParseCode(s string) (string, bool) {
	if len(s) > maxCodeInput {
		return "", false
	}
	var b [Digits]byte
	n := 0
	for i := range len(s) {
		switch c := s[i]; {
		case c == ' ':
		case c >= '0' && c <= '9' && n < Digits:
			b[n] = c
			n++
		default:
			return "", false
		}
	}
	if n != Digits {
		return "", false
	}
	return string(b[:]), true
}

// hotp is RFC 4226's HOTP value of seed at counter, zero-padded to digits
// (6 or 8).
func hotp(seed []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, seed)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	v := bin % mod
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out)
}

// stepAt is RFC 6238's T: floor(Unix time / 30).
func stepAt(t time.Time) int64 {
	u := t.Unix()
	s := u / int64(Period/time.Second)
	if u < 0 && u%int64(Period/time.Second) != 0 {
		s--
	}
	return s
}
