package config

import (
	"crypto/subtle"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

const masked = "[REDACTED]"

// Secret holds a secret string. Every formatting, JSON and slog path renders
// it as a fixed mask; only Equal and Len read it.
type Secret struct{ v string }

// Len returns the secret's length in bytes.
func (s Secret) Len() int { return len(s.v) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

// Equal compares candidate with the secret in constant time.
func (s Secret) Equal(candidate string) bool {
	return s.v != "" && subtle.ConstantTimeCompare([]byte(s.v), []byte(candidate)) == 1
}

// String implements fmt.Stringer.
func (Secret) String() string { return masked }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return masked }

// Format implements fmt.Formatter so that no verb prints the value.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(masked)) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + masked + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Secret) MarshalText() ([]byte, error) { return []byte(masked), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(masked) }

// PrivateKey is a parsed Ed25519 SSH private key. It renders as its public
// key fingerprint in every formatting, JSON and slog path.
type PrivateKey struct {
	signer      ssh.Signer
	fingerprint string
}

// Signer returns the SSH signer for client authentication.
func (k *PrivateKey) Signer() ssh.Signer { return k.signer }

// Fingerprint returns the public key's "SHA256:" fingerprint.
func (k *PrivateKey) Fingerprint() string {
	if k == nil {
		return ""
	}
	return k.fingerprint
}

// String implements fmt.Stringer.
func (k *PrivateKey) String() string { return "ssh-ed25519 " + k.Fingerprint() }

// GoString implements fmt.GoStringer.
func (k *PrivateKey) GoString() string { return k.String() }

// Format implements fmt.Formatter so that no verb prints key material.
func (k *PrivateKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

// MarshalJSON implements json.Marshaler.
func (k *PrivateKey) MarshalJSON() ([]byte, error) { return []byte(`"` + k.Fingerprint() + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (k *PrivateKey) MarshalText() ([]byte, error) { return []byte(k.Fingerprint()), nil }

// LogValue implements slog.LogValuer.
func (k *PrivateKey) LogValue() slog.Value { return slog.StringValue(k.Fingerprint()) }
