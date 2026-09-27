package config

import "time"

// LookupFunc returns the value of an environment variable and whether it is set.
type LookupFunc func(key string) (string, bool)

// Error is a configuration error with a one-line reason.
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Secret holds a secret string.
type Secret struct{ v string }

// Len returns the secret's length.
func (s Secret) Len() int { return len(s.v) }

// PrivateKey holds a parsed SSH private key.
type PrivateKey struct{}

// Fingerprint returns the public key fingerprint.
func (k *PrivateKey) Fingerprint() string { return "" }

// Target is one SSH target.
type Target struct {
	Name     string
	Host     string
	Port     int
	User     string
	HostKeys []string
	Key      *PrivateKey
}

// Config is the validated server configuration.
type Config struct {
	Profile          string
	Transport        string
	Bind             string
	Port             int
	Path             string
	AuthMode         string
	Token            Secret
	Targets          []Target
	SSHMaxSessions   int
	MaxOutputBytes   int
	ApprovalTiers    []string
	ApprovalFallback string
	ApprovalTTL      time.Duration
	MaxTimeout       time.Duration
	Warnings        []string
}

// Effective returns the printable configuration.
func (c *Config) Effective() any { return nil }

// Load reads and validates the configuration.
func Load(_ LookupFunc) (*Config, error) { return nil, &Error{Reason: "not implemented"} }
