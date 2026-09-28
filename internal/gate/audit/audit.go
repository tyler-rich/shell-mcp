// Package audit writes one syslog audit line per gate request (D-009,
// S-11).
package audit

// Record is one request's audit data.
type Record struct {
	Principal  string
	Client     string
	Op         string
	Args       map[string]any
	Outcome    string
	DurationMS int64
}

// Sink receives audit records.
type Sink interface{ Log(r *Record) }

// DevLog is the system syslog socket.
const DevLog = "/dev/log"

// Line is not implemented yet.
func Line(_ *Record) string { return "" }

// Client is not implemented yet.
func Client(_ *string) string { return "" }

// SanitizeArgs is not implemented yet.
func SanitizeArgs(_ string, _ []byte) map[string]any { return nil }

// Syslog is not implemented yet.
type Syslog struct{}

// NewSyslog is not implemented yet.
func NewSyslog(_ string) *Syslog { return &Syslog{} }

// Log is not implemented yet.
func (*Syslog) Log(_ *Record) {}
