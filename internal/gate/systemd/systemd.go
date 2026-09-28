// Package systemd validates arguments for, and parses the output of, the
// fixed systemctl and journalctl invocations the gate runs.
package systemd

import (
	"errors"
	"time"
)

// Bounds.
const (
	MaxValue = 4096
	MaxUnits = 10000
)

// ShowProperties are the properties service_status asks for.
var ShowProperties = []string{"Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState",
	"MainPID", "ActiveEnterTimestamp", "StateChangeTimestamp", "MemoryCurrent", "NRestarts", "Result"}

// Unit is one list-units entry.
type Unit struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Job         string `json:"job,omitempty"`
	Description string `json:"description"`
}

var errTODO = errors.New("not implemented")

// ValidUnit is not implemented yet.
func ValidUnit(_ string) bool { return false }

// ParseShow is not implemented yet.
func ParseShow(_ []byte, _ []string) (map[string]string, error) { return nil, errTODO }

// ParseListUnits is not implemented yet.
func ParseListUnits(_ []byte) ([]Unit, error) { return nil, errTODO }

// JournalTime is not implemented yet.
func JournalTime(_ string, _ time.Time) (string, error) { return "", errTODO }

// ValidPriority is not implemented yet.
func ValidPriority(_ string) bool { return false }
