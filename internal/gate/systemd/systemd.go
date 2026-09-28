// Package systemd validates arguments for, and parses the output of, the
// fixed systemctl and journalctl invocations the gate runs. Formats were
// verified against the systemd 257 (Debian 13) and 259 (Ubuntu 26.04 LTS)
// sources: `systemctl show -p` prints one KEY=VALUE per requested property
// that exists (unknown properties are silently omitted, a missing unit
// still exits 0 with LoadState=not-found); `systemctl list-units
// --output=json` prints one JSON array of objects keyed by the lowercased
// column headers ("unit", "load", "active", "sub", "description", and "job"
// only when some unit has a pending job).
package systemd

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds.
const (
	MaxValue = 4096
	MaxUnits = 10000
	// maxRelative bounds a relative journal time (-N<unit>): ten years.
	maxRelative = 10 * 365 * 24 * time.Hour
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

var errFormat = errors.New("unexpected output format")

// unitRE is an exact unit name with a type suffix: systemd's unit-name
// characters, no leading "-" (option injection), no glob characters
// (journalctl -u treats globs as patterns), no "/", and never all digits
// (systemctl show treats a number as a job id).
var unitRE = regexp.MustCompile(`^[A-Za-z0-9:_.\\@][A-Za-z0-9:_.\\@-]{0,249}\.(service|socket|target|timer|mount|automount|path|slice|scope|swap|device)$`)

// ValidUnit reports whether s is an exact unit name the gate may pass to
// systemctl or journalctl.
func ValidUnit(s string) bool { return len(s) <= 256 && unitRE.MatchString(s) }

var keyRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// ParseShow parses `systemctl show -p` output strictly: every line is
// KEY=VALUE with KEY one of want, no key twice, no blank lines (one unit),
// values valid UTF-8 and at most MaxValue bytes. Missing keys are allowed.
func ParseShow(out []byte, want []string) (map[string]string, error) {
	got := map[string]string{}
	text := strings.TrimSuffix(string(out), "\n")
	if text == "" {
		return got, nil
	}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		switch {
		case !ok || !keyRE.MatchString(k):
			return nil, fmt.Errorf("show: line is not KEY=VALUE: %w", errFormat)
		case !slices.Contains(want, k):
			return nil, fmt.Errorf("show: unrequested property: %w", errFormat)
		case len(v) > MaxValue || !utf8.ValidString(v):
			return nil, fmt.Errorf("show: value too long or not UTF-8: %w", errFormat)
		}
		if _, dup := got[k]; dup {
			return nil, fmt.Errorf("show: property repeated: %w", errFormat)
		}
		got[k] = v
	}
	return got, nil
}

// rawUnit has pointers so that missing required fields are detected.
type rawUnit struct {
	Unit        *string `json:"unit"`
	Load        *string `json:"load"`
	Active      *string `json:"active"`
	Sub         *string `json:"sub"`
	Job         *string `json:"job"`
	Description *string `json:"description"`
}

// ParseListUnits parses `systemctl list-units --output=json`: exactly one
// JSON array (plus a trailing newline) of objects with string fields unit,
// load, active, sub and description, and optionally job. Unknown members
// are ignored so that a later systemd adding a column does not break the
// op; at most MaxUnits entries.
func ParseListUnits(out []byte) ([]Unit, error) {
	b := bytes.TrimSuffix(out, []byte("\n"))
	if len(b) == 0 || b[0] != '[' {
		return nil, fmt.Errorf("list-units: not a JSON array: %w", errFormat)
	}
	var raw []rawUnit
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("list-units: %w", errFormat)
	}
	if len(raw) > MaxUnits {
		return nil, fmt.Errorf("list-units: more than %d units: %w", MaxUnits, errFormat)
	}
	units := make([]Unit, 0, len(raw))
	for _, r := range raw {
		if r.Unit == nil || r.Load == nil || r.Active == nil || r.Sub == nil || r.Description == nil {
			return nil, fmt.Errorf("list-units: entry lacks a field: %w", errFormat)
		}
		u := Unit{Unit: *r.Unit, Load: *r.Load, Active: *r.Active, Sub: *r.Sub, Description: *r.Description}
		if r.Job != nil {
			u.Job = *r.Job
		}
		units = append(units, u)
	}
	return units, nil
}

var relRE = regexp.MustCompile(`^-([1-9]\d{0,6})([smhdw])$`)

// JournalTime converts a since/until value — RFC 3339 with a zone ("Z" or
// an offset), or a relative "-N<s|m|h|d|w>" of at most ten years — into
// journalctl's "@<unix seconds>" form (systemd.time(7)), computed here, so
// that nothing from the request reaches journalctl verbatim.
func JournalTime(s string, now time.Time) (string, error) {
	var t time.Time
	if m := relRE.FindStringSubmatch(s); m != nil {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return "", fmt.Errorf("time: %w", errFormat)
		}
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
		if n > int64(maxRelative/unit) {
			return "", errors.New("relative time is longer than ten years")
		}
		t = now.Add(-time.Duration(n) * unit)
	} else {
		var err error
		if t, err = time.Parse(time.RFC3339, s); err != nil || !strings.Contains(s, "T") {
			return "", errors.New("time must be RFC 3339 (2026-09-27T10:00:00Z) or relative (-15m, -2h, -1d, -1w)")
		}
	}
	if t.Unix() < 0 {
		return "", errors.New("time is before 1970")
	}
	return "@" + strconv.FormatInt(t.Unix(), 10), nil
}

var priorities = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// ValidPriority reports whether p is one of the syslog priority names
// journalctl -p accepts.
func ValidPriority(p string) bool { return slices.Contains(priorities, p) }
