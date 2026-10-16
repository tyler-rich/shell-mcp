package tools

import (
	"testing"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/gate/systemd"
)

// FuzzJournalTimeAgreesWithGate: the server accepts exactly the since/until
// values the gate accepts (up to the server's 64-byte bound), so its early
// rejection never refuses what the gate would serve, nor passes what the
// gate refuses. modified_within shares the relative parser.
func FuzzJournalTimeAgreesWithGate(f *testing.F) {
	for _, s := range []string{"-15m", "-2h", "-1d", "-1w", "-3650d", "-3651d", "-521w", "-0s", "-1x", "15m",
		"2026-10-01T08:00:00Z", "2026-10-01T08:00:00+02:00", "2026-10-01T08:00:00.123456789-05:00", "2026-10-01T08:00:00",
		"2026-10-01 08:00:00Z", "1969-12-31T23:59:59Z", "yesterday", "", "-9999999s", "-10000000s"} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		_, serverOK := journalTime(s, now)
		_, gateErr := systemd.JournalTime(s, now)
		if len(s) <= 64 && serverOK != (gateErr == nil) {
			t.Fatalf("%q: server accepts %v, gate accepts %v", s, serverOK, gateErr == nil)
		}
		if len(s) > 64 && serverOK && s[0] != '-' {
			t.Fatalf("%q: accepted beyond the bound", s)
		}
		if secs, ok := relativeSeconds(s); ok && (secs <= 0 || secs > maxRelativeSeconds) {
			t.Fatalf("%q: relative %d accepted", s, secs)
		}
		_ = checkPath("path", s)
	})
}
