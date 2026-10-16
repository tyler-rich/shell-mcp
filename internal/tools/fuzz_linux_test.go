//go:build linux

package tools

import (
	"errors"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// FuzzModeAgreesWithGate: the server's mode check accepts exactly the
// strings the gate can parse as a mode, so its early rejection never
// refuses what the gate would accept. Which bits are allowed stays the
// gate's rule: a mode the gate parses but refuses (setuid, world-write)
// passes the server and is refused with policy_denied there.
func FuzzModeAgreesWithGate(f *testing.F) {
	for _, s := range []string{"0640", "640", "755", "0755", "4755", "2755", "1777", "0666", "0777", "7777", "60", "06440",
		"0x1a4", "rw-r--r--", "644 ", " 644", "0o644", "8", "0888", "", "-644", "+644", "06\x0040"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		serverOK := checkMode("mode", s, true) == nil
		_, err := fsx.ParseMode(s)
		var fe *fsx.Error
		gateParses := err == nil || (errors.As(err, &fe) && fe.Code == protocol.CodePolicyDenied)
		if serverOK != gateParses {
			t.Fatalf("%q: server accepts %v, gate parses %v (%v)", s, serverOK, gateParses, err)
		}
	})
}
