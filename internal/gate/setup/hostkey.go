//go:build linux

package setup

import (
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// parseAnyKey decodes a host key's base64 (any type x/crypto/ssh parses).
func parseAnyKey(b64 string) (ssh.PublicKey, error) {
	var stub0 ssh.PublicKey
	var stub1 error
	return stub0, stub1
}

func sshFingerprint(k ssh.PublicKey) string { var stub0 string; return stub0 }

// pinVar is the server's host-key variable (ARCHITECTURE §5).
const pinVar = "SHELL_MCP_TARGET_HOST_KEYS"

// printPins prints the host's pins (TARGET-SETUP §12.1 step 9), read from
// its own /etc/ssh/ssh_host_*_key.pub and fingerprinted here, never asked
// of the network: the Ed25519 key as the variable's value, the other keys
// (DSA left out, which the server never accepts) as extra pins.
func printPins(h setupx.Host, r *setupx.Report) error { var stub0 error; return stub0 }

// HostKey is shell-mcp-gate host-key (TARGET-SETUP §12.2): the pin lines
// alone, as any user. It returns the exit code.
func HostKey(h setupx.Host, stdout io.Writer) int { var stub0 int; return stub0 }
