//go:build linux

package setup

import (
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// parseAnyKey decodes a host key's base64 (any type x/crypto/ssh parses).
func parseAnyKey(b64 string) (ssh.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(raw)
}

func sshFingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// pinVar is the server's host-key variable (ARCHITECTURE §5).
const pinVar = "SHELL_MCP_TARGET_HOST_KEYS"

// printPins prints the host's pins (TARGET-SETUP §12.1 step 9), read from
// its own /etc/ssh/ssh_host_*_key.pub and fingerprinted here, never asked
// of the network: the Ed25519 key as the variable's value, the other keys
// (DSA left out, which the server never accepts) as extra pins.
func printPins(h setupx.Host, r *setupx.Report) error {
	hks, err := hostKeys(h)
	if err != nil {
		return err
	}
	var primary string
	var others []string
	for _, k := range hks {
		pin := k.typ + " " + k.fingerprint
		switch {
		case k.typ == "ssh-dss":
		case k.typ == ssh.KeyAlgoED25519 && primary == "":
			primary = pin
		default:
			others = append(others, pin)
		}
	}
	slices.Sort(others)
	if primary == "" && len(others) == 0 {
		return ErrNoHostKey
	}
	if primary == "" {
		primary, others = others[0], others[1:]
	}
	_, _ = fmt.Fprintf(r.W, "%s=%s\n", pinVar, primary)
	if len(others) > 0 {
		r.Note("this host's other keys, to add to %s (comma-separated) as extra pins: %s", pinVar, strings.Join(others, ", "))
	}
	r.Note("set the pin on the server from these lines, read over a channel you trust (ARCHITECTURE §5)")
	return nil
}

// HostKey is shell-mcp-gate host-key (TARGET-SETUP §12.2): the pin lines
// alone, as any user. It returns the exit code.
func HostKey(h setupx.Host, stdout io.Writer) int {
	r := &setupx.Report{W: stdout}
	if err := printPins(h, r); err != nil {
		r.Fail("host keys: %v", err)
		return 1
	}
	return 0
}
