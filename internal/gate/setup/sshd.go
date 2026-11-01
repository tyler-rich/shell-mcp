package setup

import (
	"errors"
)

// matchBlock is TARGET-SETUP §7's Match block, in its order: the
// directive as written, the key and value sshd -T -C prints for it.
var matchBlock = []struct{ directive, key, value string }{
	{"AuthorizedKeysFile", "authorizedkeysfile", KeysDir + "/%u"},
	{"AuthenticationMethods", "authenticationmethods", "publickey"},
	{"PasswordAuthentication", "passwordauthentication", "no"},
	{"KbdInteractiveAuthentication", "kbdinteractiveauthentication", "no"},
	{"PermitTTY", "permittty", "no"},
	{"AllowTcpForwarding", "allowtcpforwarding", "no"},
	{"AllowStreamLocalForwarding", "allowstreamlocalforwarding", "no"},
	{"AllowAgentForwarding", "allowagentforwarding", "no"},
	{"X11Forwarding", "x11forwarding", "no"},
	{"PermitTunnel", "permittunnel", "no"},
	{"PermitUserRC", "permituserrc", "no"},
	{"MaxSessions", "maxsessions", "8"},
}

// DropIn is /etc/ssh/sshd_config.d/60-shell-mcp.conf for user, exactly
// TARGET-SETUP §7's block.
func DropIn(user string) []byte { var stub0 []byte; return stub0 }

// dropInUser is the account an existing drop-in's first line names, or "".
func dropInUser(b []byte) string { var stub0 string; return stub0 }

// maxSshdT bounds sshd -T's output (it is about 10 KiB).
const maxSshdT = 1 << 20

// ErrSshdT is output of sshd -T that is not its key-value form.
var ErrSshdT = errors.New("malformed sshd -T output")

// ParseSshdT parses sshd -T's output: one "keyword value…" line each,
// keywords in lowercase; a keyword may repeat (hostkey, listenaddress).
func ParseSshdT(b []byte) (map[string][]string, error) {
	var stub0 map[string][]string
	var stub1 error
	return stub0, stub1
}

// blockMismatch compares sshd -T -C output for the account with the block,
// and names every value that differs.
func blockMismatch(got map[string][]string) []string { var stub0 []string; return stub0 }

// SliceDropIn is the account slice's drop-in (TARGET-SETUP §4).
func SliceDropIn(size string) []byte { var stub0 []byte; return stub0 }

// ErrSize is a malformed --memory-max.
var ErrSize = errors.New("malformed size")

// ParseSize parses --memory-max: digits and the suffix M or G (MiB, GiB),
// at least 64M and at most 1048576G. It returns the bytes and the text
// written into MemoryMax=.
func ParseSize(s string) (n uint64, text string, err error) {
	var stub0 uint64
	var stub1 string
	var stub2 error
	return stub0, stub1, stub2
}

// DefaultSize is the slice's default MemoryMax=: 4 × the policy's
// limits.max_memory_mb, in G when it is a whole number of GiB (4G at the
// default 1024, as TARGET-SETUP §4 writes it).
func DefaultSize(maxMemoryMB int) string { var stub0 string; return stub0 }
