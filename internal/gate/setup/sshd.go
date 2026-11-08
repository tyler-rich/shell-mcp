package setup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
func DropIn(user string) []byte {
	var b strings.Builder
	b.WriteString("Match User " + user + "\n")
	for _, d := range matchBlock {
		b.WriteString("    " + d.directive + " " + d.value + "\n")
	}
	return []byte(b.String())
}

// DropInFor is the drop-in for several accounts, in their order: each
// account's DropIn block, with one empty line between two blocks
// (TARGET-SETUP §7, "With a second account").
func DropInFor(users []string) []byte {
	var b []byte
	for i, u := range users {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, DropIn(u)...)
	}
	return b
}

// ErrDropInForeign is a drop-in that holds a block install does not write
// (refused as dropin_other_account); ErrDropInEdited is one whose blocks
// are install's but whose bytes differ (refused as file_differs).
var (
	ErrDropInForeign = errors.New("the drop-in holds a block install did not write")
	ErrDropInEdited  = errors.New("the drop-in's content was edited")
)

// ParseDropIn reads an existing drop-in as install writes it and returns
// its accounts in order. Not implemented yet.
func ParseDropIn(b []byte) ([]string, error) {
	return nil, fmt.Errorf("%w: not implemented", ErrDropInEdited)
}

// dropInUser is the account an existing drop-in's first line names, or "".
func dropInUser(b []byte) string {
	first, _, _ := strings.Cut(string(b), "\n")
	if f := strings.Fields(first); len(f) == 3 && f[0] == "Match" && f[1] == "User" {
		return f[2]
	}
	return ""
}

// maxSshdT bounds sshd -T's output (it is about 10 KiB).
const maxSshdT = 1 << 20

// ErrSshdT is output of sshd -T that is not its key-value form.
var ErrSshdT = errors.New("malformed sshd -T output")

// ParseSshdT parses sshd -T's output: one "keyword value…" line each,
// keywords in lowercase; a keyword may repeat (hostkey, listenaddress).
func ParseSshdT(b []byte) (map[string][]string, error) {
	if len(b) > maxSshdT || len(b) == 0 {
		return nil, ErrSshdT
	}
	out := map[string][]string{}
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		k, v, ok := strings.Cut(l, " ")
		if !ok || k == "" || strings.ToLower(k) != k || strings.ContainsAny(k, "\t\r\x00") {
			return nil, fmt.Errorf("%w: line %.60q", ErrSshdT, l)
		}
		out[k] = append(out[k], v)
	}
	return out, nil
}

// blockMismatch compares sshd -T -C output for the account with the block,
// and names every value that differs.
func blockMismatch(got map[string][]string) []string {
	var bad []string
	for _, d := range matchBlock {
		if v := got[d.key]; len(v) != 1 || v[0] != d.value {
			bad = append(bad, fmt.Sprintf("%s is %q, want %q", d.key, strings.Join(v, " | "), d.value))
		}
	}
	return bad
}

// SliceDropIn is the account slice's drop-in (TARGET-SETUP §4).
func SliceDropIn(size string) []byte {
	return []byte("[Slice]\nMemoryMax=" + size + "\nMemorySwapMax=0\n")
}

// ErrSize is a malformed --memory-max.
var ErrSize = errors.New("malformed size")

// ParseSize parses --memory-max: digits and the suffix M or G (MiB, GiB),
// at least 64M and at most 1048576G. It returns the bytes and the text
// written into MemoryMax=.
func ParseSize(s string) (n uint64, text string, err error) {
	if len(s) < 2 || len(s) > 12 {
		return 0, "", fmt.Errorf("%w: %q (want <n>M or <n>G)", ErrSize, s)
	}
	v, err := ParseID(s[:len(s)-1])
	if err != nil {
		return 0, "", fmt.Errorf("%w: %q (want <n>M or <n>G)", ErrSize, s)
	}
	var mib uint64
	switch s[len(s)-1] {
	case 'M':
		mib = uint64(v)
	case 'G':
		mib = uint64(v) << 10
	default:
		return 0, "", fmt.Errorf("%w: %q (want <n>M or <n>G)", ErrSize, s)
	}
	if mib < 64 || mib > 1<<30 {
		return 0, "", fmt.Errorf("%w: %q is outside 64M to 1048576G", ErrSize, s)
	}
	return mib << 20, s, nil
}

// DefaultSize is the slice's default MemoryMax=: 4 × the policy's
// limits.max_memory_mb, in G when it is a whole number of GiB (4G at the
// default 1024, as TARGET-SETUP §4 writes it).
func DefaultSize(maxMemoryMB int) string {
	mib := 4 * maxMemoryMB
	if mib%1024 == 0 {
		return strconv.Itoa(mib/1024) + "G"
	}
	return strconv.Itoa(mib) + "M"
}
