package setup

import (
	"errors"
)

// KeyType is the only key type a service key may have (D-012).
const KeyType = "ssh-ed25519"

// ErrKey is a refused key file or key line.
var ErrKey = errors.New("key refused")

// PubKey is the server's public key, from its .pub file.
type PubKey struct {
	Base64      string
	Fingerprint string // SHA256:…
	Marshal     []byte // the wire form, to compare with the host's keys
}

// keyTypes are the words that start a key without options (sshd's
// authorized_keys format); anything else at the start of a line is an
// option list.
var keyTypes = []string{
	"ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
}

func isKeyType(w string) bool { var stub0 bool; return stub0 }

// parseKey decodes a key's base64 and requires an Ed25519 key of that type.
func parseKey(typ, b64 string) (*PubKey, error) {
	var stub0 *PubKey
	var stub1 error
	return stub0, stub1
}

// ParsePubFile parses the server's ssh_key.pub: exactly one line, the key
// type first (no options), ssh-ed25519. A private key is refused without
// echoing any of it.
func ParsePubFile(b []byte) (*PubKey, error) { var stub0 *PubKey; var stub1 error; return stub0, stub1 }

// Option is one key-line option: a name, and a value when it has one.
type Option struct {
	Name     string
	Value    string
	HasValue bool
}

// KeyLine is one parsed line of a keys file.
type KeyLine struct {
	Options []Option
	Type    string
	Base64  string
	Comment string
}

// parseOptions reads sshd's option list at the start of s up to the first
// unquoted space: name or name="value", comma-separated, a value quoted
// with \" for a quote inside it. It returns the options and the rest.
func parseOptions(s string) ([]Option, string, error) {
	var stub0 []Option
	var stub1 string
	var stub2 error
	return stub0, stub1, stub2
}

// ParseKeyLine parses one keys-file line (not a comment or a blank line).
func ParseKeyLine(s string) (*KeyLine, error) {
	var stub0 *KeyLine
	var stub1 error
	return stub0, stub1
}

// harmless are the options a line may carry besides restrict, from= and
// command=: each only restricts further what restrict already forbids.
var harmless = []string{"no-agent-forwarding", "no-port-forwarding", "no-pty", "no-user-rc", "no-X11-forwarding", "no-x11-forwarding"}

// ForcedCommand parses a command= value: exactly
// "/usr/local/bin/shell-mcp-gate serve --policy <path> [--principal <label>]"
// with the path and label in the safe character sets. It returns them.
func ForcedCommand(v string) (policy, principal string, err error) {
	var stub0 string
	var stub1 string
	var stub2 error
	return stub0, stub1, stub2
}

// CheckLine applies install's checks to an existing line: restrict, from=
// within the floors, command= exactly the forced command, no option that
// re-enables anything (only the no-* options besides those three), and an
// Ed25519 key. It returns the key.
func CheckLine(kl *KeyLine) (*PubKey, error) { var stub0 *PubKey; var stub1 error; return stub0, stub1 }

// RenderKeyLine is the key line install writes (TARGET-SETUP §7, §12.1).
func RenderKeyLine(from, policy, principal string, k *PubKey) string { var stub0 string; return stub0 }
