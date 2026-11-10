package setup

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
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

func isKeyType(w string) bool {
	return slices.Contains(keyTypes, w) || strings.HasSuffix(w, "-cert-v01@openssh.com")
}

// parseKey decodes a key's base64 and requires an Ed25519 key of that type.
func parseKey(typ, b64 string) (*PubKey, error) {
	if typ != KeyType {
		return nil, fmt.Errorf("%w: a %s key; the service key must be %s (D-012)", ErrKey, typ, KeyType)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: the key's base64 does not decode", ErrKey)
	}
	k, err := ssh.ParsePublicKey(raw)
	if err != nil || k.Type() != KeyType {
		return nil, fmt.Errorf("%w: the key does not parse as %s", ErrKey, KeyType)
	}
	return &PubKey{Base64: b64, Fingerprint: ssh.FingerprintSHA256(k), Marshal: k.Marshal()}, nil
}

// ParsePubFile parses the server's ssh_key.pub: exactly one line, the key
// type first (no options), ssh-ed25519. A private key is refused without
// echoing any of it.
func ParsePubFile(b []byte) (*PubKey, error) {
	if bytes.Contains(b, []byte("PRIVATE KEY")) || bytes.Contains(b, []byte("-----BEGIN")) {
		return nil, fmt.Errorf("%w: this is a private key; give the public key file (ssh_key.pub), and keep the private key on the server", ErrKey)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" || strings.ContainsAny(s, "\n\r") {
		return nil, fmt.Errorf("%w: the key file must hold exactly one line", ErrKey)
	}
	f := strings.Fields(s)
	if len(f) < 2 {
		return nil, fmt.Errorf("%w: the key file's line has no key", ErrKey)
	}
	if !isKeyType(f[0]) {
		return nil, fmt.Errorf("%w: the key file's line starts with options; give the plain ssh_key.pub line", ErrKey)
	}
	return parseKey(f[0], f[1])
}

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
	var opts []Option
	i := 0
	for {
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ',' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		o := Option{Name: s[start:i]}
		if o.Name == "" {
			return nil, "", fmt.Errorf("%w: an empty option", ErrKey)
		}
		if i < len(s) && s[i] == '=' {
			i++
			if i >= len(s) || s[i] != '"' {
				return nil, "", fmt.Errorf("%w: option %s has an unquoted value", ErrKey, o.Name)
			}
			i++
			var v strings.Builder
			for {
				if i >= len(s) {
					return nil, "", fmt.Errorf("%w: option %s's value has no closing quote", ErrKey, o.Name)
				}
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					v.WriteByte('"')
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				v.WriteByte(s[i])
				i++
			}
			o.Value, o.HasValue = v.String(), true
		}
		opts = append(opts, o)
		if i >= len(s) {
			return nil, "", fmt.Errorf("%w: no key after the options", ErrKey)
		}
		switch s[i] {
		case ',':
			i++
		case ' ', '\t':
			return opts, strings.TrimLeft(s[i:], " \t"), nil
		default:
			return nil, "", fmt.Errorf("%w: option %s is followed by %q", ErrKey, o.Name, s[i])
		}
	}
}

// ParseKeyLine parses one keys-file line (not a comment or a blank line).
func ParseKeyLine(s string) (*KeyLine, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return nil, fmt.Errorf("%w: the line holds a control character", ErrKey)
	}
	s = strings.TrimLeft(s, " \t")
	kl := &KeyLine{}
	rest := s
	if f := strings.Fields(s); len(f) == 0 || !isKeyType(f[0]) {
		opts, r, err := parseOptions(s)
		if err != nil {
			return nil, err
		}
		kl.Options, rest = opts, r
	}
	f := strings.Fields(rest)
	if len(f) < 2 || !isKeyType(f[0]) {
		return nil, fmt.Errorf("%w: no key type and key after the options", ErrKey)
	}
	kl.Type, kl.Base64 = f[0], f[1]
	kl.Comment = strings.Join(f[2:], " ")
	return kl, nil
}

// harmless are the options a line may carry besides restrict, from= and
// command=: each only restricts further what restrict already forbids.
var harmless = []string{"no-agent-forwarding", "no-port-forwarding", "no-pty", "no-user-rc", "no-X11-forwarding", "no-x11-forwarding"}

// ForcedCommand parses a command= value: exactly
// "/usr/local/bin/shell-mcp-gate serve --policy <path> [--principal <label>]"
// with the path and label in the safe character sets. It returns them.
func ForcedCommand(v string) (policy, principal string, err error) {
	f := strings.Split(v, " ")
	switch {
	case len(f) == 4 && f[0] == GatePath && f[1] == "serve" && f[2] == "--policy":
	case len(f) == 6 && f[0] == GatePath && f[1] == "serve" && f[2] == "--policy" && f[4] == "--principal":
		principal = f[5]
		if !ValidPrincipal(principal) {
			return "", "", fmt.Errorf("%w: command= names the principal %q, outside ^[a-z][a-z0-9-]{0,31}$", ErrKey, principal)
		}
	default:
		return "", "", fmt.Errorf("%w: command= is not exactly %s serve --policy <file> [--principal <label>]", ErrKey, GatePath)
	}
	if err := CheckSafePath("command='s --policy", f[3]); err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrKey, err)
	}
	return f[3], principal, nil
}

// CheckLine applies install's checks to an existing line: restrict, from=
// within the floors, command= exactly the forced command, no option that
// re-enables anything (only the no-* options besides those three), and an
// Ed25519 key. It returns the key.
func CheckLine(kl *KeyLine) (*PubKey, error) {
	var restrict, from, command int
	for _, o := range kl.Options {
		switch {
		case o.Name == "restrict" && !o.HasValue:
			restrict++
		case o.Name == "from" && o.HasValue:
			from++
			if _, _, err := ParseFrom(strings.Split(o.Value, ",")); err != nil {
				return nil, fmt.Errorf("%w: from=: %w", ErrKey, err)
			}
		case o.Name == "command" && o.HasValue:
			command++
			if _, _, err := ForcedCommand(o.Value); err != nil {
				return nil, err
			}
		case slices.Contains(harmless, o.Name) && !o.HasValue:
		default:
			return nil, fmt.Errorf("%w: option %s is not one install allows (restrict, from=, command= and the no-* restrictions)", ErrKey, o.Name)
		}
	}
	switch {
	case restrict != 1:
		return nil, fmt.Errorf("%w: the line has no restrict option", ErrKey)
	case from != 1:
		return nil, fmt.Errorf("%w: the line has no from= option (or more than one)", ErrKey)
	case command != 1:
		return nil, fmt.Errorf("%w: the line has no command= option (or more than one)", ErrKey)
	}
	return parseKey(kl.Type, kl.Base64)
}

// RenderKeyLine is the key line install writes (TARGET-SETUP §7, §12.1).
func RenderKeyLine(from, policy, principal string, k *PubKey) string {
	return `restrict,from="` + from + `",command="` + GatePath + ` serve --policy ` + policy + ` --principal ` + principal + `" ` +
		KeyType + " " + k.Base64 + " shell-mcp-" + principal
}
