package approval

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// IDPattern is an approval id: 128 random bits as lowercase unpadded base32
// (26 characters). An id is a capability to view a record, never to approve
// or decline it.
const IDPattern = `^[a-z2-7]{26}$`

// IDLength is an id's length in characters.
const IDLength = 26

// idBytes is an id's entropy: 128 bits.
const idBytes = 16

// idEncoding is upper-case unpadded base32; ids are its lower-case form.
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewID returns a fresh id from crypto/rand.
func NewID() (string, error) {
	return randomToken()
}

// randomToken is 128 random bits as lowercase unpadded base32: ids and
// CSRF tokens.
func randomToken() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(idEncoding.EncodeToString(b)), nil
}

// ParseID reports whether s is an approval id in canonical form: 26
// characters of the lowercase base32 alphabet that decode to exactly 16
// bytes and re-encode to s.
func ParseID(s string) bool {
	if len(s) != IDLength {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	raw, err := idEncoding.DecodeString(strings.ToUpper(s))
	return err == nil && len(raw) == idBytes && strings.ToLower(idEncoding.EncodeToString(raw)) == s
}
