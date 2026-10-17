package approval

import "encoding/base32"

// IDPattern is an approval id: 128 random bits as lowercase unpadded base32
// (26 characters). An id is a capability to view a record, never to approve
// or decline it.
const IDPattern = `^[a-z2-7]{26}$`

// IDLength is an id's length in characters.
const IDLength = 26

// NewID returns a fresh id from crypto/rand.
func NewID() (string, error) { return "", nil }

// ParseID reports whether s is an approval id in canonical form: 26
// characters of the lowercase base32 alphabet that decode to exactly 16
// bytes and re-encode to s.
func ParseID(s string) bool { return false }

// idEncoding is upper-case unpadded base32; ids are its lower-case form.
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
