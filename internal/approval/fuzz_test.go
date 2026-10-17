package approval

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParseID: ParseID never panics, accepts only 26-character strings of
// the id alphabet, and everything it accepts round-trips through base32 as
// 16 bytes.
func FuzzParseID(f *testing.F) {
	id, _ := NewID()
	for _, s := range []string{id, "", strings.Repeat("a", 26), strings.Repeat("a", 25) + "b", strings.ToUpper(id), id + "a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !ParseID(s) {
			return
		}
		if len(s) != IDLength || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz234567") != "" {
			t.Fatalf("ParseID accepted %q", s)
		}
		raw, err := idEncoding.DecodeString(strings.ToUpper(s))
		if err != nil || len(raw) != 16 || strings.ToLower(idEncoding.EncodeToString(raw)) != s {
			t.Fatalf("accepted id %q does not round-trip (%v)", s, err)
		}
	})
}

// FuzzCanonicalJSON: for any JSON value, the canonical form is valid JSON,
// canonicalising it again changes nothing (round trip), and its hash is
// stable; two inputs that decode to the same value hash the same.
func FuzzCanonicalJSON(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"b":1,"a":2}`, `{"a":{"z":[1,2,{"y":null}],"x":"é"}}`, `[1,"2",true,null]`,
		`{"n":12345678901234567890}`, `{"f":1.5e300}`, `"‮"`, `{"a":"<>&"}`, `{"a":1,"a":2}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if !json.Valid(in) {
			return
		}
		c1, err := CanonicalJSON(json.RawMessage(in))
		if err != nil {
			return
		}
		if !json.Valid(c1) {
			t.Fatalf("canonical form is not JSON: %q", c1)
		}
		c2, err := CanonicalJSON(json.RawMessage(c1))
		if err != nil || !bytes.Equal(c1, c2) {
			t.Fatalf("round trip changed the canonical form: %q -> %q (%v)", c1, c2, err)
		}
		h1, _ := HashOf(json.RawMessage(in))
		h2, _ := HashOf(json.RawMessage(c1))
		if h1 != h2 || h1 != SHA256Hex(c1) {
			t.Fatalf("hash not stable: %s %s", h1, h2)
		}
	})
}
