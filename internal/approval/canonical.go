package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tyler-rich/shell-mcp/internal/redact"
)

// CanonicalJSON returns v's canonical JSON: v marshalled, decoded into
// generic values (numbers kept as their literal text) and marshalled again,
// which sorts every object's keys. Equal values give equal bytes, and the
// canonical form of the canonical form is itself.
func CanonicalJSON(v any) ([]byte, error) {
	g, err := generic(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(g)
}

// generic is v as generic JSON values: maps, slices, strings, bools,
// json.Number and nil.
func generic(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var g any
	if err := dec.Decode(&g); err != nil {
		return nil, err
	}
	return g, nil
}

// SHA256Hex is the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// HashOf is SHA256Hex(CanonicalJSON(v)).
func HashOf(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}

// Field is one key and value of a record's arguments or preview, for the
// approval page. Keys are server-defined paths (path, current.size,
// entries[0].path); values are the data as text, at most MaxFieldBytes.
type Field struct {
	Key   string
	Value string
}

// Fields flattens v's canonical JSON into fields: objects by key (sorted),
// arrays by index, strings as they are (each private-key block in one
// only as its size and SHA-256: shown), other values as JSON text. A value
// longer than MaxFieldBytes is cut (on a rune boundary) and marked, and at
// most maxTotal bytes of values are kept, then one field says what was left
// out.
func Fields(v any, maxTotal int) ([]Field, error) {
	g, err := generic(v)
	if err != nil {
		return nil, err
	}
	var all []Field
	flatten("", g, &all)
	out := make([]Field, 0, len(all))
	total := 0
	for i, f := range all {
		f.Value = cutField(f.Value)
		if total+len(f.Value) > maxTotal {
			out = append(out, Field{Key: "…", Value: fmt.Sprintf("%d more fields left out (shown up to %d bytes)", len(all)-i, maxTotal)})
			break
		}
		total += len(f.Value)
		out = append(out, f)
	}
	return out, nil
}

func flatten(key string, v any, out *[]Field) {
	join := func(k string) string {
		if key == "" {
			return k
		}
		return key + "." + k
	}
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			*out = append(*out, Field{Key: orValue(key), Value: "{}"})
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			flatten(join(k), x[k], out)
		}
	case []any:
		if len(x) == 0 {
			*out = append(*out, Field{Key: orValue(key), Value: "[]"})
			return
		}
		for i, e := range x {
			flatten(key+"["+strconv.Itoa(i)+"]", e, out)
		}
	case string:
		*out = append(*out, Field{Key: orValue(key), Value: shown(x)})
	case nil:
		*out = append(*out, Field{Key: orValue(key), Value: "null"})
	default:
		b, _ := json.Marshal(x)
		*out = append(*out, Field{Key: orValue(key), Value: string(b)})
	}
}

// shown is a string value as the approval page shows it (handoff N-5):
// each PEM private-key block (redact.PrivateKeyBlocks: from its BEGIN line
// through the END line of the same label, or to the end of the value when
// there is none) only as that block's size and SHA-256, and everything
// around it as it is, so a key cannot hide the rest of a file from the
// approver. The key has already passed through the client; this keeps it
// off the page and out of the record's fields, while the arguments hash
// (HashOf, over the real value) still binds it.
func shown(s string) string {
	blocks := redact.PrivateKeyBlocks(s)
	if len(blocks) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, r := range blocks {
		block := s[r[0]:r[1]]
		b.WriteString(s[last:r[0]])
		fmt.Fprintf(&b, "private key, not shown: %d bytes, sha256 %s", len(block), SHA256Hex([]byte(block)))
		last = r[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func orValue(k string) string {
	if k == "" {
		return "value"
	}
	return k
}

func cutField(s string) string {
	if len(s) <= MaxFieldBytes {
		return s
	}
	c := s[:MaxFieldBytes]
	for !utf8.ValidString(c) {
		c = c[:len(c)-1]
	}
	return c + fmt.Sprintf(" … (cut; %d bytes in all)", len(s))
}
