package approval

// CanonicalJSON returns v's canonical JSON: v marshalled, decoded into
// generic values (numbers kept as their literal text) and marshalled again,
// which sorts every object's keys. Equal values give equal bytes, and the
// canonical form of the canonical form is itself.
func CanonicalJSON(v any) ([]byte, error) { return nil, nil }

// SHA256Hex is the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string { return "" }

// HashOf is SHA256Hex(CanonicalJSON(v)).
func HashOf(v any) (string, error) { return "", nil }

// Field is one key and value of a record's arguments or preview, for the
// approval page. Keys are server-defined paths (path, current.size,
// entries[0].path); values are the data as text, at most MaxFieldBytes.
type Field struct {
	Key   string
	Value string
}

// Fields flattens v's canonical JSON into fields: objects by key (sorted),
// arrays by index, strings as they are, other values as JSON text. A value
// longer than MaxFieldBytes is cut (on a rune boundary) and marked, and at
// most maxTotal bytes of values are kept, then one field says what was left
// out.
func Fields(v any, maxTotal int) ([]Field, error) { return nil, nil }
