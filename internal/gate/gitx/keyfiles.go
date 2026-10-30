package gitx

import (
	"bytes"
	"errors"
)

// ErrNames is a NUL-separated name list that is not one.
var ErrNames = errors.New("unexpected name list")

// ParseNames parses NUL-terminated path names, as `git diff --name-only
// -z` and `git grep -l -z` print them, each with prefix (`git grep` on a
// tree prints "<tree>:" before each name; "" for none) removed. An empty
// name, a name without prefix, or text after the last NUL is ErrNames.
func ParseNames(out []byte, prefix string) ([]string, error) {
	if len(out) == 0 {
		return nil, nil
	}
	if out[len(out)-1] != 0 {
		return nil, ErrNames
	}
	var names []string
	for _, n := range bytes.Split(out[:len(out)-1], []byte{0}) {
		if !bytes.HasPrefix(n, []byte(prefix)) || len(n) == len(prefix) {
			return nil, ErrNames
		}
		names = append(names, string(n[len(prefix):]))
	}
	return names, nil
}
