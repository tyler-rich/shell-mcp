// Package polkit generates the polkit rule for the gate policy's exact
// unit × verb list (docs/POLICY.md §4b).
package polkit

import "errors"

// Spec is what the rule is generated from.
type Spec struct {
	User         string
	Units        []string
	Verbs        []string
	PolicySHA256 string
}

// Rule is not implemented yet.
func Rule(_ Spec) (string, error) { return "", errors.New("not implemented") }
