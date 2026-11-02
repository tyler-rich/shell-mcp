// Command doccheck: a stub (S8-4's failing-first commit).
package main

import "io/fs"

func main() {}

// check returns one line per link, anchor or section reference in paths
// that does not resolve.
func check(fs.FS, []string) ([]string, error) { return nil, nil }

// slug is GitHub's anchor for a heading.
func slug(string) string { return "" }

// ref is one section reference: the document it names ("" for the one it
// is in) and the section number.
type ref struct {
	doc     string
	section string
}

// refs returns the section references of one line of prose.
func refs(string) []ref { return nil }
