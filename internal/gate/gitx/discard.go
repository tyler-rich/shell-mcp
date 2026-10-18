package gitx

import "strings"

// DiscardEntry is one tracked record of `git status --porcelain=v2 -z
// --no-renames --untracked-files=no` with every field git_discard binds:
// the XY letters, the submodule state, the HEAD, index and work-tree modes
// (six octal digits; 000000 when absent) and the HEAD and index object ids.
// Kind is changed or unmerged.
type DiscardEntry struct {
	Kind         string
	XY           string
	Sub          string
	ModeHead     string
	ModeIndex    string
	ModeWorktree string
	OIDHead      string
	OIDIndex     string
	Path         string
}

// ParseDiscardStatus parses the records of the status command above. Header
// lines ("# ") are ignored; a renamed, untracked or ignored record is an
// error (the command never asks for them), as is any field of the wrong
// shape. At most maxEntries entries are kept and the rest are reported as
// truncated.
func ParseDiscardStatus(b []byte, maxEntries int) (entries []DiscardEntry, truncated bool, err error) {
	return nil, false, bad("discard status: not implemented")
}

// isMode: six octal digits.
func isMode(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return false
		}
	}
	return true
}

// isOID: a full object id, 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
func isOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}
