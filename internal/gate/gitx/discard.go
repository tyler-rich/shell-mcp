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
	entries = []DiscardEntry{}
	if len(b) == 0 {
		return entries, false, nil
	}
	if b[len(b)-1] != 0 {
		return nil, false, bad("discard status: missing terminator")
	}
	recs := strings.Split(string(b[:len(b)-1]), "\x00")
	if len(recs) > maxRecords {
		return nil, false, bad("discard status: too many records")
	}
	for _, r := range recs {
		if len(r) > maxField {
			return nil, false, bad("discard status: record too long")
		}
		if strings.HasPrefix(r, "# ") {
			continue
		}
		var e DiscardEntry
		switch {
		case strings.HasPrefix(r, "1 "):
			// 1 XY sub mH mI mW hH hI path
			f := strings.SplitN(r, " ", 9)
			if len(f) != 9 || !isMode(f[3]) || !isMode(f[4]) || !isMode(f[5]) || !isOID(f[6]) || !isOID(f[7]) {
				return nil, false, bad("discard status: changed entry")
			}
			e = DiscardEntry{Kind: "changed", XY: f[1], Sub: f[2], ModeHead: f[3], ModeIndex: f[4], ModeWorktree: f[5],
				OIDHead: f[6], OIDIndex: f[7], Path: f[8]}
		case strings.HasPrefix(r, "u "):
			// u XY sub m1 m2 m3 mW h1 h2 h3 path: refused by the caller; only
			// its path and work-tree mode are kept.
			f := strings.SplitN(r, " ", 11)
			if len(f) != 11 || !isMode(f[3]) || !isMode(f[4]) || !isMode(f[5]) || !isMode(f[6]) || !isOID(f[7]) || !isOID(f[8]) || !isOID(f[9]) {
				return nil, false, bad("discard status: unmerged entry")
			}
			e = DiscardEntry{Kind: "unmerged", XY: f[1], Sub: f[2], ModeWorktree: f[6], Path: f[10]}
		default:
			// Renames (--no-renames), untracked and ignored entries are never
			// asked for.
			return nil, false, bad("discard status: unexpected record")
		}
		if len(e.XY) != 2 || len(e.Sub) != 4 || e.Path == "" {
			return nil, false, bad("discard status: entry fields")
		}
		if len(entries) == maxEntries {
			truncated = true
			continue
		}
		entries = append(entries, e)
	}
	return entries, truncated, nil
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
