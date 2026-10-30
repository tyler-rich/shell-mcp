package policy

import (
	"fmt"
	"slices"
)

// Range and filter programs (handoff N-35, POLICY §4): a command that
// declares reads_private_keys may read a file holding a private key, and
// one of these programs can print a range or a filtered part of it (lines,
// bytes, columns, matches, reordered, reversed, re-wrapped or re-encoded)
// without the BEGIN line that output redaction needs. check-policy warns
// about such a command, by the name written, the name resolved and binary
// identity, as the GTFOBins warning matches (POLICY §6). This project's
// own list.
var rangePrograms = []string{
	"awk", "base32", "base64", "basenc", "comm", "csplit", "cut", "dd", "egrep", "fgrep", "fold", "gawk",
	"grep", "head", "hexdump", "join", "mawk", "nawk", "od", "rev", "sed", "shuf", "sort", "split",
	"strings", "tac", "tail", "tr", "xxd",
}

// RangeProgramNames returns the range and filter programs, sorted.
func RangeProgramNames() []string { return slices.Clone(rangePrograms) }

func isRangeProgram(n string) bool { return slices.Contains(rangePrograms, n) }

// KeyRangeWarnings is check-policy's warnings for the command at field
// that declares reads_private_keys and whose binary (written at written,
// resolved to resolved, identity matches ident) is a range or filter
// program: one per program it is, naming it and how it matched. asRoot says
// the command runs as root.
func KeyRangeWarnings(field string, asRoot bool, written, resolved string, ident []ListedMatch) []string {
	who := ""
	if asRoot {
		who = ", and it runs as root"
	}
	var out []string
	for _, m := range matchesOf(written, resolved, ident, isRangeProgram) {
		out = append(out, fmt.Sprintf("%s: reads_private_keys is set, and %s prints ranges or filtered parts of its input%s: it can show a private key's body "+
			"without the BEGIN line that output redaction needs, which then only the width heuristic masks; declare reads_private_keys only for "+
			"a program that never prints part of its input (POLICY §4)%s", field, m.Name, who, m.suffix()))
	}
	return out
}
