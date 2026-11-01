package setupx

import ()

// maxDiffLines bounds each side of a diff; the files the installers own
// are a few dozen lines.
const maxDiffLines = 2000

// diffContext is the unified diff's context lines.
const diffContext = 3

// UnifiedDiff is a unified diff (diff -u) from a (labelled aName) to b
// (bName), or "" when they are equal. Longer inputs than maxDiffLines get a
// one-line summary instead.
func UnifiedDiff(aName, bName string, a, b []byte) string { var stub0 string; return stub0 }

// A hunk: from diffContext lines before this change to diffContext
// lines after the last change within 2*diffContext of the next.

func hunkRange(start, n int) string { var stub0 string; return stub0 }

func splitLines(s string) []string { var stub0 []string; return stub0 }

type editOp struct {
	kind   byte // ' ', '-' or '+'
	ai, bi int  // positions in a and b (the next line of each)
}

// editScript is a shortest edit script from x to y by the longest common
// subsequence (O(len(x)·len(y)), bounded by maxDiffLines).
func editScript(x, y []string) []editOp { var stub0 []editOp; return stub0 }
