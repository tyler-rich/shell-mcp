package setupx

import (
	"bytes"
	"fmt"
	"strings"
)

// maxDiffLines bounds each side of a diff; the files the installers own
// are a few dozen lines.
const maxDiffLines = 2000

// diffContext is the unified diff's context lines.
const diffContext = 3

// UnifiedDiff is a unified diff (diff -u) from a (labelled aName) to b
// (bName), or "" when they are equal. Longer inputs than maxDiffLines get a
// one-line summary instead.
func UnifiedDiff(aName, bName string, a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	x, y := splitLines(string(a)), splitLines(string(b))
	if len(x) > maxDiffLines || len(y) > maxDiffLines {
		return fmt.Sprintf("--- %s\n+++ %s\n(the files differ; too long to show: %d and %d lines)\n", aName, bName, len(x), len(y))
	}
	ops := editScript(x, y)
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", aName, bName)
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// A hunk: from diffContext lines before this change to diffContext
		// lines after the last change within 2*diffContext of the next.
		start := max(0, i-diffContext)
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*diffContext {
				end = min(len(ops), end+diffContext)
				break
			}
			end = run
		}
		ax, ay := ops[start].ai, ops[start].bi
		var nx, ny int
		var body strings.Builder
		for _, o := range ops[start:end] {
			switch o.kind {
			case ' ':
				nx++
				ny++
				body.WriteString(" " + x[o.ai] + "\n")
			case '-':
				nx++
				body.WriteString("-" + x[o.ai] + "\n")
			case '+':
				ny++
				body.WriteString("+" + y[o.bi] + "\n")
			}
		}
		fmt.Fprintf(&out, "@@ -%s +%s @@\n%s", hunkRange(ax, nx), hunkRange(ay, ny), body.String())
		i = end
	}
	return out.String()
}

func hunkRange(start, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", start)
	}
	if n == 1 {
		return fmt.Sprintf("%d", start+1)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

type editOp struct {
	kind   byte // ' ', '-' or '+'
	ai, bi int  // positions in a and b (the next line of each)
}

// editScript is a shortest edit script from x to y by the longest common
// subsequence (O(len(x)·len(y)), bounded by maxDiffLines).
func editScript(x, y []string) []editOp {
	n, m := len(x), len(y)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []editOp
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, editOp{' ', i, j})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, editOp{'-', i, j})
			i++
		default:
			ops = append(ops, editOp{'+', i, j})
			j++
		}
	}
	return ops
}
