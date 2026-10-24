//go:build linux

package fsx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// TestMoveTreeHoldingLeftEntries (handoff N-21): a move of a tree that
// holds an entry a delete set aside (.shell-mcp-delete-) or a stopped move
// left (.shell-mcp-move-), at any depth, is refused in the gate and in the
// helper, naming that entry, before anything is moved: otherwise the entry
// moves with its tree and the path its refusal named goes stale. Layouts
// are invented.
func TestMoveTreeHoldingLeftEntries(t *testing.T) {
	for _, prefix := range []string{".shell-mcp-delete-", ".shell-mcp-move-"} {
		for _, depth := range []string{"top", "nested"} {
			for _, helper := range []bool{false, true} {
				name := strings.Trim(prefix, ".-") + "/" + depth + "/gate"
				if helper {
					name = strings.TrimSuffix(name, "gate") + "helper"
				}
				t.Run(name, func(t *testing.T) {
					e := newMovedEnv(t, true)
					fs := e.newFS(t, e.root, true, helper)
					tree := filepath.Join(e.root, "tree")
					mkdirMode(t, filepath.Join(tree, "inner"), 0o755)
					mkdirMode(t, tree, 0o755)
					putMode(t, filepath.Join(tree, "inner", "keep.conf"), "keep\n", 0o640)
					dir := tree
					if depth == "nested" {
						dir = filepath.Join(tree, "inner")
					}
					left := filepath.Join(dir, prefix+"0123456789abcdef0123456789abcdef")
					putMode(t, left, "left\n", 0o640)
					dst := filepath.Join(e.root, "moved")
					_, err := fs.Move(tree, dst, false)
					wantCode(t, err, protocol.CodePathDenied)
					var fe *Error
					if !asError(err, &fe) || !strings.Contains(fe.Msg, left) || !strings.Contains(fe.Msg, "nothing was moved") || !fe.Unchanged {
						t.Fatalf("the refusal does not name %s, or says something changed: %+v", left, err)
					}
					gone(t, dst)
					if read(t, left) != "left\n" || read(t, filepath.Join(tree, "inner", "keep.conf")) != "keep\n" {
						t.Fatal("the tree changed")
					}
					if ents, rerr := os.ReadDir(e.root); rerr != nil || len(ents) != 1 {
						t.Fatalf("the root holds %v (%v), want the tree alone", ents, rerr)
					}
				})
			}
		}
	}
}
