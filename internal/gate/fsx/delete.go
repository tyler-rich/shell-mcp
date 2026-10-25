//go:build linux

package fsx

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

const previewFirst = 50

// treeEntry is one entry visited by walkTree: its logical and real paths,
// its name in dir (the verified os.Root of its parent directory), its
// lstat information, and in the helper (Config.GuardMovedIn) the moved
// tree's directories from its top down to dir, each read by statx on the
// descriptor the walk opened (the move rule, move_rule.go).
type treeEntry struct {
	lp, rp, name string
	info         fs.FileInfo
	dir          *os.Root
	tree         []ChainDir
}

// walkTree visits every entry beneath dir (pre-order, not dir itself).
// Every entry's requested and real paths are checked against the deny list
// and the protected set (the walk serves writes), subdirectories are opened
// as verified sub-roots and never through symlinks, and depth is bounded.
// Each directory is read completely before its entries are visited, so a
// visitor may remove entries. tree is the chain of directories down to dir
// (the helper's move rule); in the helper each subdirectory is added to it
// as it is opened, after its mode is checked (moveDirMode).
func (f *FS) walkTree(l *loc, dir *os.Root, logical, dirReal string, depth int, tree []ChainDir, visit func(e *treeEntry) error) error {
	if depth > maxTreeDepth {
		return errf(protocol.CodeTooLarge, "tree is deeper than %d levels", maxTreeDepth)
	}
	ents, err := readAll(dir, f.cfg.Limits.MaxDeleteEntries+1)
	if err != nil {
		return err
	}
	for _, en := range ents {
		name := en.Name()
		lp, rp := join(logical, name), join(dirReal, name)
		if e := f.checkPath(lp, true); e != nil {
			return e
		}
		if e := f.checkPath(rp, true); e != nil {
			return e
		}
		info, err := en.Info()
		if err != nil {
			return mapErr(err)
		}
		if err := visit(&treeEntry{lp: lp, rp: rp, name: name, info: info, dir: dir, tree: tree}); err != nil {
			return err
		}
		if info.IsDir() {
			sub, subReal, _, err := f.openSubdir(l, dir, rp, name)
			if err != nil {
				return err
			}
			subTree := tree
			if f.cfg.GuardMovedIn {
				if subTree, err = f.treeDir(sub, lp, tree); err != nil {
					_ = sub.Close()
					return err
				}
			}
			err = f.walkTree(l, sub, lp, subReal, depth+1, subTree, visit)
			_ = sub.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// readAll reads at most limit entries of dir.
func readAll(dir *os.Root, limit int) ([]fs.DirEntry, error) {
	d, err := dir.Open(".")
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = d.Close() }()
	var out []fs.DirEntry
	for len(out) < limit {
		ents, err := d.ReadDir(min(readDirChunk, limit-len(out)))
		out = append(out, ents...)
		if errors.Is(err, io.EOF) || len(ents) == 0 {
			break
		}
		if err != nil {
			return nil, mapErr(err)
		}
	}
	return out, nil
}
