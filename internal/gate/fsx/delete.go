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

// walkTree visits every entry beneath dir (pre-order, not dir itself).
// Every entry's requested and real paths are checked against the deny list
// and the protected set (the walk serves writes), subdirectories are opened
// as verified sub-roots and never through symlinks, and depth is bounded.
// Each directory is read completely before its entries are visited, so a
// visitor may remove entries.
func (f *FS) walkTree(l *loc, dir *os.Root, logical, dirReal string, depth int, visit func(lp string, fi fs.FileInfo) error) error {
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
		if err := visit(lp, info); err != nil {
			return err
		}
		if info.IsDir() {
			sub, subReal, _, err := f.openSubdir(l, dir, rp, name)
			if err != nil {
				return err
			}
			err = f.walkTree(l, sub, lp, subReal, depth+1, visit)
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

// Delete removes p under a write root (recursively only if recursive).
func (f *FS) Delete(p string, recursive bool) (DeleteResult, error) {
	return f.deleteOp(p, recursive, true)
}

// DeletePreview reports what Delete would remove, removing nothing.
func (f *FS) DeletePreview(p string, recursive bool) (DeleteResult, error) {
	return f.deleteOp(p, recursive, false)
}

func (f *FS) deleteOp(p string, recursive, apply bool) (DeleteResult, error) {
	res := DeleteResult{Path: p, First: []string{}}
	l, err := f.locate(p, true)
	if err != nil {
		return res, err
	}
	defer l.close()
	if l.parent == nil {
		return res, errf(protocol.CodePathDenied, "a root cannot be deleted")
	}
	fi, err := l.parent.Lstat(l.base)
	if err != nil {
		return res, mapErr(err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return res, errf(protocol.CodePathDenied, "final path component is a symlink")
	}
	res.Type = typeOf(fi.Mode())
	res.Entries = 1
	res.First = append(res.First, p)
	if !fi.IsDir() {
		if fi.Mode().IsRegular() {
			res.Bytes = fi.Size()
		}
		if apply {
			if err = l.parent.Remove(l.base); err != nil {
				return res, mapErr(err)
			}
			res.Deleted = true
		}
		return res, nil
	}

	sub, subReal, _, err := f.openSubdir(l, l.parent, l.targetReal(), l.base)
	if err != nil {
		return res, err
	}
	defer func() { _ = sub.Close() }()
	limit := f.cfg.Limits.MaxDeleteEntries
	err = f.walkTree(l, sub, p, subReal, 1, func(lp string, info fs.FileInfo) error {
		if !recursive {
			return errf(protocol.CodeBadRequest, "directory is not empty; set recursive to delete it")
		}
		res.Entries++
		if res.Entries > limit {
			return errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) entries", limit)
		}
		if info.Mode().IsRegular() {
			res.Bytes += info.Size()
		}
		if len(res.First) < previewFirst {
			res.First = append(res.First, lp)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	if !apply {
		return res, nil
	}
	removed := 0
	if err := f.removeTree(l, sub, p, subReal, 1, &removed); err != nil {
		return res, err
	}
	if err := l.parent.Remove(l.base); err != nil {
		return res, mapErr(err)
	}
	res.Deleted = true
	return res, nil
}

// removeTree empties dir bottom-up, re-checking every entry and bounding the
// count again (the tree may have changed since the preview walk). Symlinks
// are unlinked, never followed.
func (f *FS) removeTree(l *loc, dir *os.Root, logical, dirReal string, depth int, removed *int) error {
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
		*removed++
		if *removed > f.cfg.Limits.MaxDeleteEntries {
			return errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) entries", f.cfg.Limits.MaxDeleteEntries)
		}
		if en.Type().IsDir() {
			sub, subReal, _, err := f.openSubdir(l, dir, rp, name)
			if err != nil {
				return err
			}
			err = f.removeTree(l, sub, lp, subReal, depth+1, removed)
			_ = sub.Close()
			if err != nil {
				return err
			}
		}
		if err := dir.Remove(name); err != nil {
			return mapErr(err)
		}
	}
	return nil
}
