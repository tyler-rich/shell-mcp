//go:build linux

package fsx

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

const previewFirst = 50

// treeEntry is one entry visited by walkTree: its logical and real paths,
// its name in dir (the verified os.Root of its parent directory), and its
// lstat information.
type treeEntry struct {
	lp, rp, name string
	info         fs.FileInfo
	dir          *os.Root
}

// walkTree visits every entry beneath dir (pre-order, not dir itself).
// Every entry's requested and real paths are checked against the deny list
// and the protected set (the walk serves writes), subdirectories are opened
// as verified sub-roots and never through symlinks, and depth is bounded.
// Each directory is read completely before its entries are visited, so a
// visitor may remove entries.
func (f *FS) walkTree(l *loc, dir *os.Root, logical, dirReal string, depth int, visit func(e *treeEntry) error) error {
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
		if err := visit(&treeEntry{lp: lp, rp: rp, name: name, info: info, dir: dir}); err != nil {
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
			if f.cfg.Backup != nil {
				if !fi.Mode().IsRegular() {
					return res, errf(protocol.CodeBackupFailed, "only regular files and directories can be backed up; nothing was deleted")
				}
				backedUp, berr := f.backupFile(l)
				if berr != nil {
					return res, berr
				}
				if e := unchangedSince(l.parent, l.base, backedUp); e != nil {
					return res, e
				}
			}
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
	err = f.walkTree(l, sub, p, subReal, 1, func(e *treeEntry) error {
		if !recursive {
			return errf(protocol.CodeBadRequest, "directory is not empty; set recursive to delete it")
		}
		res.Entries++
		if res.Entries > limit {
			return errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) entries", limit)
		}
		if e.info.Mode().IsRegular() {
			res.Bytes += e.info.Size()
		}
		if len(res.First) < previewFirst {
			res.First = append(res.First, e.lp)
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	if !apply {
		return res, nil
	}
	var backedUp map[fileKey]bool
	if f.cfg.Backup != nil {
		if backedUp, err = f.backupTree(l, sub, subReal, fi); err != nil {
			return res, err
		}
	}
	removed := 0
	if err := f.removeTree(l, sub, p, subReal, 1, &removed, backedUp); err != nil {
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
// are unlinked, never followed. With backedUp set (the helper), an entry
// the backup did not see stops the removal: nothing is removed without a
// backup.
func (f *FS) removeTree(l *loc, dir *os.Root, logical, dirReal string, depth int, removed *int, backedUp map[fileKey]bool) error {
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
		if backedUp != nil {
			info, err := en.Info()
			if err != nil {
				return mapErr(err)
			}
			if !backedUp[keyOf(info)] {
				return errf(protocol.CodeBackupFailed, "the tree changed after it was backed up; deletion stopped before removing anything that was not backed up")
			}
		}
		if en.Type().IsDir() {
			sub, subReal, _, err := f.openSubdir(l, dir, rp, name)
			if err != nil {
				return err
			}
			err = f.removeTree(l, sub, lp, subReal, depth+1, removed, backedUp)
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

// backupTree hands the tree to the backup hook and returns the entries it
// was shown. Only regular files and directories can be backed up.
func (f *FS) backupTree(l *loc, sub *os.Root, subReal string, fi fs.FileInfo) (map[fileKey]bool, error) {
	seen := map[fileKey]bool{}
	walk := func(visit func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error) error {
		return f.walkTree(l, sub, l.p, subReal, 1, func(e *treeEntry) error {
			if !e.info.Mode().IsRegular() && !e.info.IsDir() {
				return errf(protocol.CodeBackupFailed, "the tree holds a symlink or special file, which cannot be backed up; nothing was deleted")
			}
			seen[keyOf(e.info)] = true
			return visit(pathx.Rel(l.p, e.lp), e.info, func() (*os.File, error) { return f.openEntry(l, e) })
		})
	}
	if err := f.cfg.Backup(&BackupSource{Path: l.p, Kind: BackupTree, Info: fi, Walk: walk}); err != nil {
		return nil, backupErr(err)
	}
	return seen, nil
}
