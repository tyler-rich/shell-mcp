//go:build linux

package fsx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// What the privileged helper adds to fsx (PRIVILEGED §6): an explicit owner
// on writes and mkdir, the bound chown and chmod (meta_exact.go), and a backup hook called before every
// overwrite, move-over and delete. The gate sets none of them, so its
// behaviour is unchanged.

// Owner is a file owner to set; a nil id is left as it is (or, for a new
// file or directory, as the process creates it).
type Owner struct {
	UID, GID *uint32
}

// ChownResult is the helper's priv_chown result (the target's owner and
// group before and after).
type ChownResult struct {
	Path   string `json:"path"`
	OldUID uint32 `json:"old_uid"`
	OldGID uint32 `json:"old_gid"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

// Backup kinds.
const (
	BackupFile = "file"
	BackupTree = "tree"
)

// BackupSource describes what a destructive operation is about to replace
// or remove. Everything in it was opened and verified by fsx: the hook
// reads through these descriptors, never by path.
type BackupSource struct {
	// Path is the logical path as requested.
	Path string
	// Kind is BackupFile or BackupTree.
	Kind string
	// Info describes the file, or the tree's root directory.
	Info fs.FileInfo
	// File is the open target (BackupFile); fsx closes it.
	File *os.File
	// SHA256, when set, is the SHA-256 fsx computed of File's content just
	// before: the backup must hold exactly that content, or fail.
	SHA256 string
	// Walk visits every entry beneath the tree root in pre-order
	// (BackupTree): rel is relative to the root, open opens a regular file
	// through a verified descriptor. Only regular files and directories
	// occur; anything else fails the walk.
	Walk func(visit func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error) error
	// List visits the same entries as Walk, in the same order, from the
	// delete's plan without opening anything (BackupTree; sizing the
	// backup before it is written).
	List func(visit func(rel string, fi fs.FileInfo) error) error
	// Count is how many entries Walk visits (BackupTree from a plan): the
	// backup must hold exactly that many.
	Count int
}

// BackupFunc is called before every overwrite, move-over and delete. Its
// error aborts the operation before anything changes and is returned as
// is when it is an *Error (otherwise as backup_failed).
type BackupFunc func(src *BackupSource) error

func backupErr(err error) error {
	var fe *Error
	if errors.As(err, &fe) {
		return fe
	}
	return errf(protocol.CodeBackupFailed, "the backup could not be written; nothing was changed")
}

// backupFile hands the target to the backup hook through a verified
// descriptor, with sha, the SHA-256 fsx computed of it just before (empty
// when it computed none), and returns what was backed up. hashed, when
// set, is the file as fsx hashed it: the file backed up must be that
// version (sameVersion), or the backup is refused before the hook runs.
func (f *FS) backupFile(l *loc, sha string, hashed fs.FileInfo) (fs.FileInfo, error) {
	if f.cfg.InjectBeforeBackup != nil {
		f.cfg.InjectBeforeBackup()
	}
	file, err := f.openTarget(l)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, mapErr(err)
	}
	if !info.Mode().IsRegular() {
		return nil, errf(protocol.CodeBackupFailed, "only regular files can be backed up; nothing was changed")
	}
	if hashed != nil && !sameVersion(hashed, info) {
		return nil, unchanged(errf(protocol.CodeBackupFailed, "the file changed while it was being backed up; nothing was changed"))
	}
	if err := f.cfg.Backup(&BackupSource{Path: l.p, Kind: BackupFile, Info: info, File: file, SHA256: sha}); err != nil {
		return nil, backupErr(err)
	}
	return info, nil
}

// hashTarget opens the target through a verified descriptor and returns its
// stat and, with hash, the SHA-256 of its content (a regular file of at
// most maxHashBytes; a larger one is too_large).
func (f *FS) hashTarget(l *loc, hash bool) (fs.FileInfo, string, error) {
	file, err := f.openTarget(l)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, "", mapErr(err)
	}
	if !hash || !info.Mode().IsRegular() {
		return info, "", nil
	}
	if info.Size() > maxHashBytes {
		return nil, "", errf(protocol.CodeTooLarge, "the destination is larger than the %d MiB that is hashed", maxHashBytes>>20)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, maxHashBytes+1)); err != nil {
		return nil, "", mapErr(err)
	}
	return info, hex.EncodeToString(h.Sum(nil)), nil
}

// sameVersion reports whether a and b describe the same file, unchanged:
// the same inode, size and modification time.
func sameVersion(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// unchangedSince refuses when name in dir is no longer the file that was
// backed up (replaced, or rewritten in place): the backup would not hold
// what the operation destroys.
func unchangedSince(dir *os.Root, name string, backedUp fs.FileInfo) *Error {
	cur, err := dir.Lstat(name)
	if err != nil || !os.SameFile(cur, backedUp) || cur.Size() != backedUp.Size() || !cur.ModTime().Equal(backedUp.ModTime()) {
		return unchanged(errf(protocol.CodeBackupFailed, "the file changed while it was being backed up; nothing was changed"))
	}
	return nil
}

// String renders an owner for messages.
func (o Owner) String() string {
	u, g := "-", "-"
	if o.UID != nil {
		u = fmt.Sprint(*o.UID)
	}
	if o.GID != nil {
		g = fmt.Sprint(*o.GID)
	}
	return u + ":" + g
}

// WriteTarget is the stat of p as the write operations find it (the
// helper's priv_backup_check): p must be under a write root and pass the
// deny list and the protected set; nil when nothing is there. A final
// symlink is reported, not followed.
func (f *FS) WriteTarget(p string) (fs.FileInfo, error) {
	l, err := f.locate(p, true)
	if err != nil {
		return nil, err
	}
	defer l.close()
	if l.parent == nil {
		fi, serr := l.top.Stat(".")
		if serr != nil {
			return nil, mapErr(serr)
		}
		return fi, nil
	}
	fi, err := l.parent.Lstat(l.base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, mapErr(err)
	}
	return fi, nil
}

// commit reports a commit to Config.OnCommit.
func (f *FS) commit() {
	if f.cfg.OnCommit != nil {
		f.cfg.OnCommit()
	}
}

// unchanged marks e as a refusal made before any mutating system call of
// the operation, or after undoing it (Error.Unchanged).
func unchanged(e *Error) *Error {
	e.Unchanged = true
	return e
}
