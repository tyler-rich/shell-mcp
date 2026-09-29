//go:build linux

package fsx

import (
	"io/fs"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Owner is a file owner to set; a nil id is left as it is (or, for a new
// file or directory, as the process creates it).
type Owner struct {
	UID, GID *uint32
}

// ChownResult is chown's result.
type ChownResult struct {
	Path   string `json:"path"`
	OldUID uint32 `json:"old_uid"`
	OldGID uint32 `json:"old_gid"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

// BackupSource describes what a destructive operation is about to replace
// or remove.
type BackupSource struct {
	Path string
	Kind string
	Info fs.FileInfo
	File *os.File
	Walk func(visit func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error) error
}

// BackupFunc is called before every overwrite, move-over and delete.
type BackupFunc func(src *BackupSource) error

// MkdirAs is Mkdir with an owner for the directories it creates.
func (f *FS) MkdirAs(p string, mode *os.FileMode, parents bool, owner *Owner) (MkdirResult, error) {
	return f.Mkdir(p, mode, parents)
}

// Chown sets the owner and/or group of p under a write root.
func (f *FS) Chown(p string, o Owner) (ChownResult, error) {
	return ChownResult{}, errf(protocol.CodeInternal, "not implemented")
}
