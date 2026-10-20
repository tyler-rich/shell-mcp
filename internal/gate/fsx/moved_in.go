//go:build linux

package fsx

import "io/fs"

// ChainDir is one directory on the chain from a root to a file's parent:
// its path (for messages), owner and permission bits.
type ChainDir struct {
	Path string
	UID  uint32
	Mode uint32
}

// WriteChain is not implemented yet (stub).
func (f *FS) WriteChain(string) ([]ChainDir, error) { return nil, nil }

// MovedInBy is not implemented yet (stub).
func (f *FS) MovedInBy([]ChainDir, uint32) *ChainDir { return nil }

// CurrentFile is not implemented yet (stub).
func (f *FS) CurrentFile(string) (fs.FileInfo, string, error) { return nil, "", nil }
