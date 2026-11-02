//go:build linux

package setupx

import (
	"io/fs"
	"os"
)

// Disk is Files (and ReadDir) on the real filesystem, through the write
// helper. It starts no process: the install commands' real host
// (setupx/system) adds programs, and shell-mcp init uses Disk alone.
type Disk struct {
	// TempOwner is the uid whose temp files RemoveLeftovers removes: root
	// for the install commands, the running uid for init in the image.
	TempOwner uint32
}

// State implements Files.
func (Disk) State(path string, limit int64) (FileState, error) { return ReadState(path, limit) }

// ReadDir lists a directory's names.
func (Disk) ReadDir(path string) ([]string, error) {
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ents))
	for i, e := range ents {
		out[i] = e.Name()
	}
	return out, nil
}

// WriteFile implements Files.
func (Disk) WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error {
	return WriteFile(path, data, mode, owner)
}

// Mkdir implements Files.
func (Disk) Mkdir(path string, mode fs.FileMode, owner Owner) error { return Mkdir(path, mode, owner) }

// Remove implements Files.
func (Disk) Remove(path string) error { return Remove(path) }

// RemoveLeftovers implements Files, for temp files owned by TempOwner.
func (d Disk) RemoveLeftovers(target string) ([]string, error) {
	return removeLeftovers(target, d.TempOwner)
}
