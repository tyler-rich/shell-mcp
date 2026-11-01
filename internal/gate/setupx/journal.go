//go:build linux

package setupx

import (
	"io/fs"
)

// Journal applies a run's file changes and remembers each path's previous
// state, so that Rollback can restore every file the run changed to its
// previous bytes, owner and mode, and remove what it created
// (TARGET-SETUP §12.4). Each change is audited.
type Journal struct {
	h       Host
	a       *Auditor
	entries []entry
}

type entry struct {
	path string
	prev FileState
	dir  bool // the run created this directory
}

// NewJournal returns an empty journal for h, auditing through a.
func NewJournal(h Host, a *Auditor) *Journal { var stub0 *Journal; return stub0 }

// Changed reports whether the run changed anything yet.
func (j *Journal) Changed() bool { var stub0 bool; return stub0 }

// Paths are the paths changed so far, in order.
func (j *Journal) Paths() []string { var stub0 []string; return stub0 }

// Hash is the lowercase hex SHA-256 of b.
func Hash(b []byte) string { var stub0 string; return stub0 }

// ModeString is a permission mode as four octal digits.
func ModeString(m fs.FileMode) string { var stub0 string; return stub0 }

// Write writes data to path, whose state before the run is prev, and
// audits rec (Action create or replace, Path, SHA256 and Mode filled in).
func (j *Journal) Write(path string, prev FileState, data []byte, mode fs.FileMode, owner Owner, rec *Record) error {
	var stub0 error
	return stub0
}

// Mkdir creates the directory path and audits rec.
func (j *Journal) Mkdir(path string, mode fs.FileMode, owner Owner, rec *Record) error {
	var stub0 error
	return stub0
}

// Remove removes the file path, whose state is prev, and audits rec.
func (j *Journal) Remove(path string, prev FileState, rec *Record) error {
	var stub0 error
	return stub0
}

// Rollback undoes every change, the last first: a file the run created is
// removed, a file it replaced or removed gets its previous bytes, owner and
// mode back, and a directory it created is removed. It returns one line
// per path undone, and the errors of the ones it could not undo.
func (j *Journal) Rollback() (undone []string, failed []error) {
	var stub0 []string
	var stub1 []error
	return stub0, stub1
}
