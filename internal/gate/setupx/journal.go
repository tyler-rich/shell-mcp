//go:build linux

package setupx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
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
func NewJournal(h Host, a *Auditor) *Journal { return &Journal{h: h, a: a} }

// Changed reports whether the run changed anything yet.
func (j *Journal) Changed() bool { return len(j.entries) > 0 }

// Paths are the paths changed so far, in order.
func (j *Journal) Paths() []string {
	out := make([]string, len(j.entries))
	for i, e := range j.entries {
		out[i] = e.path
	}
	return out
}

// Hash is the lowercase hex SHA-256 of b.
func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ModeString is a permission mode as four octal digits.
func ModeString(m fs.FileMode) string { return fmt.Sprintf("%04o", uint32(m)) }

// Write writes data to path, whose state before the run is prev, and
// audits rec (Action create or replace, Path, SHA256 and Mode filled in).
func (j *Journal) Write(path string, prev FileState, data []byte, mode fs.FileMode, owner Owner, rec *Record) error {
	j.entries = append(j.entries, entry{path: path, prev: prev})
	if err := j.h.WriteFile(path, data, mode, owner); err != nil {
		var we *WriteError
		if !errors.As(err, &we) || !we.Committed {
			j.entries = j.entries[:len(j.entries)-1]
		}
		return err
	}
	rec.Action = ActionCreate
	if prev.Exists {
		rec.Action = ActionReplace
	}
	rec.Path, rec.SHA256, rec.Mode = path, Hash(data), ModeString(mode)
	if rec.Owner == "" {
		rec.Owner = owner.String()
	}
	j.a.Log(rec)
	return nil
}

// Mkdir creates the directory path and audits rec.
func (j *Journal) Mkdir(path string, mode fs.FileMode, owner Owner, rec *Record) error {
	if err := j.h.Mkdir(path, mode, owner); err != nil {
		return err
	}
	j.entries = append(j.entries, entry{path: path, dir: true})
	rec.Action, rec.Path, rec.Mode = ActionCreate, path, ModeString(mode)
	if rec.Owner == "" {
		rec.Owner = owner.String()
	}
	j.a.Log(rec)
	return nil
}

// Remove removes the file path, whose state is prev, and audits rec.
func (j *Journal) Remove(path string, prev FileState, rec *Record) error {
	if err := j.h.Remove(path); err != nil {
		return err
	}
	j.entries = append(j.entries, entry{path: path, prev: prev})
	rec.Action, rec.Path, rec.SHA256 = ActionRemove, path, Hash(prev.Data)
	j.a.Log(rec)
	return nil
}

// Rollback undoes every change, the last first: a file the run created is
// removed, a file it replaced or removed gets its previous bytes, owner and
// mode back, and a directory it created is removed. It returns one line
// per path undone, and the errors of the ones it could not undo.
func (j *Journal) Rollback() (undone []string, failed []error) {
	for _, e := range slices.Backward(j.entries) {
		var err error
		switch {
		case e.dir:
			err = j.h.Remove(e.path)
		case !e.prev.Exists:
			err = j.h.Remove(e.path)
		default:
			err = j.h.WriteFile(e.path, e.prev.Data, e.prev.Perm(), e.prev.Owner)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			failed = append(failed, fmt.Errorf("rolling back %s: %w", e.path, err))
			continue
		}
		undone = append(undone, e.path)
		j.a.Log(&Record{Action: ActionRollback, Object: "file", Path: e.path})
	}
	j.entries = nil
	return undone, failed
}
