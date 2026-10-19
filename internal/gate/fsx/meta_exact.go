//go:build linux

package fsx

import (
	"os"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// STUB (S4c-3 failing-tests commit): the API of the helper's bound chown and
// chmod, with inert bodies. PreviewMeta reports the target alone under a
// fixed hash; ApplyMeta changes the target as S4c-0's Chmod and Chown did,
// ignoring the hash, recursion and the chain rule.

// MetaOp is the kind of metadata change.
type MetaOp int

// Metadata changes.
const (
	MetaChown MetaOp = iota + 1
	MetaChmod
)

// MetaChange is what a chown or chmod sets.
type MetaChange struct {
	Op       MetaOp
	UID, GID *uint32
	Mode     os.FileMode
}

// MetaStep names a point of ApplyMeta's pass, for tests (Config.InjectMetaStep).
type MetaStep int

// Points of the pass.
const (
	MetaStepAfterCompare MetaStep = iota + 1
	MetaStepBeforeEntry
	MetaStepBeforeChange
)

// MetaEntry is one entry of a plan.
type MetaEntry struct {
	Path, Type              string
	UID, GID, Mode          uint32
	NewUID, NewGID, NewMode uint32
	Change                  bool
}

// MetaChanged is an entry ApplyMeta changed, with its values before.
type MetaChanged struct {
	Path   string
	Before Meta
}

// MetaPlan is PreviewMeta's and ApplyMeta's result.
type MetaPlan struct {
	Path          string
	Type          string
	Entries       int
	Changes       int
	First         []MetaEntry
	PreviewSHA256 string
	Top           MetaEntry
	Changed       []MetaChanged
	Done          bool
}

// ChainError is a directory on a path that another account could write.
type ChainError struct {
	Dir      string
	UID      uint32
	Mode     uint32
	Writable bool
}

func (e *ChainError) Error() string { return "stub" }

// CheckRootChain checks the directories from / to dir (stub: nothing).
func CheckRootChain(_ string, _ func(uint32) bool) error { return nil }

// appendMetaEntry (stub): the delete's encoding.
func appendMetaEntry(b []byte, path string, id *ident) []byte { return appendPreviewEntry(b, path, id) }

const stubMetaHash = "1111111111111111111111111111111111111111111111111111111111111111"

// PreviewMeta (stub).
func (f *FS) PreviewMeta(p string, ch MetaChange, _ bool, _ string) (MetaPlan, error) {
	st, err := f.Stat(p)
	if err != nil {
		return MetaPlan{Path: p}, err
	}
	e := MetaEntry{Path: p, Type: st.Type, UID: st.UID, GID: st.GID, Change: true}
	return MetaPlan{Path: p, Type: st.Type, Entries: 1, Changes: 1, First: []MetaEntry{e}, PreviewSHA256: stubMetaHash, Top: e}, nil
}

// ApplyMeta (stub).
func (f *FS) ApplyMeta(p string, ch MetaChange, _ bool, _, _ string) (MetaPlan, error) {
	res := MetaPlan{Path: p}
	switch ch.Op {
	case MetaChmod:
		r, err := f.Chmod(p, ch.Mode)
		if r.Changed {
			res.Changed = append(res.Changed, MetaChanged{Path: p, Before: r.Before})
		}
		res.Top = MetaEntry{Path: p, Mode: r.Before.Mode, NewMode: uint32(ch.Mode)}
		res.Done = err == nil
		return res, err
	case MetaChown:
		r, err := f.Chown(p, Owner{UID: ch.UID, GID: ch.GID})
		if r.Changed {
			res.Changed = append(res.Changed, MetaChanged{Path: p, Before: r.Before})
		}
		res.Top = MetaEntry{Path: p, UID: r.OldUID, GID: r.OldGID, NewUID: r.UID, NewGID: r.GID}
		res.Done = err == nil
		return res, err
	}
	return res, errf(protocol.CodeBadRequest, "unknown change")
}
