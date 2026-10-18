//go:build linux

package fsx

import (
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// git_discard's filesystem side (docs/POLICY.md §7, "Discarding changes").
// Stubs: implemented with the tests' companion commit.

// DiscardStep names a point of git_discard, for tests
// (Options.InjectDiscardStep in the gate).
type DiscardStep int

// Points of a discard.
const (
	// DiscardStepAfterCompare: the lock is held and the preview hash
	// matched; nothing has changed yet.
	DiscardStepAfterCompare DiscardStep = iota + 1
	// DiscardStepBeforeUntracked: tracked entries are set aside; untracked
	// ones are about to be removed.
	DiscardStepBeforeUntracked
	// DiscardStepBeforeCheckout: git is about to write the restored files.
	DiscardStepBeforeCheckout
	// DiscardStepAfterCheckout: git wrote them; nothing is verified yet.
	DiscardStepAfterCheckout
	// DiscardStepBeforeCommit: everything verified; the index is about to
	// be replaced.
	DiscardStepBeforeCommit
)

// WorktreeEntry is what is at a tracked path in the work tree.
type WorktreeEntry struct {
	Path      string // the logical path
	State     string // absent, file, symlink or dir
	Mode      uint32 // permission bits of a file
	Size      int64
	SHA256    string // a file's content, or a symlink's target
	BlockedBy string // the first ancestor that exists and is not a directory

	id ident
}

// ObserveWorktree describes the entry at p (under a write root),
// following nothing. budget bounds the bytes hashed across calls.
func (f *FS) ObserveWorktree(p string, budget *int64) (WorktreeEntry, error) {
	return WorktreeEntry{Path: p}, errf(protocol.CodeInternal, "not implemented")
}

// AppendHash appends w's hash input.
func (w *WorktreeEntry) AppendHash(b []byte) []byte { return b }

// AsideEntry is a work-tree entry set aside under a temporary name.
type AsideEntry struct{}

// SetAside sets w's entry aside, after checking that it is what w
// describes.
func (f *FS) SetAside(w *WorktreeEntry) (*AsideEntry, error) {
	return nil, errf(protocol.CodeInternal, "not implemented")
}

// Temp is the entry's temporary path.
func (a *AsideEntry) Temp() string { return "" }

// Remove removes the entry set aside.
func (a *AsideEntry) Remove() error { return errf(protocol.CodeInternal, "not implemented") }

// PutBack puts the entry back under its name, never replacing anything.
func (a *AsideEntry) PutBack() error { return errf(protocol.CodeInternal, "not implemented") }

// GitIndexLock is git's index lock, held by this gate.
type GitIndexLock struct{}

// LockGitIndex creates <repo>/.git/index.lock.
func (f *FS) LockGitIndex(repo string) (*GitIndexLock, error) {
	return nil, errf(protocol.CodeInternal, "not implemented")
}

// GitIndexLockState reports whether <repo>/.git/index.lock exists and
// whether a gate created it.
func (f *FS) GitIndexLockState(repo string) (locked, byGate bool, err error) {
	return false, false, nil
}

// NewTempIndex creates the temporary index and returns its real path.
func (k *GitIndexLock) NewTempIndex() (string, error) {
	return "", errf(protocol.CodeInternal, "not implemented")
}

// CommitTempIndex renames the temporary index onto .git/index.
func (k *GitIndexLock) CommitTempIndex() error { return errf(protocol.CodeInternal, "not implemented") }

// Release removes what this lock created.
func (k *GitIndexLock) Release() {}
