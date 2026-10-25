//go:build linux

// Package fsx confines filesystem operations (docs/POLICY.md §3): the longest
// matching root is opened as an os.Root, the target's parent directory is
// opened as a sub-root, and after every open the real path from
// /proc/self/fd/N is re-checked against the root, the deny list and (for
// writes) the protected set. Final-component symlinks are refused except by
// Stat. Writes are temp file → fsync → rename → directory fsync → re-open
// and SHA-256 compare.
//
// fsx is shared with the privileged helper: everything it needs comes from
// Config (roots, deny and protected matchers, limits), so the helper can
// apply its own roots.
package fsx

import (
	"os"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
)

// Limits bound fsx operations.
type Limits struct {
	MaxReadBytes     int
	MaxWriteBytes    int
	MaxFindResults   int
	MaxFindDepth     int
	MaxDeleteEntries int
}

// MaxListEntries caps list_dir results.
const MaxListEntries = 5000

// Config is the confinement for one FS.
type Config struct {
	// ReadRoots and WriteRoots are clean absolute directories. Write roots
	// are implicitly readable.
	ReadRoots  []string
	WriteRoots []string
	// Deny applies to every operation, on requested and real paths.
	Deny *pathx.Matcher
	// BuiltinDeny is how many of Deny's leading patterns are the built-in read
	// deny list (the rest are the policy's paths.deny, in order).
	BuiltinDeny int
	// Protected applies to every write, on requested and real paths.
	Protected *pathx.Matcher
	Limits    Limits
	// InjectReadBackFault, when non-nil, transforms the bytes read back
	// after a write before they are compared. Tests only; production code
	// never sets it.
	InjectReadBackFault func([]byte) []byte
	// InjectBeforeCommit, when non-nil, is called after every check and
	// immediately before a write, copy or move commits (the rename or link
	// that makes the destination appear). Tests only; production code never
	// sets it.
	InjectBeforeCommit func()
	// InjectNoReplaceFault, when non-nil, is called instead of the system
	// call of a create-only commit (link for write and copy, renameat2 with
	// RENAME_NOREPLACE for move) and of a move's stage (renameat2 with
	// RENAME_NOREPLACE), and its error is that call's result. Tests only;
	// production code never sets it.
	InjectNoReplaceFault func() error
	// InjectDeleteStep, when non-nil, is called at each point of
	// DeleteExact's deletion pass with the logical path of the entry
	// concerned (the target's for DeleteStepAfterCompare). Tests only;
	// production code never sets it.
	InjectDeleteStep func(step DeleteStep, path string)
	// InjectStopAfterSetAside, when non-nil, is called right after a delete
	// set an entry aside (its logical path); an error it returns stops the
	// deletion there, without putting the entry back or unlinking it, as a
	// path that stops unexpectedly would. Tests only; production code never
	// sets it.
	InjectStopAfterSetAside func(path string) error
	// InjectAfterStage, when non-nil, is called right after a move staged
	// its source under a temporary name in the destination's directory
	// (that name); an error it returns stops the move there, leaving the
	// staged entry, as a gate or helper that dies there would. Tests only;
	// production code never sets it.
	InjectAfterStage func(tmp string) error
	// Backup, when non-nil, is called before every overwrite, move-over and
	// delete; its error aborts the operation. The gate never sets it.
	Backup BackupFunc
	// ModesMax, when non-nil, masks the mode of every new inode: a file
	// written (over an existing one too), copied or restored, and a
	// directory created. The helper sets it to its modes.max (PRIVILEGED
	// §4); the gate leaves it nil.
	ModesMax *os.FileMode
	// VerifyMetadata makes Chmod re-read the mode, owner and group through
	// the descriptor it changed; a mismatch is verify_failed. The gate (its
	// chmod, handoff N-4) and the helper set it. (The helper's chown and
	// chmod, ApplyMeta, always read back.)
	VerifyMetadata bool
	// InjectMetadataReadBackFault, when non-nil, transforms what Chmod and
	// ApplyMeta read back before it is compared. Tests only; production code
	// never sets it.
	InjectMetadataReadBackFault func(Meta) Meta
	// VerifyReplaced makes every commit that replaces an existing file an
	// exchange (renameat2 RENAME_EXCHANGE) followed by a check that the
	// inode exchanged out is the one that was checked and backed up; another
	// is exchanged back and the operation refused with exists. The helper
	// sets it; the gate does not.
	VerifyReplaced bool
	// InjectBeforeBackup, when non-nil, is called after a file to be
	// replaced was hashed and before it is handed to the backup hook. Tests
	// only; production code never sets it.
	InjectBeforeBackup func()
	// InjectExchangeFault, when non-nil, is called instead of the
	// RENAME_EXCHANGE system call of a verified replace, and its error is
	// that call's result. Tests only; production code never sets it.
	InjectExchangeFault func() error
	// OnCommit, when non-nil, is called after each commit that changes the
	// filesystem (a file or directory created, replaced, moved, removed, or
	// its metadata changed; for a delete, each entry unlinked, and an entry
	// left set aside under its temporary name). The helper uses it to tell a
	// failed operation that changed nothing from one that did; the gate
	// leaves it nil.
	OnCommit func()
	// TrustedDirOwner decides whose directories the chain rules trust
	// (PreviewMeta and ApplyMeta on the path to an entry and inside a tree,
	// the moved-in rule, GuardExecPaths, CheckGitRepo): a directory must be
	// owned by a uid it accepts and be neither group- nor world-writable
	// (PRIVILEGED §6, handoff N-1). nil trusts uid 0 only. The helper sets it
	// from its trust (root); the gate, for its commands' paths and its git
	// repositories only, to root and the service account (handoff N-11,
	// N-20).
	TrustedDirOwner func(uid uint32) bool
	// GuardMovedIn applies the moved-in rule (PRIVILEGED §6, "Files another
	// account could have moved in"; handoff N-6, N-7; moved_in.go): a file
	// under a directory another account could write (the chain from its
	// root to its parent, by descriptor, trusting TrustedDirOwner) is read
	// only when owner-matched or world-readable, and overwritten keeping its
	// owner and group only when owner-matched. The helper sets it; the gate
	// does not.
	GuardMovedIn bool
	// GuardExecPaths applies the chain rule to the paths a command is given
	// (handoff N-10, N-11; exec_chain.go): ResolveRead, ResolveWrite and
	// ResolveDir return a path only when every directory from / to its
	// parent, by descriptor, is owned by a uid TrustedDirOwner accepts and is
	// neither group- nor world-writable nor sticky, and a directory target
	// is so itself, since the command looks the string up again itself. The
	// helper sets it; the gate sets it on the FS that resolves its commands'
	// paths, not on the one its built-in git operations use.
	GuardExecPaths bool
	// OwnerMatchedReads relaxes GuardExecPaths for a {path:read}
	// (ResolveRead) only: a directory on its path, or the target directory
	// itself, that is not closed passes when it is neither group- nor
	// world-writable nor sticky and every such directory on the path belongs
	// to the same one account (exec_chain.go). The gate sets it on the FS
	// that resolves its commands' paths (handoff N-11); the helper does not.
	OwnerMatchedReads bool
	// ExplicitOwner sets the owner and group of every inode fsx creates
	// explicitly (fchown of both ids): the ones given, else an existing
	// file's, else the process's own, so a setgid parent never chooses the
	// group (handoff N-8; PRIVILEGED §6). The helper sets it; the gate does
	// not.
	ExplicitOwner bool
	// Privileged marks the privileged helper's FS: refusals then say that
	// it acts as root and point to its documentation (PRIVILEGED.md) rather
	// than the gate's (POLICY.md). Only messages depend on it. The helper
	// sets it; the gate does not.
	Privileged bool
	// InjectMetaStep, when non-nil, is called at each point of ApplyMeta's
	// pass with the logical path of the entry concerned (the target's for
	// MetaStepAfterCompare). Tests only; production code never sets it.
	InjectMetaStep func(step MetaStep, path string)
	// confineHooks is empty in a release build; the shellmcp_confine_hook
	// test build's hooks turn off one read-confinement layer (handoff N-12).
	confineHooks
}

// Meta is an inode's mode (permission and special bits), owner and group.
type Meta struct {
	Mode     uint32
	UID, GID uint32
}

// FS performs confined operations.
type FS struct {
	cfg Config
}

// asRoot, who and docs word a refusal for the program the FS serves: the
// privileged helper (Config.Privileged), which acts as root, or the gate.
func (f *FS) asRoot() string {
	if f.cfg.Privileged {
		return " as root"
	}
	return ""
}

func (f *FS) who() string {
	if f.cfg.Privileged {
		return "the helper"
	}
	return "the gate"
}

func (f *FS) docs() string {
	if f.cfg.Privileged {
		return "the privileged helper's documentation"
	}
	return "the policy documentation"
}

// New returns an FS for cfg.
func New(cfg *Config) *FS { return &FS{cfg: *cfg} }

// Error is an fsx failure with a gate error code (internal/protocol).
type Error struct {
	Code string
	Msg  string
	// SetAside, when set, is the path of an entry a delete set aside and
	// could not put back under its name (it was not deleted).
	SetAside string
	// Unchanged is set only by a refusal that fsx made before any mutating
	// system call of the operation, or after undoing the one it made (a
	// verified replace exchanged back): the operation provably changed
	// nothing. Never on the wire.
	Unchanged bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// Entry describes one filesystem object.
type Entry struct {
	Path       string `json:"path"`
	Name       string `json:"name"`
	Type       string `json:"type"` // file | dir | symlink | other
	Size       int64  `json:"size"`
	Mode       string `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Owner      string `json:"owner,omitempty"`
	Group      string `json:"group,omitempty"`
	MTime      string `json:"mtime"`
	LinkTarget string `json:"link_target,omitempty"`
}

// ListResult is list_dir's result.
type ListResult struct {
	Path      string  `json:"path"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

// ReadOptions are read_file's options.
type ReadOptions struct {
	Offset    int64
	MaxBytes  int
	TailLines int
}

// ReadResult is read_file's result. Content is set only for text.
type ReadResult struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Binary    bool   `json:"binary"`
	Content   string `json:"content,omitempty"`
	Offset    int64  `json:"offset"`
	Truncated bool   `json:"truncated"`
}

// FindOptions are find's options.
type FindOptions struct {
	NameGlob        string
	Type            string // "", file, dir, symlink
	ModifiedWithinS int64
	MaxDepth        int
	Limit           int
}

// FindResult is find's result.
type FindResult struct {
	Path      string  `json:"path"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

// WriteOptions are write_file's options.
type WriteOptions struct {
	Mode           *os.FileMode
	Create         bool
	ExpectedSHA256 string
	// ExpectAbsent refuses the write with exists if the file exists, up to
	// and including the commit. Mutually exclusive with ExpectedSHA256.
	ExpectAbsent bool
	// Owner, when set, is the new file's owner (the helper only).
	Owner *Owner
	// DefaultMode, when non-zero, replaces 0640 as a new file's mode when
	// Mode is not given (the helper caps it by its mode mask).
	DefaultMode os.FileMode
}

// WriteResult is write_file's (and copy's) result.
type WriteResult struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	OldSHA256      string `json:"old_sha256,omitempty"`
	Bytes          int    `json:"bytes"`
	Created        bool   `json:"created"`
	Mode           string `json:"mode"`
	LinesOld       int    `json:"lines_old"`
	LinesNew       int    `json:"lines_new"`
	OwnerPreserved bool   `json:"owner_preserved"`
	Verified       bool   `json:"verified"`
	// UID and GID are the new inode's owner and group, read from its own
	// descriptor after they were set; the helper reports them, the gate's
	// wire does not carry them.
	UID uint32 `json:"-"`
	GID uint32 `json:"-"`
}

// MkdirResult is mkdir's result.
type MkdirResult struct {
	Path    string `json:"path"`
	Created bool   `json:"created"`
	Mode    string `json:"mode"`
	// UID and GID are the directory's owner and group (as WriteResult's).
	UID uint32 `json:"-"`
	GID uint32 `json:"-"`
}

// MoveResult is move's result.
type MoveResult struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
	Replaced    bool   `json:"replaced"`
}

// ChmodResult is chmod's result.
type ChmodResult struct {
	Path    string `json:"path"`
	OldMode string `json:"old_mode"`
	Mode    string `json:"mode"`
	// Before is the inode's mode, owner and group before the change, and
	// Changed whether the change was made (also when its read-back then
	// failed); for the helper's audit, never on the wire.
	Before  Meta `json:"-"`
	Changed bool `json:"-"`
}

// DeleteResult is the helper's priv_delete result (the gate's delete and
// delete_preview answer DeletePlan).
type DeleteResult struct {
	Path    string   `json:"path"`
	Type    string   `json:"type"`
	Entries int      `json:"entries"`
	Bytes   int64    `json:"bytes"`
	First   []string `json:"first"`
	Deleted bool     `json:"deleted"`
}
