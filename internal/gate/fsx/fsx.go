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
	// RENAME_NOREPLACE for move), and its error is that call's result. Tests
	// only; production code never sets it.
	InjectNoReplaceFault func() error
	// InjectDeleteStep, when non-nil, is called at each point of
	// DeleteExact's deletion pass with the logical path of the entry
	// concerned (the target's for DeleteStepAfterCompare). Tests only;
	// production code never sets it.
	InjectDeleteStep func(step DeleteStep, path string)
	// Backup, when non-nil, is called before every overwrite, move-over and
	// delete; its error aborts the operation. The gate never sets it.
	Backup BackupFunc
	// ModesMax, when non-nil, masks the mode of every new inode: a file
	// written (over an existing one too), copied or restored, and a
	// directory created. The helper sets it to its modes.max (PRIVILEGED
	// §4); the gate leaves it nil.
	ModesMax *os.FileMode
	// VerifyMetadata makes Chmod and Chown re-read the mode, owner and group
	// through the descriptor they changed; a mismatch is verify_failed. The
	// helper sets it; the gate does not.
	VerifyMetadata bool
	// InjectMetadataReadBackFault, when non-nil, transforms what Chmod and
	// Chown read back before it is compared. Tests only; production code
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
	// its metadata changed), and before a delete starts removing entries. The
	// helper uses it to tell a failed operation that changed nothing from one
	// that did; the gate leaves it nil.
	OnCommit func()
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

// DeleteResult is delete's and delete_preview's result.
type DeleteResult struct {
	Path    string   `json:"path"`
	Type    string   `json:"type"`
	Entries int      `json:"entries"`
	Bytes   int64    `json:"bytes"`
	First   []string `json:"first"`
	Deleted bool     `json:"deleted"`
}
