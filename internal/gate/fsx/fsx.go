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
	"errors"
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
	// Protected applies to every write, on requested and real paths.
	Protected *pathx.Matcher
	Limits    Limits
	// InjectReadBackFault, when non-nil, transforms the bytes read back
	// after a write before they are compared. Tests only; production code
	// never sets it.
	InjectReadBackFault func([]byte) []byte
}

// FS performs confined operations.
type FS struct {
	cfg Config
}

// New returns an FS for cfg.
func New(cfg Config) *FS { return &FS{cfg: cfg} }

// Error is an fsx failure with a gate error code (internal/protocol).
type Error struct {
	Code string
	Msg  string
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
}

// MkdirResult is mkdir's result.
type MkdirResult struct {
	Path    string `json:"path"`
	Created bool   `json:"created"`
	Mode    string `json:"mode"`
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

var errTODO = errors.New("not implemented")

// Stat describes p without following a final symlink.
func (f *FS) Stat(p string) (Entry, error) { return Entry{}, errTODO }

// ListDir lists the directory p.
func (f *FS) ListDir(p string, includeHidden bool, limit int) (ListResult, error) {
	return ListResult{}, errTODO
}

// ReadFile reads the regular file p.
func (f *FS) ReadFile(p string, o ReadOptions) (ReadResult, error) { return ReadResult{}, errTODO }

// Find walks the directory p.
func (f *FS) Find(p string, o FindOptions) (FindResult, error) { return FindResult{}, errTODO }

// WriteFile atomically writes content to p under a write root.
func (f *FS) WriteFile(p string, content []byte, o WriteOptions) (WriteResult, error) {
	return WriteResult{}, errTODO
}

// Mkdir creates the directory p under a write root.
func (f *FS) Mkdir(p string, mode *os.FileMode, parents bool) (MkdirResult, error) {
	return MkdirResult{}, errTODO
}

// Copy copies the regular file src (any root) to dst (a write root).
func (f *FS) Copy(src, dst string, overwrite bool) (WriteResult, error) {
	return WriteResult{}, errTODO
}

// Move renames src to dst; both must be under the same write root.
func (f *FS) Move(src, dst string, overwrite bool) (MoveResult, error) {
	return MoveResult{}, errTODO
}

// Chmod sets the mode of p under a write root.
func (f *FS) Chmod(p string, mode os.FileMode) (ChmodResult, error) {
	return ChmodResult{}, errTODO
}

// Delete removes p under a write root (recursively only if recursive).
func (f *FS) Delete(p string, recursive bool) (DeleteResult, error) {
	return DeleteResult{}, errTODO
}

// DeletePreview reports what Delete would remove, removing nothing.
func (f *FS) DeletePreview(p string, recursive bool) (DeleteResult, error) {
	return DeleteResult{}, errTODO
}

// ResolveRead returns the real path of an existing object under a read or
// write root (for {path:read}).
func (f *FS) ResolveRead(p string) (string, error) { return "", errTODO }

// ResolveWrite returns the real path of p under a write root; p need not
// exist, but its parent must (for {path:write}).
func (f *FS) ResolveWrite(p string) (string, error) { return "", errTODO }

// ResolveDir returns the real path of a directory under a read or write
// root (for an exec cwd).
func (f *FS) ResolveDir(p string) (string, error) { return "", errTODO }

// ParseMode parses an octal mode string ("0640" or "640") and applies the
// gate's mode rules: permission bits only, no setuid/setgid/sticky, no
// world-write.
func ParseMode(s string) (os.FileMode, error) { return 0, errTODO }
