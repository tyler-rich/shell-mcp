//go:build linux

package setupx

import (
	"encoding/base32"
	"errors"

	"io/fs"

	"regexp"
)

// Owner is a file's owner and group.
type Owner struct{ UID, GID uint32 }

// Root is root:root.
var Root = Owner{0, 0}

func (o Owner) String() string { var stub0 string; return stub0 }

// tempSuffixLen is the random part of a temp name: 12 characters of the
// lowercase base32 alphabet (a-z, 2-7), 60 bits from crypto/rand.
const tempSuffixLen = 12

// tempRE matches a temp name (TARGET-SETUP §12.4): the target's base name
// after a leading dot, then ".shell-mcp-" and the random part. sshd's
// Include *.conf, AuthorizedKeysFile %u, polkit's *.rules and systemd's
// unit suffixes match none of them.
var tempRE = regexp.MustCompile(`^\.(.+)\.shell-mcp-[a-z2-7]{12}$`)

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// TempName is a fresh temp name for target, in target's own directory.
func TempName(target string) (string, error) { var stub0 string; var stub1 error; return stub0, stub1 }

// IsTempFor reports whether name (a base name) is a temp name for the
// target base name base.
func IsTempFor(name, base string) bool { var stub0 bool; return stub0 }

// IsTemp reports whether name (a base name) is any install temp name.
func IsTemp(name string) bool { var stub0 bool; return stub0 }

// WriteError is a failed write: Step names where it failed, and Committed
// says whether the target was already replaced (the read-back failed after
// the rename), so the caller's journal must restore it.
type WriteError struct {
	Path      string
	Step      string
	Committed bool
	Err       error
}

func (e *WriteError) Error() string { var stub0 string; return stub0 }

func (e *WriteError) Unwrap() error { var stub0 error; return stub0 }

// ErrReadBack is a read-back that found other bytes, owner or mode.
var ErrReadBack = errors.New("read-back does not match what was written")

// writeHooks are test seams (export_test.go); production passes nil.
type writeHooks struct {
	// fail, when it returns an error for a step, makes that step fail.
	fail func(step string) error
}

func (h *writeHooks) at(step string) error { var stub0 error; return stub0 }

// Write steps, in order.
const (
	stepCreate   = "create"
	stepWrite    = "write"
	stepSync     = "fsync"
	stepChown    = "chown"
	stepChmod    = "chmod"
	stepClose    = "close"
	stepRename   = "rename"
	stepSyncDir  = "fsync of the directory"
	stepReadBack = "read-back"
)

// WriteFile writes data to path: a temp file in path's own directory
// (O_CREAT|O_EXCL|O_NOFOLLOW, 0600), written, fsync'd, given owner and
// mode on its descriptor, renamed over path, the directory fsync'd, and
// path read back (its bytes by SHA-256, its owner, mode and type). A
// failure before the rename removes the temp file; a read-back failure
// after it is a WriteError with Committed set.
func WriteFile(path string, data []byte, mode fs.FileMode, owner Owner) error {
	var stub0 error
	return stub0
}

func writeFile(path string, data []byte, mode fs.FileMode, owner Owner, h *writeHooks) error {
	var stub0 error
	return stub0
}

//nolint:gosec // G304: a fresh temp name in the target's own directory

// readBack opens path without following a link and requires a regular file
// of exactly owner and mode whose bytes hash to data's SHA-256.
func readBack(path string, data []byte, mode fs.FileMode, owner Owner) error {
	var stub0 error
	return stub0
}

//nolint:gosec // G304: the file just written

func syncDir(dir string) error { var stub0 error; return stub0 }

//nolint:gosec // G304: the target's own directory

// Mkdir creates the directory path (its parent must exist) and gives it
// owner and mode on its own descriptor; a failure after the mkdir(2)
// removes it again.
func Mkdir(path string, mode fs.FileMode, owner Owner) error { var stub0 error; return stub0 }

//nolint:gosec // G304: the directory just created

// Remove removes the file or empty directory path and fsyncs its parent.
func Remove(path string) error { var stub0 error; return stub0 }

// RemoveLeftovers removes the temp files a killed run left for target: in
// target's directory, each regular root-owned file whose name is a temp
// name for target's base name. It returns the paths removed. A matching
// name that is anything else is refused, and left for the operator.
func RemoveLeftovers(target string) ([]string, error) {
	var stub0 []string
	var stub1 error
	return stub0, stub1
}

// removeLeftovers is RemoveLeftovers for temp files owned by uid (tests use
// their own).
func removeLeftovers(target string, uid uint32) ([]string, error) {
	var stub0 []string
	var stub1 error
	return stub0, stub1
}

// FileState is what a path holds now: nothing, or a file, directory or
// other entry with its owner and mode, and a regular file's bytes.
type FileState struct {
	Exists bool
	Mode   fs.FileMode // type bits and permission bits, as Lstat reports them
	Owner  Owner
	Data   []byte // a regular file's content (at most the caller's bound)
}

// IsRegular reports a regular file.
func (s FileState) IsRegular() bool { var stub0 bool; return stub0 }

// IsDir reports a directory.
func (s FileState) IsDir() bool { var stub0 bool; return stub0 }

// Perm is the permission bits with setuid, setgid and sticky.
func (s FileState) Perm() fs.FileMode { var stub0 fs.FileMode; return stub0 }

// Same reports whether s is a regular file holding exactly data with mode
// and owner.
func (s FileState) Same(data []byte, mode fs.FileMode, owner Owner) bool {
	var stub0 bool
	return stub0
}

// ErrTooLarge is a file over the caller's bound.
var ErrTooLarge = errors.New("file is larger than the bound")

// ReadState reads path without following a link: absent, or its kind,
// owner and mode, and for a regular file at most limit bytes (more is
// ErrTooLarge).
func ReadState(path string, limit int64) (FileState, error) {
	var stub0 FileState
	var stub1 error
	return stub0, stub1
}

//nolint:gosec // G304: a path the installer manages
