//go:build linux

package setupx

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"
)

// Owner is a file's owner and group.
type Owner struct{ UID, GID uint32 }

// Root is root:root.
var Root = Owner{0, 0}

func (o Owner) String() string { return fmt.Sprintf("%d:%d", o.UID, o.GID) }

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
func TempName(target string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".shell-mcp-"+lowerBase32.EncodeToString(b[:])[:tempSuffixLen]), nil
}

// IsTempFor reports whether name (a base name) is a temp name for the
// target base name base.
func IsTempFor(name, base string) bool {
	m := tempRE.FindStringSubmatch(name)
	return len(m) == 2 && m[1] == base
}

// IsTemp reports whether name (a base name) is any install temp name.
func IsTemp(name string) bool { return tempRE.MatchString(name) }

// WriteError is a failed write: Step names where it failed, and Committed
// says whether the target was already replaced (the read-back failed after
// the rename), so the caller's journal must restore it.
type WriteError struct {
	Path      string
	Step      string
	Committed bool
	Err       error
}

func (e *WriteError) Error() string {
	return fmt.Sprintf("writing %s failed at %s: %v", e.Path, e.Step, e.Err)
}

func (e *WriteError) Unwrap() error { return e.Err }

// ErrReadBack is a read-back that found other bytes, owner or mode.
var ErrReadBack = errors.New("read-back does not match what was written")

// writeHooks are test seams (export_test.go); production passes nil.
type writeHooks struct {
	// fail, when it returns an error for a step, makes that step fail.
	fail func(step string) error
}

func (h *writeHooks) at(step string) error {
	if h == nil || h.fail == nil {
		return nil
	}
	return h.fail(step)
}

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
	return writeFile(path, data, mode, owner, nil)
}

func writeFile(path string, data []byte, mode fs.FileMode, owner Owner, h *writeHooks) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || mode&^fs.ModePerm != 0 {
		return &WriteError{Path: path, Step: stepCreate, Err: errors.New("not an absolute clean path with a permission-only mode")}
	}
	fail := func(step string, err error) error { return &WriteError{Path: path, Step: step, Err: err} }
	tmp, err := TempName(path)
	if err != nil {
		return fail(stepCreate, err)
	}
	if err = h.at(stepCreate); err != nil {
		return fail(stepCreate, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600) //nolint:gosec // G304: a fresh temp name in the target's own directory
	if err != nil {
		return fail(stepCreate, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	for _, s := range []struct {
		step string
		do   func() error
	}{
		{stepWrite, func() error { _, err := f.Write(data); return err }},
		{stepSync, f.Sync},
		{stepChown, func() error { return f.Chown(int(owner.UID), int(owner.GID)) }},
		{stepChmod, func() error { return f.Chmod(mode) }},
		{stepClose, f.Close},
	} {
		if err := h.at(s.step); err != nil {
			return fail(s.step, err)
		}
		if err := s.do(); err != nil {
			return fail(s.step, err)
		}
	}
	if err := h.at(stepRename); err != nil {
		return fail(stepRename, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(stepRename, err)
	}
	committed = true
	after := func(step string, err error) error {
		return &WriteError{Path: path, Step: step, Committed: true, Err: err}
	}
	if err := h.at(stepSyncDir); err != nil {
		return after(stepSyncDir, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return after(stepSyncDir, err)
	}
	if err := h.at(stepReadBack); err != nil {
		return after(stepReadBack, err)
	}
	if err := readBack(path, data, mode, owner); err != nil {
		return after(stepReadBack, err)
	}
	return nil
}

// readBack opens path without following a link and requires a regular file
// of exactly owner and mode whose bytes hash to data's SHA-256.
func readBack(path string, data []byte, mode fs.FileMode, owner Owner) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: the file just written
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if serr := unix.Fstat(int(f.Fd()), &st); serr != nil {
		return serr
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || fs.FileMode(st.Mode&0o7777) != mode || st.Uid != owner.UID || st.Gid != owner.GID {
		return fmt.Errorf("%w: mode %04o, owner %d:%d", ErrReadBack, st.Mode&0o7777, st.Uid, st.Gid)
	}
	got, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil {
		return err
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		return fmt.Errorf("%w: the content differs", ErrReadBack)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the target's own directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Mkdir creates the directory path (its parent must exist) and gives it
// owner and mode on its own descriptor; a failure after the mkdir(2)
// removes it again.
func Mkdir(path string, mode fs.FileMode, owner Owner) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || mode&^fs.ModePerm != 0 {
		return fmt.Errorf("mkdir %s: not an absolute clean path with a permission-only mode", path)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	err := func() error {
		d, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: the directory just created
		if err != nil {
			return err
		}
		defer func() { _ = d.Close() }()
		if err := d.Chown(int(owner.UID), int(owner.GID)); err != nil {
			return err
		}
		if err := d.Chmod(mode); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(d.Fd()), &st); err != nil {
			return err
		}
		if fs.FileMode(st.Mode&0o7777) != mode || st.Uid != owner.UID || st.Gid != owner.GID {
			return fmt.Errorf("%w: directory mode %04o, owner %d:%d", ErrReadBack, st.Mode&0o7777, st.Uid, st.Gid)
		}
		return syncDir(filepath.Dir(path))
	}()
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	return nil
}

// Remove removes the file or empty directory path and fsyncs its parent.
func Remove(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// RemoveLeftovers removes the temp files a killed run left for target: in
// target's directory, each regular root-owned file whose name is a temp
// name for target's base name. It returns the paths removed. A matching
// name that is anything else is refused, and left for the operator.
func RemoveLeftovers(target string) ([]string, error) { return removeLeftovers(target, 0) }

// removeLeftovers is RemoveLeftovers for temp files owned by uid (tests use
// their own).
func removeLeftovers(target string, uid uint32) ([]string, error) {
	dir, base := filepath.Dir(target), filepath.Base(target)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var removed []string
	for _, e := range ents {
		if !IsTempFor(e.Name(), base) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			return removed, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.Mode().IsRegular() || !ok || st.Uid != uid {
			return removed, fmt.Errorf("%s looks like an install temp file but is not a regular root-owned file; remove it yourself", p)
		}
		if err := Remove(p); err != nil {
			return removed, err
		}
		removed = append(removed, p)
	}
	return removed, nil
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
func (s FileState) IsRegular() bool { return s.Exists && s.Mode.IsRegular() }

// IsDir reports a directory.
func (s FileState) IsDir() bool { return s.Exists && s.Mode.IsDir() }

// Perm is the permission bits with setuid, setgid and sticky.
func (s FileState) Perm() fs.FileMode {
	p := s.Mode.Perm()
	if s.Mode&fs.ModeSetuid != 0 {
		p |= 0o4000
	}
	if s.Mode&fs.ModeSetgid != 0 {
		p |= 0o2000
	}
	if s.Mode&fs.ModeSticky != 0 {
		p |= 0o1000
	}
	return p
}

// Same reports whether s is a regular file holding exactly data with mode
// and owner.
func (s FileState) Same(data []byte, mode fs.FileMode, owner Owner) bool {
	return s.IsRegular() && s.Perm() == mode && s.Owner == owner && bytes.Equal(s.Data, data)
}

// ErrTooLarge is a file over the caller's bound.
var ErrTooLarge = errors.New("file is larger than the bound")

// ReadState reads path without following a link: absent, or its kind,
// owner and mode, and for a regular file at most limit bytes (more is
// ErrTooLarge).
func ReadState(path string, limit int64) (FileState, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileState{}, fmt.Errorf("%s: no ownership information", path)
	}
	s := FileState{Exists: true, Mode: fi.Mode(), Owner: Owner{st.Uid, st.Gid}}
	if !fi.Mode().IsRegular() {
		return s, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) //nolint:gosec // G304: a path the installer manages
	if err != nil {
		return FileState{}, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return FileState{}, err
	}
	if int64(len(b)) > limit {
		return FileState{}, fmt.Errorf("%s: %w (%d bytes)", path, ErrTooLarge, limit)
	}
	s.Data = b
	return s, nil
}
