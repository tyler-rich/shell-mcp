//go:build linux

// Package procself reads this process's own /proc/<pid> through a
// descriptor opened before the Landlock sandbox is applied and kept for the
// process's life (PRIVILEGED §5.1, "The helper's own /proc/<pid>").
//
// The privileged helper's core unit grants Landlock read access to its own
// /proc/<pid> only, as a rule on that directory. A Landlock rule holds the
// directory's inode, not its dentry: under memory-cgroup pressure the
// kernel may reclaim the unused dentry of /proc/<pid>, and the next lookup
// of the path makes a new dentry with a new procfs inode that the rule does
// not cover, so every later read through the path is EACCES. A descriptor
// kept open pins the dentry, and reads made relative to it (openat(2),
// readlinkat(2)) walk from it, so the rule keeps covering them.
package procself

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Self is this process's own procfs directory.
const Self = "/proc/self"

// maxName bounds a name read under the directory.
const maxName = 256

// Dir is an open O_PATH descriptor of a /proc/<pid> directory (or, in
// tests, of a directory laid out like one). It is safe for concurrent use;
// it is never closed in production.
type Dir struct {
	fd   int
	path string
}

// Open opens /proc/self, resolved to this process's /proc/<pid>, as an
// O_PATH directory descriptor. Call it before the Landlock sandbox is
// applied: afterwards the open itself may be refused.
func Open() (*Dir, error) { return OpenDir(Self) }

// OpenDir opens dir as Open opens /proc/self; tests pass a directory of
// their own.
func OpenDir(dir string) (*Dir, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return &Dir{fd: fd, path: dir}, nil
}

// Path is the directory as it was opened, for messages.
func (d *Dir) Path() string { return d.path }

// Close closes the descriptor (tests only; production keeps it).
func (d *Dir) Close() error { return unix.Close(d.fd) }

// ValidName reports whether name is a relative path the Dir reads: one to
// eight components separated by "/", none empty, "." or "..", each at most
// maxName bytes of printable ASCII other than "/". Names are the callers'
// constants with thread ids and descriptor numbers, never request input;
// this keeps a read inside the directory even if one were not.
func ValidName(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) > 8 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > maxName {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] <= ' ' || p[i] > '~' {
				return false
			}
		}
	}
	return true
}

func (d *Dir) name(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("procself: %q is not a name under %s", name, d.path)
	}
	return nil
}

// ReadFile reads the file name under the directory, at most limit bytes;
// a longer file is an error.
func (d *Dir) ReadFile(name string, limit int64) ([]byte, error) {
	f, err := d.open(name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s/%s: longer than %d bytes", d.path, name, limit)
	}
	return b, nil
}

// ReadDirNames lists the directory name under the directory, at most limit
// entries; more is an error.
func (d *Dir) ReadDirNames(name string, limit int) ([]string, error) {
	f, err := d.open(name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		return nil, fmt.Errorf("%s/%s: more than %d entries", d.path, name, limit)
	}
	return names, nil
}

// Readlink reads the symbolic link name under the directory (fd/N: an open
// descriptor's path).
func (d *Dir) Readlink(name string) (string, error) {
	if err := d.name(name); err != nil {
		return "", err
	}
	buf := make([]byte, unix.PathMax)
	n, err := d.readlinkat(name, buf)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: d.path + "/" + name, Err: err}
	}
	if n == len(buf) {
		return "", &os.PathError{Op: "readlink", Path: d.path + "/" + name, Err: unix.ENAMETOOLONG}
	}
	return string(buf[:n]), nil
}

func (d *Dir) open(name string, flags int) (*os.File, error) {
	if err := d.name(name); err != nil {
		return nil, err
	}
	fd, err := d.openat(name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: d.path + "/" + name, Err: err}
	}
	return os.NewFile(uintptr(fd), d.path+"/"+name), nil
}

// openat and readlinkat are the two primitives every read goes through:
// relative to the descriptor, never through the path it was opened by.
func (d *Dir) openat(name string, flags int) (int, error) {
	return unix.Openat(d.fd, name, flags, 0)
}

func (d *Dir) readlinkat(name string, buf []byte) (int, error) {
	return unix.Readlinkat(d.fd, name, buf)
}
