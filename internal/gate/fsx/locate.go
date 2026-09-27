//go:build linux

package fsx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Bounds on walks.
const (
	maxScan      = 100000 // directory entries examined by one list/find/tree walk
	maxTreeDepth = 256    // nesting for recursive delete and move checks
	readDirChunk = 256
)

func errf(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// mapErr turns an OS error into an fsx error. Messages carry no content.
func mapErr(err error) *Error {
	var fe *Error
	switch {
	case errors.As(err, &fe):
		return fe
	case errors.Is(err, fs.ErrNotExist):
		return errf(protocol.CodeNotFound, "no such file or directory")
	case errors.Is(err, syscall.ENOTDIR):
		return errf(protocol.CodeNotADirectory, "a path component is not a directory")
	case errors.Is(err, syscall.EISDIR):
		return errf(protocol.CodeIsADirectory, "is a directory")
	case errors.Is(err, fs.ErrExist):
		return errf(protocol.CodeExists, "already exists")
	case errors.Is(err, syscall.ELOOP), strings.Contains(err.Error(), "path escapes from parent"):
		return errf(protocol.CodePathDenied, "path leaves its root or crosses a symlink")
	case errors.Is(err, fs.ErrPermission):
		return errf(protocol.CodePathDenied, "permission denied")
	case errors.Is(err, syscall.ENOTEMPTY):
		return errf(protocol.CodeBadRequest, "directory is not empty")
	case errors.Is(err, syscall.EXDEV):
		return errf(protocol.CodeBadRequest, "source and destination are on different filesystems")
	case errors.Is(err, syscall.EINVAL):
		return errf(protocol.CodeBadRequest, "invalid operation for this path")
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errf(protocol.CodeInternal, "filesystem error: %s", errno.Error())
	}
	return errf(protocol.CodeInternal, "filesystem error")
}

func join(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// realPathOfFile reads /proc/self/fd/N for an open file.
func realPathOfFile(f *os.File) (string, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	var p string
	var rerr error
	if err := sc.Control(func(fd uintptr) {
		p, rerr = os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10))
	}); err != nil {
		return "", err
	}
	if rerr != nil {
		return "", rerr
	}
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, " (deleted)") {
		return "", errf(protocol.CodePathDenied, "object has no stable path")
	}
	return p, nil
}

func realPathOfRoot(r *os.Root) (string, error) {
	f, err := r.Open(".")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return realPathOfFile(f)
}

// loc is a located target: its root (opened), and for anything but the root
// itself, its parent directory opened as a sub-root and verified.
type loc struct {
	p          string // requested path
	write      bool
	root       string // configured root
	rootReal   string
	top        *os.Root
	rel        string
	parent     *os.Root // nil when the target is the root itself
	parentReal string
	base       string
}

func (l *loc) close() {
	if l.parent != nil {
		_ = l.parent.Close()
	}
	if l.top != nil {
		_ = l.top.Close()
	}
}

// targetReal is where the target is (or would be) on disk.
func (l *loc) targetReal() string {
	if l.parent == nil {
		return l.rootReal
	}
	return join(l.parentReal, l.base)
}

func (f *FS) roots(write bool) []string {
	if write {
		return f.cfg.WriteRoots
	}
	return append(append([]string(nil), f.cfg.ReadRoots...), f.cfg.WriteRoots...)
}

// checkPath applies the deny list (and for writes the protected set) to a
// path, including its ancestors.
func (f *FS) checkPath(p string, write bool) *Error {
	if f.cfg.Deny.Covers(p) {
		return errf(protocol.CodePathDenied, "path is denied by policy")
	}
	if write && f.cfg.Protected.Covers(p) {
		return errf(protocol.CodePathDenied, "path is protected and never writable")
	}
	return nil
}

// checkReal re-checks a real path against the root and the lists, both as
// is and translated back under the configured root name (a root may itself
// be a symlink, and policy patterns name configured paths).
func (f *FS) checkReal(l *loc, real string, write bool) *Error {
	if !pathx.Within(l.rootReal, real) {
		return errf(protocol.CodePathDenied, "path resolves outside its root")
	}
	logical := l.root
	if real != l.rootReal {
		logical = join(l.root, pathx.Rel(l.rootReal, real))
	}
	if e := f.checkPath(real, write); e != nil {
		return e
	}
	return f.checkPath(logical, write)
}

// locate validates p, selects its root, opens it, and opens and verifies the
// parent directory.
func (f *FS) locate(p string, write bool) (*loc, error) {
	if err := pathx.CheckClean(p); err != nil {
		return nil, errf(protocol.CodeBadRequest, "path must be absolute and clean: %v", err)
	}
	root, ok := pathx.Longest(f.roots(write), p)
	if !ok {
		if write {
			return nil, errf(protocol.CodePathDenied, "path is outside the policy's write roots")
		}
		return nil, errf(protocol.CodePathDenied, "path is outside the policy's roots")
	}
	if e := f.checkPath(p, write); e != nil {
		return nil, e
	}
	top, err := os.OpenRoot(root)
	if err != nil {
		return nil, mapErr(err)
	}
	l := &loc{p: p, write: write, root: root, top: top, rel: pathx.Rel(root, p)}
	if l.rootReal, err = realPathOfRoot(top); err != nil {
		l.close()
		return nil, mapErr(err)
	}
	if l.rootReal == "/" || pathx.Within("/proc", l.rootReal) || pathx.Within("/sys", l.rootReal) ||
		pathx.Within("/dev", l.rootReal) || pathx.Within("/run", l.rootReal) {
		l.close()
		return nil, errf(protocol.CodePathDenied, "root resolves to a forbidden location")
	}
	if l.rel == "." {
		return l, nil
	}
	l.base = path.Base(l.rel)
	if l.parent, err = top.OpenRoot(path.Dir(l.rel)); err != nil {
		l.close()
		return nil, mapErr(err)
	}
	if l.parentReal, err = realPathOfRoot(l.parent); err != nil {
		l.close()
		return nil, mapErr(err)
	}
	if e := f.checkReal(l, l.parentReal, write); e != nil {
		l.close()
		return nil, e
	}
	if e := f.checkReal(l, l.targetReal(), write); e != nil {
		l.close()
		return nil, e
	}
	return l, nil
}

// lstat describes the target without following it.
func (l *loc) lstat() (fs.FileInfo, error) {
	if l.parent == nil {
		return l.top.Lstat(".")
	}
	return l.parent.Lstat(l.base)
}

// openTarget opens the target, refusing a final-component symlink, and
// verifies that the opened object is exactly parentReal/base (os.Root
// follows a final symlink within the root, so a symlink swapped in after
// the Lstat shows up here as a different real path).
func (f *FS) openTarget(l *loc, flags int) (*os.File, error) {
	var file *os.File
	var err error
	if l.parent == nil {
		file, err = l.top.OpenFile(".", flags, 0)
	} else {
		fi, lerr := l.parent.Lstat(l.base)
		if lerr != nil {
			return nil, mapErr(lerr)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, errf(protocol.CodePathDenied, "final path component is a symlink")
		}
		file, err = l.parent.OpenFile(l.base, flags, 0)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	real, err := realPathOfFile(file)
	if err != nil {
		_ = file.Close()
		return nil, mapErr(err)
	}
	if real != l.targetReal() {
		_ = file.Close()
		return nil, errf(protocol.CodePathDenied, "path changed while opening, or its final component is a symlink")
	}
	if e := f.checkReal(l, real, l.write); e != nil {
		_ = file.Close()
		return nil, e
	}
	return file, nil
}

// openDirRoot opens the target directory as an os.Root and verifies it.
// When the target is the root itself it returns l.top (not to be closed
// separately; close reports whether the caller must close it).
func (f *FS) openDirRoot(l *loc) (dir *os.Root, real string, owned bool, err error) {
	if l.parent == nil {
		return l.top, l.rootReal, false, nil
	}
	fi, err := l.parent.Lstat(l.base)
	if err != nil {
		return nil, "", false, mapErr(err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, "", false, errf(protocol.CodePathDenied, "final path component is a symlink")
	}
	if !fi.IsDir() {
		return nil, "", false, errf(protocol.CodeNotADirectory, "not a directory")
	}
	return f.openSubdir(l, l.parent, l.targetReal(), l.base)
}

// openSubdir opens name inside dir as an os.Root and requires its real path
// to be exactly want.
func (f *FS) openSubdir(l *loc, dir *os.Root, want, name string) (*os.Root, string, bool, error) {
	sub, err := dir.OpenRoot(name)
	if err != nil {
		return nil, "", false, mapErr(err)
	}
	real, err := realPathOfRoot(sub)
	if err != nil {
		_ = sub.Close()
		return nil, "", false, mapErr(err)
	}
	if real != want {
		_ = sub.Close()
		return nil, "", false, errf(protocol.CodePathDenied, "directory changed while opening, or is a symlink")
	}
	if e := f.checkReal(l, real, l.write); e != nil {
		_ = sub.Close()
		return nil, "", false, e
	}
	return sub, real, true, nil
}

// names resolves owner and group names with a per-call cache.
type names struct {
	mu     sync.Mutex
	users  map[uint32]string
	groups map[uint32]string
}

func newNames() *names { return &names{users: map[uint32]string{}, groups: map[uint32]string{}} }

func (n *names) user(uid uint32) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if s, ok := n.users[uid]; ok {
		return s
	}
	s := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		s = u.Username
	}
	n.users[uid] = s
	return s
}

func (n *names) group(gid uint32) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if s, ok := n.groups[gid]; ok {
		return s
	}
	s := ""
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil {
		s = g.Name
	}
	n.groups[gid] = s
	return s
}

// unixMode returns the permission and special bits of fi as a Unix mode.
func unixMode(fi fs.FileInfo) uint32 {
	m := fi.Mode()
	bits := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

func typeOf(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	}
	return "other"
}

func entryOf(p, name string, fi fs.FileInfo, n *names) Entry {
	e := Entry{
		Path:  p,
		Name:  name,
		Type:  typeOf(fi.Mode()),
		Size:  fi.Size(),
		Mode:  fmt.Sprintf("%04o", unixMode(fi)),
		MTime: fi.ModTime().UTC().Format(time.RFC3339),
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.UID, e.GID = st.Uid, st.Gid
		e.Owner, e.Group = n.user(st.Uid), n.group(st.Gid)
	}
	return e
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on Linux
	return hex.EncodeToString(b)
}

// checkMode applies the gate's mode rules.
func checkMode(m os.FileMode) *Error {
	if m&^os.ModePerm != 0 {
		return errf(protocol.CodePolicyDenied, "setuid, setgid and sticky bits are not allowed")
	}
	if m&0o002 != 0 {
		return errf(protocol.CodePolicyDenied, "world-writable modes are not allowed")
	}
	return nil
}

// ParseMode parses an octal mode string ("0640" or "640") and applies the
// gate's mode rules: permission bits only, no setuid/setgid/sticky, no
// world-write.
func ParseMode(s string) (os.FileMode, error) {
	if len(s) < 3 || len(s) > 4 {
		return 0, errf(protocol.CodeBadRequest, "mode must be 3 or 4 octal digits")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return 0, errf(protocol.CodeBadRequest, "mode must be 3 or 4 octal digits")
		}
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, errf(protocol.CodeBadRequest, "mode must be 3 or 4 octal digits")
	}
	m := os.FileMode(v)
	if e := checkMode(m); e != nil {
		return 0, e
	}
	return m, nil
}
