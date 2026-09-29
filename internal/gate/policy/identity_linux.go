//go:build linux

package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// Binary identity check. A hard link or a copy gives a hard-denied binary
// an innocent name that the base-name check (POLICY §5) cannot see. After a
// command's binary is resolved, it is compared by device + inode, and by
// SHA-256 when the sizes match, with every file found under the standard
// system binary directories (following symlinks) whose name is hard-denied.
// A match rejects the policy, naming the denied binary. Multi-call binaries
// that a denied name links to (for example a firewall or module tool
// reached through several names) are therefore refused under any name.

// Bounds on the scan.
const (
	maxBinDirEntries = 1 << 16
	maxIdentityBytes = 1 << 30 // larger same-size candidates fail closed
)

// errIdentityTooLarge fails the check closed for oversized candidates.
var errIdentityTooLarge = errors.New("too large to compare")

func fileSum(p string, size int64) (*[32]byte, error) {
	if size > maxIdentityBytes {
		return nil, errIdentityTooLarge
	}
	f, err := os.Open(p) //nolint:gosec // G304: a resolved command binary or a file in a system binary directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, size+1)); err != nil {
		return nil, err
	}
	var s [32]byte
	copy(s[:], h.Sum(nil))
	return &s, nil
}

// scanDenied lists the hard-denied files under dirs; each real directory is
// scanned once. Unreadable directories and entries are skipped (they cannot
// be the command's binary either: the gate would not be able to read it).
func scanDenied(dirs []string) []*deniedFile {
	var out []*deniedFile
	seen := map[string]bool{}
	for _, d := range dirs {
		rd, err := filepath.EvalSymlinks(d)
		if err != nil || seen[rd] {
			continue
		}
		seen[rd] = true
		f, err := os.Open(rd)
		if err != nil {
			continue
		}
		names, _ := f.Readdirnames(maxBinDirEntries)
		_ = f.Close()
		slices.Sort(names)
		for _, n := range names {
			if _, _, denied := hardDenied(n); !denied {
				continue
			}
			p := filepath.Join(rd, n)
			fi, err := os.Stat(p) // follows symlinks: the file the name runs
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			out = append(out, &deniedFile{name: n, path: p, dev: st.Dev, ino: st.Ino, size: fi.Size()})
		}
	}
	return out
}

// IdentityScan is the binary identity check's scan of the system binary
// directories, made lazily once per policy load and shared by every
// command of that load.
type IdentityScan struct {
	dirs   []string
	denied []*deniedFile
}

// NewIdentityScan returns a scan of dirs (nil means DefaultSystemBinDirs).
func NewIdentityScan(dirs []string) *IdentityScan {
	if dirs == nil {
		dirs = DefaultSystemBinDirs
	}
	return &IdentityScan{dirs: dirs}
}

// DeniedMatch is the hard-denied file a command binary is identical to.
type DeniedMatch struct {
	Name, Path string
	Group      int
	GroupName  string
}

// Match compares the resolved command binary (fi from os.Stat) with every
// hard-denied file. It returns nil when nothing matches, and an error when
// a comparison is impossible (the check fails closed). Error messages name
// local paths and are for check-policy.
func (s *IdentityScan) Match(resolved string, fi os.FileInfo) (*DeniedMatch, error) {
	if s.denied == nil {
		s.denied = scanDenied(s.dirs)
		if s.denied == nil {
			s.denied = []*deniedFile{}
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s has no inode information", resolved)
	}
	var sum *[32]byte
	for _, d := range s.denied {
		same := d.dev == st.Dev && d.ino == st.Ino
		if !same && d.size == fi.Size() {
			var err error
			if sum == nil {
				if sum, err = fileSum(resolved, fi.Size()); err != nil {
					return nil, fmt.Errorf("%s cannot be compared with hard-denied binaries: %v", resolved, errReason(err))
				}
			}
			if d.sum == nil {
				if d.sum, err = fileSum(d.path, d.size); err != nil {
					return nil, fmt.Errorf("%s cannot be compared with hard-denied %q (%s): %v", resolved, d.name, d.path, errReason(err))
				}
			}
			same = *sum == *d.sum
		}
		if same {
			g, gname, _ := hardDenied(d.name)
			return &DeniedMatch{Name: d.name, Path: d.path, Group: g, GroupName: gname}, nil
		}
	}
	return nil, nil
}

// identity compares the resolved command binary with every denied file.
func (v *validator) identity(field, resolved string, fi os.FileInfo, opts *LoadOptions) bool {
	if v.scan == nil {
		v.scan = NewIdentityScan(opts.SystemBinDirs)
	}
	m, err := v.scan.Match(resolved, fi)
	if err != nil {
		v.fail(field+".path", "%v", err)
		return false
	}
	if m != nil {
		v.fail(field+".path", "%s is a hard link to, or a copy of, the hard-denied %q (%s; group %d: %s)", resolved, m.Name, m.Path, m.Group, m.GroupName)
		return false
	}
	return true
}

// CheckFile checks an already-opened or stat'ed file: regular, owned by a
// trusted uid, not group/other-writable.
func CheckFile(t Trust, p string, fi os.FileInfo) error { return checkFile(t, p, fi) }
