//go:build linux

package policy

import (
	"crypto/sha256"
	"errors"
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

// identity compares the resolved command binary with every denied file.
func (v *validator) identity(field, resolved string, fi os.FileInfo, opts *LoadOptions) bool {
	if v.denied == nil {
		dirs := opts.SystemBinDirs
		if dirs == nil {
			dirs = DefaultSystemBinDirs
		}
		v.denied = scanDenied(dirs)
		if v.denied == nil {
			v.denied = []*deniedFile{}
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		v.fail(field+".path", "%s has no inode information", resolved)
		return false
	}
	var sum *[32]byte
	for _, d := range v.denied {
		same := d.dev == st.Dev && d.ino == st.Ino
		if !same && d.size == fi.Size() {
			var err error
			if sum == nil {
				if sum, err = fileSum(resolved, fi.Size()); err != nil {
					v.fail(field+".path", "%s cannot be compared with hard-denied binaries: %v", resolved, errReason(err))
					return false
				}
			}
			if d.sum == nil {
				if d.sum, err = fileSum(d.path, d.size); err != nil {
					v.fail(field+".path", "%s cannot be compared with hard-denied %q (%s): %v", resolved, d.name, d.path, errReason(err))
					return false
				}
			}
			same = *sum == *d.sum
		}
		if same {
			g, gname, _ := hardDenied(d.name)
			v.fail(field+".path", "%s is a hard link to, or a copy of, the hard-denied %q (%s; group %d: %s)", resolved, d.name, d.path, g, gname)
			return false
		}
	}
	return true
}
