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
// system binary directories (following symlinks) whose name is hard-denied,
// is a built-in operation's binary (systemctl, journalctl, git) or is a
// D-Bus client (S4c-9). A match rejects the policy, naming the denied
// binary; the privileged helper scans its own names too. Multi-call binaries
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

// scanned reports whether the identity check compares binaries with files
// of this name: a hard-denied name, a built-in operation's binary or a D-Bus
// client (which may not be commands either), or one of extra.
func scanned(name string, extra []string) bool {
	if _, _, denied := hardDenied(name); denied {
		return true
	}
	return notCommand(name) || slices.Contains(extra, name) || slices.Contains(extra, CanonicalName(name))
}

// scanDenied lists the files under dirs whose names are scanned; each real
// directory is scanned once. Unreadable directories and entries are skipped
// (they cannot be the command's binary either: the gate would not be able to
// read it).
func scanDenied(dirs, extra []string) []*deniedFile {
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
			if !scanned(n, extra) {
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
	dirs, extra []string
	denied      []*deniedFile
}

// NewIdentityScan returns a scan of dirs (nil means DefaultSystemBinDirs)
// for the hard-denied names, the built-in operations' binaries, the D-Bus
// clients, and extra (the privileged helper's own names, N-13).
func NewIdentityScan(dirs []string, extra ...string) *IdentityScan {
	if dirs == nil {
		dirs = DefaultSystemBinDirs
	}
	return &IdentityScan{dirs: dirs, extra: slices.Clone(extra)}
}

// IdentityMatch is a scanned file a command binary is identical to: its
// name, its path, and its POLICY §5 group (0 when the name is not
// hard-denied).
type IdentityMatch struct {
	Name, Path string
	Group      int
	GroupName  string
}

// MatchAll compares the resolved command binary (fi from os.Stat) with every
// scanned file and returns each match, in directory and name order (a
// multi-call binary matches every name that runs it). It returns an error
// when a comparison is impossible (the check fails closed). Error messages
// name local paths and are for check-policy.
func (s *IdentityScan) MatchAll(resolved string, fi os.FileInfo) ([]IdentityMatch, error) {
	if s.denied == nil {
		s.denied = scanDenied(s.dirs, s.extra)
		if s.denied == nil {
			s.denied = []*deniedFile{}
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s has no inode information", resolved)
	}
	var sum *[32]byte
	var out []IdentityMatch
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
			out = append(out, IdentityMatch{Name: d.name, Path: d.path, Group: g, GroupName: gname})
		}
	}
	return out, nil
}

// identity compares the resolved command binary with every scanned file:
// identical to a hard-denied file, or to a built-in operation's binary or a
// D-Bus client, it is refused as that name would be. For the uutils
// multi-call binary (S-MC), which runs as the name of the file it is
// executed by, its other names are its other utilities and say nothing
// about this command; any other name is refused.
func (v *validator) identity(field, resolved string, fi os.FileInfo, opts *LoadOptions, uutils bool, via string) bool {
	if v.scan == nil {
		v.scan = NewIdentityScan(opts.SystemBinDirs)
	}
	ms, err := v.scan.MatchAll(resolved, fi)
	if err != nil {
		v.fail(field+".path", "%s%v", via, err)
		return false
	}
	if uutils {
		ms, err = UutilsSiblings(resolved, ms)
		if err != nil {
			v.fail(field+".path", "%s%v", via, err)
			return false
		}
	}
	for _, m := range ms {
		if m.Group > 0 {
			v.fail(field+".path", "%s%s is a hard link to, or a copy of, the hard-denied %q (%s; group %d: %s)", via, resolved, m.Name, m.Path, m.Group, m.GroupName)
			return false
		}
	}
	for _, m := range ms {
		if notCommand(m.Name) {
			v.fail(field+".path", "%s%s is a hard link to, or a copy of, %q (%s), which may not be a policy command", via, resolved, m.Name, m.Path)
			return false
		}
	}
	return true
}

// UutilsSiblings drops from a uutils binary's identity matches the names
// that are its own utilities, and refuses one under any other name: the
// uutils binary is never also a shell, or a renamed program of another
// package, and if it is, its names cannot be trusted.
func UutilsSiblings(resolved string, ms []IdentityMatch) ([]IdentityMatch, error) {
	for _, m := range ms {
		if !IsUutilsApplet(m.Name) {
			return nil, fmt.Errorf("%s is the uutils multi-call binary and is also reached as %q (%s), which is not one of its utilities", resolved, m.Name, m.Path)
		}
	}
	return nil, nil
}

// CheckFile checks an already-opened or stat'ed file: regular, owned by a
// trusted uid, not group/other-writable.
func CheckFile(t Trust, p string, fi os.FileInfo) error { return checkFile(t, p, fi) }
