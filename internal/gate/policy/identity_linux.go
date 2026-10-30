//go:build linux

package policy

import (
	"cmp"
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
			isScanned, isListed := scanned(n, extra), listedOf(n) != "" || isRangeProgram(CanonicalName(n))
			if !isScanned && !isListed {
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
			out = append(out, &deniedFile{name: n, path: p, dev: st.Dev, ino: st.Ino, size: fi.Size(), scanned: isScanned, listed: isListed})
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
	content     ContentCache
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
	id, err := s.Match(resolved, fi)
	return id.Scanned, err
}

// Identity is what a command binary is identical to among the scanned
// files.
type Identity struct {
	// Scanned are the matches with the files the check refuses or
	// classifies (MatchAll).
	Scanned []IdentityMatch
	// Listed are the GTFOBins-listed and range programs (keyrange.go) it is
	// identical to, by their canonical names (handoff N-33, N-35), in
	// directory and name order.
	Listed []ListedMatch
	// Skipped is why a comparison with a listed program's file was
	// impossible, or nil. It never fails the check: the GTFOBins warning
	// is an aid, and a listed file the check cannot read is only not
	// compared.
	Skipped error
}

// Match compares the resolved command binary (fi from os.Stat) with every
// scanned file. A comparison with a file the check refuses or classifies
// that is impossible is an error (it fails closed); one with a listed
// program's file that is not also one of those is recorded in Skipped.
func (s *IdentityScan) Match(resolved string, fi os.FileInfo) (Identity, error) {
	if s.denied == nil {
		s.denied = scanDenied(s.dirs, s.extra)
		if s.denied == nil {
			s.denied = []*deniedFile{}
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, fmt.Errorf("%s has no inode information", resolved)
	}
	var (
		sum    *[32]byte
		sumErr error
		out    Identity
	)
	for _, d := range s.denied {
		same := d.dev == st.Dev && d.ino == st.Ino
		if !same && d.size == fi.Size() {
			if sum == nil && sumErr == nil {
				sum, sumErr = fileSum(resolved, fi.Size())
			}
			if sumErr == nil && d.sum == nil && d.sumErr == nil {
				d.sum, d.sumErr = fileSum(d.path, d.size)
			}
			switch {
			case sumErr != nil && d.scanned:
				return Identity{}, fmt.Errorf("%s cannot be compared with hard-denied binaries: %v", resolved, errReason(sumErr))
			case sumErr != nil:
				out.Skipped = cmp.Or(out.Skipped, fmt.Errorf("%s cannot be compared with the listed %q (%s): %v", resolved, d.name, d.path, errReason(sumErr)))
				continue
			case d.sumErr != nil && d.scanned:
				return Identity{}, fmt.Errorf("%s cannot be compared with hard-denied %q (%s): %v", resolved, d.name, d.path, errReason(d.sumErr))
			case d.sumErr != nil:
				out.Skipped = cmp.Or(out.Skipped, fmt.Errorf("%s cannot be compared with the listed %q (%s): %v", resolved, d.name, d.path, errReason(d.sumErr)))
				continue
			}
			same = *sum == *d.sum
		}
		if !same {
			continue
		}
		if d.scanned {
			g, gname, _ := hardDenied(d.name)
			out.Scanned = append(out.Scanned, IdentityMatch{Name: d.name, Path: d.path, Group: g, GroupName: gname})
		}
		if d.listed {
			out.Listed = append(out.Listed, ListedMatch{Name: CanonicalName(d.name), Kind: MatchKindIdentity, Detail: "identical to " + d.path})
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
//
// It returns the GTFOBins-listed programs the binary is identical to (N-33;
// none for the uutils binary, which runs as the name it is executed by and
// whose own name the warning already checks) and whether it passed.
func (v *validator) identity(field, resolved string, fi os.FileInfo, opts *LoadOptions, uutils bool, via string) ([]ListedMatch, bool) {
	if v.scan == nil {
		v.scan = NewIdentityScan(opts.SystemBinDirs)
	}
	id, err := v.scan.Match(resolved, fi)
	if err != nil {
		v.fail(field+".path", "%s%v", via, err)
		return nil, false
	}
	ms := id.Scanned
	if uutils {
		ms, err = UutilsSiblings(resolved, ms)
		if err != nil {
			v.fail(field+".path", "%s%v", via, err)
			return nil, false
		}
		id.Listed = nil
	}
	for _, m := range ms {
		if m.Group > 0 {
			v.fail(field+".path", "%s%s is a hard link to, or a copy of, the hard-denied %q (%s; group %d: %s)", via, resolved, m.Name, m.Path, m.Group, m.GroupName)
			return nil, false
		}
	}
	for _, m := range ms {
		if notCommand(m.Name) {
			v.fail(field+".path", "%s%s is a hard link to, or a copy of, %q (%s), which may not be a policy command", via, resolved, m.Name, m.Path)
			return nil, false
		}
	}
	if id.Skipped != nil {
		v.warn("%s: %s%v; a renamed copy of a GTFOBins-listed program is not recognised by identity here (POLICY §6)", field, via, id.Skipped)
	}
	return id.Listed, true
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

// Content returns what the file at p (described by fi, from os.Stat) holds,
// read once per load for each device, inode, size, modification and change
// time (ContentCache).
func (s *IdentityScan) Content(p string, fi os.FileInfo) (Content, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Content{}, fmt.Errorf("has no inode information")
	}
	if s.content == nil {
		s.content = ContentCache{}
	}
	return s.content.Probe(p, FileKey{Dev: st.Dev, Ino: st.Ino, Size: fi.Size(), Mtime: st.Mtim.Nano(), Ctime: st.Ctim.Nano()})
}

// probe is Content through the validator's scan, made on first use.
func (v *validator) probe(p string, fi os.FileInfo, opts *LoadOptions) (Content, error) {
	if v.scan == nil {
		v.scan = NewIdentityScan(opts.SystemBinDirs)
	}
	return v.scan.Content(p, fi)
}
