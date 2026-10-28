//go:build linux

package fsx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
	"github.com/tyler-rich/shell-mcp/internal/redact"
)

const (
	sniffKeyBytes    = 64 << 10  // private-key header search (POLICY §3)
	sniffTextBytes   = 8 << 10   // binary detection
	defaultReadBytes = 64 << 10  // read_file default max_bytes
	maxTailLines     = 5000      // read_file tail_lines ceiling
	maxHashBytes     = 256 << 20 // whole-file SHA-256 (and key search) only up to this size
	keyLookback      = 1 << 20   // above that size: key search before a read window
	keyScanOverlap   = 4 << 10   // bytes kept between chunks, so a header cannot straddle one unseen
	defaultFindDepth = 4
	defaultFindLimit = 200
)

// Stat describes p without following a final symlink.
func (f *FS) Stat(p string) (Entry, error) {
	l, err := f.locate(p, false)
	if err != nil {
		return Entry{}, err
	}
	defer l.close()
	fi, err := l.lstat()
	if err != nil {
		return Entry{}, mapErr(err)
	}
	e := entryOf(p, path.Base(p), fi, newNames())
	if fi.Mode()&fs.ModeSymlink != 0 && l.parent != nil {
		if target, err := l.parent.Readlink(l.base); err == nil {
			e.LinkTarget = target
		}
	}
	return e, nil
}

// ListDir lists the directory p. Entries covered by the deny list are left
// out; symlink targets are reported, never followed.
func (f *FS) ListDir(p string, includeHidden bool, limit int) (ListResult, error) {
	if limit < 1 || limit > MaxListEntries {
		return ListResult{}, errf(protocol.CodeBadRequest, "limit must be 1..%d", MaxListEntries)
	}
	l, err := f.locate(p, false)
	if err != nil {
		return ListResult{}, err
	}
	defer l.close()
	dir, dirReal, owned, err := f.openDirRoot(l)
	if err != nil {
		return ListResult{}, err
	}
	if owned {
		defer func() { _ = dir.Close() }()
	}
	d, err := dir.Open(".")
	if err != nil {
		return ListResult{}, mapErr(err)
	}
	defer func() { _ = d.Close() }()
	res := ListResult{Path: p, Entries: []Entry{}}
	n := newNames()
	scanned := 0
	for {
		ents, rerr := d.ReadDir(readDirChunk)
		for _, en := range ents {
			scanned++
			name := en.Name()
			if !includeHidden && strings.HasPrefix(name, ".") {
				continue
			}
			if f.cfg.Deny.Covers(join(p, name)) || f.cfg.Deny.Covers(join(dirReal, name)) {
				continue
			}
			if len(res.Entries) == limit {
				res.Truncated = true
				return res, nil
			}
			info, err := en.Info()
			if err != nil {
				continue // removed while listing
			}
			e := entryOf(join(p, name), name, info, n)
			if e.Type == "symlink" {
				if t, err := dir.Readlink(name); err == nil {
					e.LinkTarget = t
				}
			}
			res.Entries = append(res.Entries, e)
		}
		if errors.Is(rerr, io.EOF) || len(ents) == 0 {
			return res, nil
		}
		if rerr != nil {
			return ListResult{}, mapErr(rerr)
		}
		if scanned >= maxScan {
			res.Truncated = true
			return res, nil
		}
	}
}

// validPrefix trims an incomplete UTF-8 sequence cut off at the end of b.
func validPrefix(b []byte) []byte {
	for k := 0; k <= 3 && k <= len(b); k++ {
		if utf8.Valid(b[:len(b)-k]) {
			return b[:len(b)-k]
		}
	}
	return b
}

// keyScan is an io.Writer that notes whether the bytes written through it hold
// a private-key header, including one split between two writes.
type keyScan struct {
	tail  []byte
	found bool
}

func (k *keyScan) Write(p []byte) (int, error) {
	if k.found {
		return len(p), nil
	}
	buf := append(k.tail, p...) //nolint:gocritic // appendAssign: tail is replaced below
	if redact.ContainsPrivateKey(buf) {
		k.found = true
		k.tail = nil
		return len(p), nil
	}
	k.tail = bytes.Clone(buf[max(0, len(buf)-keyScanOverlap):])
	return len(p), nil
}

// holdsKey reports whether file holds a private-key header in [from, to) or,
// for the first sniffKeyBytes, always. Both ranges are clamped to the file.
func holdsKey(file io.ReaderAt, size, from, to int64) (bool, error) {
	k := &keyScan{}
	for _, r := range [][2]int64{{0, min(size, sniffKeyBytes)}, {max(0, from-keyLookback), min(size, to)}} {
		if r[1] <= r[0] {
			continue
		}
		if _, err := io.Copy(k, io.NewSectionReader(file, r[0], r[1]-r[0])); err != nil {
			return false, mapErr(err)
		}
		if k.found {
			return true, nil
		}
		k.tail = nil
	}
	return false, nil
}

// ReadFile reads the regular file p. A file holding a private-key header
// anywhere is refused, so a window that starts inside a key's body cannot
// return the body without its header (S7-1): up to maxHashBytes the
// whole file is searched, in the same pass as its SHA-256; above that the
// first 64 KiB, the window and the keyLookback bytes before it. Binary files
// (NUL or invalid UTF-8 in the first 8 KiB) return size and SHA-256 only.
func (f *FS) ReadFile(p string, o ReadOptions) (ReadResult, error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = min(defaultReadBytes, f.cfg.Limits.MaxReadBytes)
	}
	switch {
	case o.MaxBytes < 1 || o.MaxBytes > f.cfg.Limits.MaxReadBytes:
		return ReadResult{}, errf(protocol.CodeBadRequest, "max_bytes must be 1..%d", f.cfg.Limits.MaxReadBytes)
	case o.Offset < 0:
		return ReadResult{}, errf(protocol.CodeBadRequest, "offset must not be negative")
	case o.TailLines < 0 || o.TailLines > maxTailLines:
		return ReadResult{}, errf(protocol.CodeBadRequest, "tail_lines must be 1..%d", maxTailLines)
	case o.TailLines > 0 && o.Offset > 0:
		return ReadResult{}, errf(protocol.CodeBadRequest, "offset and tail_lines are mutually exclusive")
	}
	l, err := f.locate(p, false)
	if err != nil {
		return ReadResult{}, err
	}
	defer l.close()
	file, err := f.openTarget(l)
	if err != nil {
		return ReadResult{}, err
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil {
		return ReadResult{}, mapErr(err)
	}
	if fi.IsDir() {
		return ReadResult{}, errf(protocol.CodeIsADirectory, "is a directory")
	}
	if !fi.Mode().IsRegular() {
		return ReadResult{}, errf(protocol.CodeBadRequest, "not a regular file")
	}
	// Another account could have moved the file in: it is read only when
	// that account could read it itself (PRIVILEGED §6, handoff N-7).
	if err := f.movedInRead(l, fi); err != nil {
		return ReadResult{}, err
	}
	size := fi.Size()
	head := make([]byte, min(int64(sniffKeyBytes), size))
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, size), head); err != nil {
		return ReadResult{}, mapErr(err)
	}
	res := ReadResult{Path: p, Size: size}
	if size <= maxHashBytes {
		h, k := sha256.New(), &keyScan{}
		if _, err := io.Copy(io.MultiWriter(h, k), io.NewSectionReader(file, 0, size)); err != nil {
			return ReadResult{}, mapErr(err)
		}
		if k.found {
			return ReadResult{}, errf(protocol.CodePathDenied, "file contains a private key")
		}
		res.SHA256 = hex.EncodeToString(h.Sum(nil))
	} else {
		from, to := o.Offset, o.Offset+int64(o.MaxBytes)
		if o.TailLines > 0 {
			from, to = size-int64(o.MaxBytes), size
		}
		found, err := holdsKey(file, size, from, to)
		if err != nil {
			return ReadResult{}, err
		}
		if found {
			return ReadResult{}, errf(protocol.CodePathDenied, "file contains a private key")
		}
	}
	sniff := head[:min(len(head), sniffTextBytes)]
	if len(sniff) < len(head) || int64(len(head)) < size {
		sniff = validPrefix(sniff)
	}
	if bytes.IndexByte(sniff, 0) >= 0 || !utf8.Valid(sniff) {
		res.Binary = true
		return res, nil
	}
	if o.TailLines > 0 {
		start := max(0, size-int64(o.MaxBytes))
		buf := make([]byte, size-start)
		if _, err := io.ReadFull(io.NewSectionReader(file, start, size-start), buf); err != nil {
			return ReadResult{}, mapErr(err)
		}
		if start > 0 {
			// Drop the partial first line.
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				buf = buf[i+1:]
			} else {
				buf = nil
			}
		}
		lines := bytes.SplitAfter(buf, []byte("\n"))
		if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > o.TailLines {
			lines = lines[len(lines)-o.TailLines:]
			res.Truncated = true
		}
		content := bytes.Join(lines, nil)
		res.Truncated = res.Truncated || start > 0
		res.Content = string(content)
		res.Offset = size - int64(len(content))
		return res, nil
	}
	res.Offset = o.Offset
	if o.Offset >= size {
		return res, nil
	}
	n := min(int64(o.MaxBytes), size-o.Offset)
	buf := make([]byte, n)
	if _, err := io.ReadFull(io.NewSectionReader(file, o.Offset, n), buf); err != nil {
		return ReadResult{}, mapErr(err)
	}
	if o.Offset+n < size {
		buf = validPrefix(buf)
		res.Truncated = true
	}
	res.Content = string(buf)
	return res, nil
}

// HashResult is a regular file's size, SHA-256 and line count, and whether
// its first 64 KiB hold a private-key header: never its content (handoff
// N-5, the helper's priv_hash_file).
type HashResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Binary bool   `json:"binary"`
	// Lines is counted as a preview over read_file's default read did:
	// for a text file no larger than that read (64 KiB, or max_read_bytes
	// when smaller); nil otherwise.
	Lines      *int `json:"lines"`
	PrivateKey bool `json:"private_key"`
}

// HashFile hashes the regular file p under ReadFile's path rules (roots,
// deny lists, symlinks, the moved-in read rule) without returning any of
// its content, so a file holding a private key can be bound by its hash.
// Files above 256 MiB are refused (too_large).
func (f *FS) HashFile(p string) (HashResult, error) {
	l, err := f.locate(p, false)
	if err != nil {
		return HashResult{}, err
	}
	defer l.close()
	file, err := f.openTarget(l)
	if err != nil {
		return HashResult{}, err
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil {
		return HashResult{}, mapErr(err)
	}
	if fi.IsDir() {
		return HashResult{}, errf(protocol.CodeIsADirectory, "is a directory")
	}
	if !fi.Mode().IsRegular() {
		return HashResult{}, errf(protocol.CodeBadRequest, "not a regular file")
	}
	if err := f.movedInRead(l, fi); err != nil {
		return HashResult{}, err
	}
	size := fi.Size()
	if size > maxHashBytes {
		return HashResult{}, errf(protocol.CodeTooLarge, "the file is larger than the %d MiB the helper hashes", maxHashBytes>>20)
	}
	head := make([]byte, min(int64(sniffKeyBytes), size))
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, size), head); err != nil {
		return HashResult{}, mapErr(err)
	}
	h, k := sha256.New(), &keyScan{}
	if _, err := io.Copy(io.MultiWriter(h, k), io.NewSectionReader(file, 0, size)); err != nil {
		return HashResult{}, mapErr(err)
	}
	res := HashResult{Path: p, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), PrivateKey: k.found}
	sniff := head[:min(len(head), sniffTextBytes)]
	if len(sniff) < len(head) || int64(len(head)) < size {
		sniff = validPrefix(sniff)
	}
	res.Binary = bytes.IndexByte(sniff, 0) >= 0 || !utf8.Valid(sniff)
	if !res.Binary && size <= int64(min(defaultReadBytes, f.cfg.Limits.MaxReadBytes)) {
		// A file this small is all in head.
		lines := bytes.Count(head, []byte("\n"))
		if len(head) > 0 && head[len(head)-1] != '\n' {
			lines++
		}
		res.Lines = &lines
	}
	return res, nil
}

// Find walks the directory p: bounded depth, results and entries examined;
// symlinked directories are never followed; denied entries are skipped and
// not descended into.
func (f *FS) Find(p string, o FindOptions) (FindResult, error) {
	if o.MaxDepth == 0 {
		o.MaxDepth = min(defaultFindDepth, f.cfg.Limits.MaxFindDepth)
	}
	if o.Limit == 0 {
		o.Limit = min(defaultFindLimit, f.cfg.Limits.MaxFindResults)
	}
	switch {
	case o.MaxDepth < 1 || o.MaxDepth > f.cfg.Limits.MaxFindDepth:
		return FindResult{}, errf(protocol.CodeBadRequest, "max_depth must be 1..%d", f.cfg.Limits.MaxFindDepth)
	case o.Limit < 1 || o.Limit > f.cfg.Limits.MaxFindResults:
		return FindResult{}, errf(protocol.CodeBadRequest, "limit must be 1..%d", f.cfg.Limits.MaxFindResults)
	case o.Type != "" && o.Type != "file" && o.Type != "dir" && o.Type != "symlink":
		return FindResult{}, errf(protocol.CodeBadRequest, "type must be file, dir or symlink")
	case o.ModifiedWithinS < 0:
		return FindResult{}, errf(protocol.CodeBadRequest, "modified_within_s must not be negative")
	}
	if o.NameGlob != "" {
		if _, err := path.Match(o.NameGlob, ""); err != nil || strings.Contains(o.NameGlob, "/") || len(o.NameGlob) > 256 {
			return FindResult{}, errf(protocol.CodeBadRequest, "name_glob is malformed")
		}
	}
	l, err := f.locate(p, false)
	if err != nil {
		return FindResult{}, err
	}
	defer l.close()
	dir, dirReal, owned, err := f.openDirRoot(l)
	if err != nil {
		return FindResult{}, err
	}
	if owned {
		defer func() { _ = dir.Close() }()
	}
	w := &finder{f: f, l: l, o: o, n: newNames(), res: FindResult{Path: p, Entries: []Entry{}}}
	if o.ModifiedWithinS > 0 {
		w.since = time.Now().Add(-time.Duration(o.ModifiedWithinS) * time.Second)
	}
	if err := w.walk(dir, p, dirReal, 1); err != nil && !errors.Is(err, errStop) {
		return FindResult{}, err
	}
	return w.res, nil
}

var errStop = errors.New("stop")

type finder struct {
	f       *FS
	l       *loc
	o       FindOptions
	n       *names
	since   time.Time
	scanned int
	res     FindResult
}

func (w *finder) walk(dir *os.Root, logical, dirReal string, depth int) error {
	d, err := dir.Open(".")
	if err != nil {
		return nil // unreadable directory: skip
	}
	defer func() { _ = d.Close() }()
	for {
		ents, rerr := d.ReadDir(readDirChunk)
		for _, en := range ents {
			w.scanned++
			if w.scanned > maxScan {
				w.res.Truncated = true
				return errStop
			}
			name := en.Name()
			lp, rp := join(logical, name), join(dirReal, name)
			if w.f.cfg.Deny.Covers(lp) || w.f.cfg.Deny.Covers(rp) {
				continue
			}
			info, err := en.Info()
			if err != nil {
				continue
			}
			if w.match(name, info) {
				if len(w.res.Entries) == w.o.Limit {
					w.res.Truncated = true
					return errStop
				}
				w.res.Entries = append(w.res.Entries, entryOf(lp, name, info, w.n))
			}
			if info.IsDir() && depth < w.o.MaxDepth {
				sub, subReal, _, err := w.f.openSubdir(w.l, dir, rp, name)
				if err != nil {
					continue // swapped for a symlink, or denied: skip
				}
				err = w.walk(sub, lp, subReal, depth+1)
				_ = sub.Close()
				if err != nil {
					return err
				}
			}
		}
		if errors.Is(rerr, io.EOF) || len(ents) == 0 || rerr != nil {
			return nil
		}
	}
}

func (w *finder) match(name string, fi fs.FileInfo) bool {
	if w.o.NameGlob != "" {
		if ok, _ := path.Match(w.o.NameGlob, name); !ok {
			return false
		}
	}
	if w.o.Type != "" && typeOf(fi.Mode()) != w.o.Type {
		return false
	}
	if !w.since.IsZero() && fi.ModTime().Before(w.since) {
		return false
	}
	return true
}

// ResolveRead returns the real path of an existing object under a read or
// write root (for {path:read}), under the chain rule with GuardExecPaths
// (exec_chain.go).
func (f *FS) ResolveRead(p string) (string, error) {
	l, err := f.locate(p, false)
	if err != nil {
		return "", err
	}
	defer l.close()
	file, err := f.openTarget(l)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if err := f.execChain(l, file, true); err != nil {
		return "", err
	}
	return l.targetReal(), nil
}

// ResolveReadFD resolves a {path:read:fd} (POLICY §4, handoff N-22) exactly
// as ResolveRead does (the roots, the deny list, a final symlink refused,
// the chain rule with the owner-matched exception), but keeps the
// descriptor it opened and checked and returns it with the real path; the
// caller must close it. A command given it as /dev/fd/N reopens that file,
// whatever happens to its name afterwards. Only a regular file is given: a
// directory is is_a_directory (a command treats /dev/fd/N as a symlink, and
// looks up everything below a directory by name again), anything else
// path_denied (a FIFO could block the command, and a socket cannot be
// opened). The type is checked before the open, where open(2) would fail
// on a socket or block on a device, and again on the descriptor.
func (f *FS) ResolveReadFD(p string) (*os.File, string, error) {
	l, err := f.locate(p, false)
	if err != nil {
		return nil, "", err
	}
	defer l.close()
	// A final symlink, or a name that is gone, is left to openTarget, so
	// that its refusal is ResolveRead's.
	if fi, lerr := l.lstat(); lerr == nil && fi.Mode()&fs.ModeSymlink == 0 {
		if e := regularForFD(p, fi.Mode()); e != nil {
			return nil, "", e
		}
	}
	file, err := f.openTarget(l)
	if err != nil {
		return nil, "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	fi, err := file.Stat()
	if err != nil {
		return nil, "", mapErr(err)
	}
	if e := regularForFD(p, fi.Mode()); e != nil {
		return nil, "", e
	}
	if err := f.execChain(l, file, true); err != nil {
		return nil, "", err
	}
	keep = true
	return file, l.targetReal(), nil
}

// regularForFD refuses anything but a regular file for {path:read:fd}.
func regularForFD(p string, m fs.FileMode) error {
	switch {
	case m.IsDir():
		return errf(protocol.CodeIsADirectory, "%q is a directory; {path:read:fd} takes a regular file: a command given a directory as /dev/fd/N "+
			"treats it as a symlink, and looks up everything below it by name again; nothing was run", p)
	case !m.IsRegular():
		return errf(protocol.CodePathDenied, "%q is not a regular file (a FIFO, socket or device); {path:read:fd} takes a regular file; nothing was run", p)
	}
	return nil
}

// ResolveDir returns the real path of a directory under a read or write
// root (for an exec cwd), under the chain rule with GuardExecPaths
// (exec_chain.go).
func (f *FS) ResolveDir(p string) (string, error) {
	l, err := f.locate(p, false)
	if err != nil {
		return "", err
	}
	defer l.close()
	dir, rp, owned, err := f.openDirRoot(l)
	if err != nil {
		return "", err
	}
	if owned {
		defer func() { _ = dir.Close() }()
	}
	df, err := dir.Open(".")
	if err != nil {
		return "", mapErr(err)
	}
	defer func() { _ = df.Close() }()
	if err := f.execChain(l, df, false); err != nil {
		return "", err
	}
	return rp, nil
}

// ReadRaw returns the whole content of the regular file p under a read or
// write root; a file larger than limit is too_large. It applies no
// private-key or text rule: the caller must (cert_inspect refuses private
// keys itself and returns only what it parsed, never the bytes).
func (f *FS) ReadRaw(p string, limit int) ([]byte, error) {
	if limit < 1 || limit > f.cfg.Limits.MaxReadBytes {
		return nil, errf(protocol.CodeBadRequest, "read limit must be 1..%d", f.cfg.Limits.MaxReadBytes)
	}
	l, err := f.locate(p, false)
	if err != nil {
		return nil, err
	}
	defer l.close()
	file, err := f.openTarget(l)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil {
		return nil, mapErr(err)
	}
	if fi.IsDir() {
		return nil, errf(protocol.CodeIsADirectory, "is a directory")
	}
	if !fi.Mode().IsRegular() {
		return nil, errf(protocol.CodeBadRequest, "not a regular file")
	}
	if fi.Size() > int64(limit) {
		return nil, errf(protocol.CodeTooLarge, "file exceeds %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, mapErr(err)
	}
	if len(b) > limit {
		return nil, errf(protocol.CodeTooLarge, "file exceeds %d bytes", limit)
	}
	return b, nil
}
