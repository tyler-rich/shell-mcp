//go:build linux

package ops

import (
	"archive/tar"
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/pathx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The backup store (PRIVILEGED §2, §6): a root-owned 0700 directory holding,
// per backup, "<id>.meta.json" (what was backed up, from where, with which
// owner, mode and SHA-256) and "<id>.data" (a file's bytes) or "<id>.tar"
// (a directory tree: directories and regular files with their modes and
// owners). Both are written to temporary names, fsynced and renamed data
// first, so a backup exists exactly when its metadata does. backups.keep
// versions are kept per original path; older ones are removed after each
// new backup.

// Bounds.
const (
	maxBackupBytes  = 64 << 20 // one backup's data; larger files are refused (backup_failed), not changed
	maxMetaBytes    = 64 << 10
	maxStoreEntries = 20000 // names read from the store directory
	defaultList     = 100
	maxList         = 1000
	metaSuffix      = ".meta.json"
	tmpSuffix       = ".tmp"
	metaVersion     = 1
)

var backupIDRE = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{16}$`)

// meta is one backup's metadata file.
type meta struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Mode      string `json:"mode"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Entries   int    `json:"entries"`
	Created   string `json:"created"`
	Seq       int64  `json:"seq"` // orders backups made within the same second
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
	// PreviewSHA256 is the content hash the request's precondition named
	// (expected_sha256, expected_destination_sha256): what the approver's
	// preview saw. Optional; absent in backups made before S4c-2.
	PreviewSHA256 string `json:"preview_sha256,omitempty"`
}

func (m *meta) dataName() string {
	if m.Kind == fsx.BackupTree {
		return m.ID + ".tar"
	}
	return m.ID + ".data"
}

type store struct {
	dir   string
	trust gpolicy.Trust
	keep  int
	max   int64 // backups.max_store_bytes
	now   func() time.Time
	// protect is the backup a restore is restoring: never pruned by the
	// retention of the backup the restore writes, and never counted as freed
	// by it (handoff Q12).
	protect string
}

func storeErr(format string, a ...any) *fsx.Error {
	return &fsx.Error{Code: protocol.CodeBackupFailed, Msg: fmt.Sprintf(format, a...)}
}

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

func ownerIDs(fi fs.FileInfo) (uid, gid uint32) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, st.Gid
	}
	return 0, 0
}

// open opens the store and requires it to be a directory owned by a
// trusted uid (root), not accessible to group or other, under a trusted
// parent chain.
func (st *store) open() (*os.Root, error) {
	rp, err := gpolicy.CheckChain(st.trust, st.dir)
	if err != nil {
		return nil, storeErr("the backup store is missing or insecure; nothing was changed")
	}
	root, err := os.OpenRoot(rp)
	if err != nil {
		return nil, storeErr("the backup store cannot be opened; nothing was changed")
	}
	d, err := root.Open(".")
	var fi fs.FileInfo
	if err == nil {
		fi, err = d.Stat()
		_ = d.Close()
	}
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		_ = root.Close()
		return nil, storeErr("the backup store must be a directory with mode 0700; nothing was changed")
	}
	return root, nil
}

func newID(now time.Time) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on Linux
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// countingWriter fails once more than limit bytes are written.
type countingWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

var errTooLarge = errors.New("too large")

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > c.limit {
		return 0, errTooLarge
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// save writes one backup of src, within the store's size cap. precondition
// is the content hash the request named (expected_sha256 of a write,
// expected_destination_sha256 of a copy or move): recorded in the metadata
// as preview_sha256 and, like the hash fsx computed (src.SHA256), required
// of what is backed up. Older versions of the path are pruned only once
// the operation has succeeded (pruneAfter), never here.
func (st *store) save(src *fsx.BackupSource, op, requestID, precondition, preview string) (string, error) {
	root, err := st.open()
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	unlock, err := lockStore(root)
	if err != nil {
		return "", err
	}
	defer unlock()
	now := st.now()
	uid, gid := ownerIDs(src.Info)
	m := meta{V: metaVersion, ID: newID(now), Kind: src.Kind, Path: src.Path, UID: uid, GID: gid,
		Mode: fmt.Sprintf("%04o", unixMode(src.Info)), Created: now.UTC().Format(time.RFC3339Nano),
		Seq: time.Now().UnixNano(), Op: op, RequestID: requestID, PreviewSHA256: cmp.Or(precondition, preview)}
	size, err := backupSize(src)
	if err != nil {
		return "", err
	}
	r, err := st.room(root, src.Path, size, metaBound(&m))
	switch {
	case err != nil:
		return "", err
	case !r.fits:
		return "", r.refusal()
	}
	dataTmp, metaTmp := m.dataName()+tmpSuffix, m.ID+metaSuffix+tmpSuffix
	committed := false
	defer func() {
		if !committed {
			_ = root.Remove(dataTmp)
			_ = root.Remove(metaTmp)
		}
	}()

	f, err := root.OpenFile(dataTmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", storeErr("the backup could not be created; nothing was changed")
	}
	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, h), limit: r.limit}
	switch src.Kind {
	case fsx.BackupFile:
		_, err = io.Copy(cw, src.File)
	case fsx.BackupTree:
		m.Entries, err = writeTree(cw, src)
	default:
		err = errors.New("unknown kind")
	}
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case errors.Is(err, errTooLarge) && r.limit < maxBackupBytes:
		return "", r.fullErr()
	case errors.Is(err, errTooLarge):
		return "", storeErr("what would be replaced or removed exceeds the %d MiB backup limit; nothing was changed", maxBackupBytes>>20)
	case err != nil:
		var fe *fsx.Error
		if errors.As(err, &fe) {
			return "", fe
		}
		return "", storeErr("the backup could not be written; nothing was changed")
	}
	m.Size, m.SHA256 = cw.n, hex.EncodeToString(h.Sum(nil))
	// What was backed up must be what fsx hashed, and what the request's
	// precondition named: a file rewritten in place between the hash and
	// this read (keeping its size and mtime) is refused here.
	if src.Kind == fsx.BackupFile && (src.SHA256 != "" && m.SHA256 != src.SHA256 || precondition != "" && m.SHA256 != precondition) {
		return "", storeErr("the file changed while it was being backed up; nothing was changed")
	}
	// A tree from a delete's plan holds exactly the plan's entries.
	if src.Kind == fsx.BackupTree && src.List != nil && m.Entries != src.Count {
		return "", storeErr("the tree backup does not hold exactly the entries of the preview; nothing was deleted")
	}
	mb, err := json.Marshal(m, json.Deterministic(true))
	if err == nil {
		err = writeSmall(root, metaTmp, mb)
	}
	if err == nil {
		err = root.Rename(dataTmp, m.dataName())
	}
	if err == nil {
		if err = root.Rename(metaTmp, m.ID+metaSuffix); err != nil {
			_ = root.Remove(m.dataName())
		}
	}
	if err != nil {
		return "", storeErr("the backup could not be recorded; nothing was changed")
	}
	committed = true
	if d, derr := root.Open("."); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return m.ID, nil
}

func writeSmall(root *os.Root, name string, b []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeTree writes a PAX tar of the tree's directories and regular files.
func writeTree(w io.Writer, src *fsx.BackupSource) (int, error) {
	tw := tar.NewWriter(w)
	n := 0
	err := src.Walk(func(rel string, fi fs.FileInfo, open func() (*os.File, error)) error {
		n++
		hdr, err := treeHeader(rel, fi)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return tw.WriteHeader(hdr)
		}
		f, err := open()
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if werr := tw.WriteHeader(hdr); werr != nil {
			return werr
		}
		c, err := io.Copy(tw, io.LimitReader(f, fi.Size()+1))
		if err != nil {
			return err
		}
		if c != fi.Size() {
			return storeErr("a file changed while the tree was backed up; nothing was deleted")
		}
		return nil
	})
	if err != nil {
		return n, err
	}
	return n, tw.Close()
}

// treeHeader is the archive header of one tree entry: a directory or a
// regular file, with its mode, owner and modification time.
func treeHeader(rel string, fi fs.FileInfo) (*tar.Header, error) {
	uid, gid := ownerIDs(fi)
	hdr := &tar.Header{Name: rel, Mode: int64(unixMode(fi)), Uid: int(uid), Gid: int(gid),
		ModTime: fi.ModTime(), Format: tar.FormatPAX}
	switch {
	case fi.IsDir():
		hdr.Typeflag, hdr.Name = tar.TypeDir, rel+"/"
	case fi.Mode().IsRegular():
		hdr.Typeflag, hdr.Size = tar.TypeReg, fi.Size()
	default:
		return nil, storeErr("the tree holds a symlink or special file, which cannot be backed up, so it is not deleted while backups are on")
	}
	return hdr, nil
}

// zeros is an endless reader of zero bytes (sizing an archive).
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// backupSize is the size of src's backup: a file's bytes, or, for a tree
// from a delete's plan (List), its archive's, computed by writing the same
// headers with zeros for the data, counted up to just over the per-backup
// bound. Nothing is opened. A tree without List (none is made) counts 0
// and is bounded while it is written.
func backupSize(src *fsx.BackupSource) (int64, error) {
	if src.Kind != fsx.BackupTree {
		if !src.Info.Mode().IsRegular() {
			return 0, storeErr("only regular files and directories can be backed up, so this is not deleted while backups are on")
		}
		return src.Info.Size(), nil
	}
	if src.List == nil {
		return 0, nil
	}
	cw := &countingWriter{w: io.Discard, limit: maxBackupBytes + 1}
	tw := tar.NewWriter(cw)
	err := src.List(func(rel string, fi fs.FileInfo) error {
		hdr, herr := treeHeader(rel, fi)
		if herr != nil {
			return herr
		}
		if werr := tw.WriteHeader(hdr); werr != nil {
			return werr
		}
		_, cerr := io.CopyN(tw, zeros{}, hdr.Size)
		return cerr
	})
	if err == nil {
		err = tw.Close()
	}
	switch {
	case errors.Is(err, errTooLarge):
		return maxBackupBytes + 1, nil
	case err != nil:
		var fe *fsx.Error
		if errors.As(err, &fe) {
			return 0, fe
		}
		return 0, storeErr("the tree's backup could not be sized; nothing was changed")
	}
	return cw.n, nil
}

// check answers, for a delete's preview, what its backup of src would be
// and whether it fits, counted exactly as save counts it, without writing
// anything: a backup that would not fit is refused as the delete would
// refuse it (backup_failed), so no approval is requested.
func (st *store) check(src *fsx.BackupSource, op, requestID string, now time.Time) (deleteBackup, error) {
	size, err := backupSize(src)
	if err != nil {
		return deleteBackup{}, err
	}
	root, err := st.open()
	if err != nil {
		return deleteBackup{}, err
	}
	defer func() { _ = root.Close() }()
	r, err := st.room(root, src.Path, size, metaBound(&meta{Path: src.Path, Op: op, Kind: src.Kind, ID: newID(now),
		Created: now.UTC().Format(time.RFC3339Nano), RequestID: requestID, PreviewSHA256: strings.Repeat("0", 64)}))
	switch {
	case err != nil:
		return deleteBackup{}, err
	case !r.fits:
		return deleteBackup{}, r.refusal()
	}
	return deleteBackup{Written: true, Kind: src.Kind, Bytes: size}, nil
}

// metas reads every backup's metadata (bounded), newest first.
func (st *store) metas(root *os.Root) ([]meta, bool) {
	d, err := root.Open(".")
	if err != nil {
		return nil, false
	}
	names, _ := d.Readdirnames(maxStoreEntries + 1)
	_ = d.Close()
	truncated := len(names) > maxStoreEntries
	var out []meta
	for _, n := range names[:min(len(names), maxStoreEntries)] {
		id, ok := strings.CutSuffix(n, metaSuffix)
		if !ok || !backupIDRE.MatchString(id) {
			continue
		}
		if m, err := readMeta(root, id); err == nil {
			out = append(out, *m)
		}
	}
	sortNewestFirst(out)
	return out, truncated
}

// sortNewestFirst orders metadata newest first: by creation time, then by
// sequence within the same second, then by id.
func sortNewestFirst(out []meta) {
	slices.SortFunc(out, func(a, b meta) int {
		if c := strings.Compare(b.Created, a.Created); c != 0 {
			return c
		}
		if a.Seq != b.Seq {
			if b.Seq > a.Seq {
				return 1
			}
			return -1
		}
		return strings.Compare(b.ID, a.ID)
	})
}

// readMeta reads and strictly decodes one metadata file.
func readMeta(root *os.Root, id string) (*meta, error) {
	f, err := root.OpenFile(id+metaSuffix, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxMetaBytes+1))
	if err != nil || len(b) > maxMetaBytes {
		return nil, errors.New("metadata unreadable or too large")
	}
	var m meta
	if err := json.Unmarshal(b, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if m.V != metaVersion || m.ID != id || (m.Kind != fsx.BackupFile && m.Kind != fsx.BackupTree) || pathx.CheckClean(m.Path) != nil {
		return nil, errors.New("metadata is inconsistent")
	}
	return &m, nil
}

// The store's size cap (backups.max_store_bytes, PRIVILEGED §4 and §6): the
// bytes of every file in the store together, data and metadata, stray
// files included. A backup is written only when the store as it will be
// afterwards (this backup added, and the versions of the same path that
// this backup's retention will prune once its operation succeeds taken
// away) stays within the cap; the data written is bounded by the room left.
// A store whose total cannot be counted refuses every backup.

// storeLockWait bounds the wait for another helper instance's backup.
const storeLockWait = 10 * time.Second

// usage counts the store: its total bytes and every backup's metadata,
// newest first. It fails closed: more names than it reads, an entry that
// is not a regular file, or metadata that does not decode.
func (st *store) usage(root *os.Root) (int64, []meta, error) {
	d, err := root.Open(".")
	if err != nil {
		return 0, nil, storeErr("the backup store cannot be read; nothing was changed")
	}
	names, err := d.Readdirnames(maxStoreEntries + 1)
	_ = d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, nil, storeErr("the backup store cannot be read; nothing was changed")
	}
	if len(names) > maxStoreEntries {
		return 0, nil, storeErr("the backup store holds more than %d names, so its size cannot be counted; nothing was changed; remove old backups on the host", maxStoreEntries)
	}
	var used int64
	var out []meta
	for _, n := range names {
		fi, err := root.Lstat(n)
		if err != nil || !fi.Mode().IsRegular() {
			return 0, nil, storeErr("the backup store holds an entry that is not a regular file, so its size cannot be counted; nothing was changed")
		}
		used += fi.Size()
		if id, ok := strings.CutSuffix(n, metaSuffix); ok && backupIDRE.MatchString(id) {
			m, err := readMeta(root, id)
			if err != nil {
				return 0, nil, storeErr("a backup's metadata in the store is unreadable, so the store's size cannot be counted; nothing was changed")
			}
			out = append(out, *m)
		}
	}
	sortNewestFirst(out)
	return used, out, nil
}

// backupRoom is what a backup may take.
type backupRoom struct {
	fits          bool
	limit         int64 // data bytes it may write
	used, max     int64
	size          int64
	overPerBackup bool
}

func (r *backupRoom) fullErr() error {
	return storeErr("the backup store is full (%d of %d bytes used); nothing was changed; remove old backups on the host or raise backups.max_store_bytes", r.used, r.max)
}

func (r *backupRoom) refusal() error {
	if r.overPerBackup {
		return storeErr("what would be replaced or removed exceeds the %d MiB backup limit; nothing was changed", maxBackupBytes>>20)
	}
	return r.fullErr()
}

// room is whether a backup of p, size bytes of data and at most metaLen
// of metadata, fits the store (an error only when the store cannot be
// counted).
func (st *store) room(root *os.Root, p string, size, metaLen int64) (*backupRoom, error) {
	used, metas, err := st.usage(root)
	if err != nil {
		return nil, err
	}
	// This backup's retention, once its operation succeeds, prunes the
	// versions of p beyond the newest keep-1.
	var freed int64
	n := 0
	for i := range metas {
		m := &metas[i]
		if m.Path != p {
			continue
		}
		n++
		if n >= st.keep && m.ID != st.protect {
			for _, name := range []string{m.ID + metaSuffix, m.dataName()} {
				if fi, err := root.Lstat(name); err == nil {
					freed += fi.Size()
				}
			}
		}
	}
	base := used - freed + metaLen
	r := &backupRoom{used: used, max: st.max, size: size, limit: min(int64(maxBackupBytes), st.max-base)}
	switch {
	case size > maxBackupBytes:
		r.overPerBackup = true
	case base+size <= st.max:
		r.fits = true
	}
	return r, nil
}

// metaBound bounds the metadata file of m once its size and hash are known.
func metaBound(m *meta) int64 {
	c := *m
	c.Size, c.Entries, c.SHA256 = maxBackupBytes, maxStoreEntries, strings.Repeat("0", 64)
	b, err := json.Marshal(c, json.Deterministic(true))
	if err != nil {
		return maxMetaBytes
	}
	return int64(len(b)) + 64
}

// lockStore serializes backups across helper instances (one per
// connection), so that two cannot both find room for their backup: an
// exclusive flock on the store directory, waited for up to storeLockWait.
func lockStore(root *os.Root) (func(), error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, storeErr("the backup store cannot be opened; nothing was changed")
	}
	sc, err := d.SyscallConn()
	if err != nil {
		_ = d.Close()
		return nil, storeErr("the backup store cannot be locked; nothing was changed")
	}
	flock := func(how int) error {
		var ferr error
		if cerr := sc.Control(func(fd uintptr) { ferr = unix.Flock(int(fd), how) }); cerr != nil {
			return cerr
		}
		return ferr
	}
	deadline := time.Now().Add(storeLockWait)
	for {
		err = flock(unix.LOCK_EX | unix.LOCK_NB)
		if err == nil {
			return func() { _ = flock(unix.LOCK_UN); _ = d.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			_ = d.Close()
			return nil, storeErr("the backup store is busy (another request is writing a backup) or cannot be locked; nothing was changed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pruneAfter keeps the newest backups.keep versions of each path the
// request backed up, once its operation has succeeded (handoff X-8). The
// request's own backups are never removed and count among the versions
// kept. Failures leave extra versions behind; they never fail the
// operation.
func (st *store) pruneAfter(own []string) {
	if len(own) == 0 {
		return
	}
	root, err := st.open()
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	all, _ := st.metas(root)
	mine := map[string]bool{}
	for _, id := range own {
		mine[id] = true
	}
	kept := map[string]int{}
	for i := range all {
		if mine[all[i].ID] {
			kept[all[i].Path]++
		}
	}
	for i := range all {
		m := &all[i]
		if _, ours := kept[m.Path]; !ours || mine[m.ID] {
			continue
		}
		kept[m.Path]++
		if kept[m.Path] > st.keep && m.ID != st.protect {
			_ = root.Remove(m.ID + metaSuffix)
			_ = root.Remove(m.dataName())
		}
	}
}

// backup is fsx's backup hook for this request.
func (s *server) backup(src *fsx.BackupSource) error {
	id, err := s.store.save(src, s.req.Op, s.req.ID, s.precondition, s.boundPreview)
	if err != nil {
		return err
	}
	s.backupIDs = append(s.backupIDs, id)
	return nil
}

type listBackupsArgs struct {
	Path  string `json:"path"`
	Limit int    `json:"limit"`
}

type backupEntry struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Mode    string `json:"mode"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
	Created string `json:"created"`
	Op      string `json:"op"`
}

func (s *server) listBackups(raw jsontext.Value) (data any, warns []string, failure error) {
	var a listBackupsArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if a.Path != "" && pathx.CheckClean(a.Path) != nil {
		return nil, nil, errf(protocol.CodeBadRequest, "path must be absolute and clean")
	}
	switch {
	case a.Limit == 0:
		a.Limit = defaultList
	case a.Limit < 0 || a.Limit > maxList:
		return nil, nil, errf(protocol.CodeBadRequest, "limit must be 1..%d", maxList)
	}
	out := struct {
		Backups   []backupEntry `json:"backups"`
		Truncated bool          `json:"truncated"`
	}{Backups: []backupEntry{}}
	if s.p.BackupsKeep == 0 {
		return out, []string{"backups are disabled (backups.keep is 0)"}, nil
	}
	root, err := s.store.open()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	all, truncated := s.store.metas(root)
	out.Truncated = truncated
	for i := range all {
		m := &all[i]
		if a.Path != "" && m.Path != a.Path {
			continue
		}
		if len(out.Backups) == a.Limit {
			out.Truncated = true
			break
		}
		out.Backups = append(out.Backups, backupEntry{ID: m.ID, Kind: m.Kind, Path: m.Path, UID: m.UID, GID: m.GID,
			Mode: m.Mode, Size: m.Size, SHA256: m.SHA256, Entries: m.Entries, Created: m.Created, Op: m.Op})
	}
	return out, nil, nil
}

// The restore (PRIVILEGED §6, "Restore"; handoff S4c-5: P-2c, P-3, P-10,
// D3, Q3, Q12, R-1, N-6). priv_restore_preview and priv_restore_backup
// share restorePlan: the backup's metadata and data, read and verified
// against the recorded size and SHA-256 (verify_failed on a mismatch); the
// path re-checked against the current roots; the owner it would set checked
// by the moved-in rule; the current file (a file restore) hashed under the
// read rule, with the backup of it counted against the store's cap; a tree's
// archive parsed and every entry checked; and preview_sha256 over all of it.
// The restore recomputes the plan and refuses with exists unless the hash is
// the one previewed, then writes the very bytes it verified: a file through
// the verified replace bound to the current content (or create-only when
// there was none), a tree with exclusive mkdirs and create-only files.

type restoreArgs struct {
	ID string `json:"id"`
	// ExpectedPreviewSHA256 is priv_restore_preview's preview_sha256 (P-3).
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

type restorePreviewArgs struct {
	ID string `json:"id"`
}

// restoreBackupInfo is the backup's record in a restore preview.
type restoreBackupInfo struct {
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	Mode    string `json:"mode"`
	Created string `json:"created"`
	Op      string `json:"op"`
}

// restoreCurrent is what is at the path now: absent, or a regular file.
type restoreCurrent struct {
	State  string  `json:"state"`
	Size   *int64  `json:"size,omitempty"`
	Mode   string  `json:"mode,omitempty"`
	UID    *uint32 `json:"uid,omitempty"`
	GID    *uint32 `json:"gid,omitempty"`
	Owner  string  `json:"owner,omitempty"`
	Group  string  `json:"group,omitempty"`
	SHA256 string  `json:"sha256,omitempty"`
}

// restoreEntry is one tree entry's recorded and resulting mode (P-10).
type restoreEntry struct {
	Path         string `json:"path"`
	Type         string `json:"type"`
	RecordedMode string `json:"recorded_mode"`
	Mode         string `json:"mode"`
}

// restoreSet is what a restore sets: the owner and group, and the mode
// beside the recorded one, for a file or a tree's root; for a tree, the
// first entries' modes; narrowed counts every entry whose mode the mask
// narrowed (P-10).
type restoreSet struct {
	UID          uint32         `json:"uid"`
	GID          uint32         `json:"gid"`
	Mode         string         `json:"mode"`
	RecordedMode string         `json:"recorded_mode"`
	Narrowed     int            `json:"narrowed"`
	First        []restoreEntry `json:"first"`
	Truncated    bool           `json:"truncated"`
}

// restorePreviewData is priv_restore_preview's data (handoff P-2c, P-10).
type restorePreviewData struct {
	ID            string            `json:"id"`
	Kind          string            `json:"kind"`
	Path          string            `json:"path"`
	Backup        restoreBackupInfo `json:"backup"`
	Current       restoreCurrent    `json:"current"`
	Restore       restoreSet        `json:"restore"`
	CurrentBackup deleteBackup      `json:"current_backup"`
	PolicySHA256  string            `json:"policy_sha256"`
	PreviewSHA256 string            `json:"preview_sha256"`
}

// restoreData is priv_restore_backup's data.
type restoreData struct {
	ID           string         `json:"id"`
	Path         string         `json:"path"`
	Kind         string         `json:"kind"`
	SHA256       string         `json:"sha256,omitempty"`
	Entries      int            `json:"entries,omitempty"`
	Verified     bool           `json:"verified"`
	BackupIDs    []string       `json:"backup_ids"`
	Mode         string         `json:"mode"`
	RecordedMode string         `json:"recorded_mode"`
	Narrowed     int            `json:"narrowed"`
	First        []restoreEntry `json:"first"`
	Truncated    bool           `json:"truncated"`
}

// archiveEntry is one entry of a tree backup, as parseTreeArchive read it.
type archiveEntry struct {
	name     string // relative to the tree's root, clean
	dir      bool
	mode     uint32 // the recorded mode bits
	uid, gid uint32
	data     []byte // a file's bytes
}

// parseTreeArchive reads a tree backup's archive: directories and regular
// files only, safe relative names, parents before their entries, sizes as
// recorded, at most maxEntries entries. The archive's SHA-256 was checked
// against its record first, so a failure here is a damaged backup.
func parseTreeArchive(data []byte, maxEntries int) ([]archiveEntry, error) {
	damaged := func(what string) error {
		return &fsx.Error{Code: protocol.CodeVerifyFailed, Msg: "the tree backup " + what + "; nothing was restored"}
	}
	tr := tar.NewReader(bytes.NewReader(data))
	dirs := map[string]bool{"": true}
	var out []archiveEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, damaged("is unreadable")
		}
		if len(out) == maxEntries {
			return nil, errf(protocol.CodeTooLarge, "the tree backup has more than max_delete_entries (%d) entries; nothing was restored", maxEntries)
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") ||
			strings.ContainsRune(name, 0) {
			return nil, damaged("holds an unsafe name")
		}
		parent := path.Dir(name)
		if parent == "." {
			parent = ""
		}
		if !dirs[parent] || dirs[name] {
			return nil, damaged("lists an entry before its directory, or twice")
		}
		if hdr.Uid < 0 || hdr.Gid < 0 || int64(hdr.Uid) > math.MaxUint32 || int64(hdr.Gid) > math.MaxUint32 || hdr.Mode < 0 || hdr.Mode > 0o7777 {
			return nil, damaged("holds an entry with an invalid owner or mode")
		}
		e := archiveEntry{name: name, mode: uint32(hdr.Mode), uid: uint32(hdr.Uid), gid: uint32(hdr.Gid)}
		switch hdr.Typeflag {
		case tar.TypeDir:
			e.dir = true
			dirs[name] = true
		case tar.TypeReg:
			if hdr.Size < 0 || hdr.Size > int64(len(data)) {
				return nil, damaged("holds an entry with an invalid size")
			}
			b, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(b)) != hdr.Size {
				return nil, damaged("is unreadable")
			}
			e.data = b
		default:
			return nil, damaged("holds an unexpected entry type")
		}
		out = append(out, e)
	}
}

// restorePlan is what a restore of one backup would do, as of now.
type restorePlan struct {
	m        *meta
	data     []byte
	recorded uint32      // the recorded mode bits of the file or the tree's root
	mode     os.FileMode // what it gets
	// cur is the file a file restore replaces (nil: none), curSHA its hash.
	cur       fs.FileInfo
	curSHA    string
	curBackup deleteBackup
	entries   []archiveEntry
	modes     []os.FileMode // each entry's mode, within modes.max
	narrowed  int
	hash      string
}

func modeString(m uint32) string { return fmt.Sprintf("%04o", m) }

// restorePlan reads, verifies and checks the backup id as a restore of it
// would now go. The store's retention and cap never count it as freed
// (Q12).
func (s *server) restorePlan(id string) (*restorePlan, error) {
	if !backupIDRE.MatchString(id) {
		return nil, errf(protocol.CodeBadRequest, "id is not a backup id")
	}
	if s.p.BackupsKeep == 0 {
		return nil, errf(protocol.CodeNotFound, "backups are disabled (backups.keep is 0)")
	}
	s.store.protect = id
	root, err := s.store.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	m, err := readMeta(root, id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errf(protocol.CodeNotFound, "no such backup")
	case err != nil:
		return nil, storeErr("the backup's metadata is unreadable; nothing was restored")
	}
	data, err := readData(root, m)
	if err != nil {
		return nil, err
	}
	recorded, err := strconv.ParseUint(m.Mode, 8, 32)
	if err != nil || recorded > 0o7777 {
		return nil, storeErr("the backup's mode is unreadable; nothing was restored")
	}
	pl := &restorePlan{m: m, data: data, recorded: uint32(recorded), mode: s.newInodeMode(uint32(recorded))}
	if uint32(pl.mode) != pl.recorded {
		pl.narrowed++
	}
	switch m.Kind {
	case fsx.BackupFile:
		err = s.planFileRestore(root, pl)
	default:
		err = s.planTreeRestore(pl)
	}
	if err != nil {
		return nil, err
	}
	pl.hash = restoreHash(s.p.SHA256, pl)
	return pl, nil
}

// refuseOwner is the moved-in rule's refusal of the owner a restore would
// set (handoff N-6).
func (s *server) refuseOwner(p string, d *fsx.ChainDir, uid uint32) error {
	return errf(protocol.CodePathDenied, "%q is not restored as root with its recorded owner (uid %d): the directory %s is %s, so another account "+
		"could take a file it could not have made itself; nothing was restored", p, uid, d.Path, s.fs.MovedInWhy(d, uid))
}

// planFileRestore: the recorded owner must be owner-matched on the path's
// chain; the current file (if any) is hashed under the read rule, and its
// backup must fit.
func (s *server) planFileRestore(root *os.Root, pl *restorePlan) error {
	m := pl.m
	chain, err := s.fs.WriteChain(m.Path)
	if err != nil {
		return err
	}
	if d := s.fs.MovedInBy(chain, m.UID); d != nil {
		return s.refuseOwner(m.Path, d, m.UID)
	}
	cur, sha, err := s.fs.CurrentFile(m.Path)
	if err != nil || cur == nil {
		return err
	}
	pl.cur, pl.curSHA = cur, sha
	now := s.o.Now()
	r, err := s.store.room(root, m.Path, cur.Size(), metaBound(&meta{Path: m.Path, Op: protocol.OpPrivRestoreBackup, Kind: fsx.BackupFile,
		ID: newID(now), Created: now.UTC().Format(time.RFC3339Nano), RequestID: s.req.ID, PreviewSHA256: strings.Repeat("0", 64)}))
	switch {
	case err != nil:
		return err
	case !r.fits:
		return r.refusal()
	}
	pl.curBackup = deleteBackup{Written: true, Kind: fsx.BackupFile, Bytes: cur.Size()}
	return nil
}

// planTreeRestore: nothing may be at the path; the archive holds exactly
// the recorded entries; every entry's path may be written; and the owner of
// every entry is owner-matched on its chain, which the tree's own restored
// directories extend.
func (s *server) planTreeRestore(pl *restorePlan) error {
	m := pl.m
	fi, err := s.fs.WriteTarget(m.Path)
	switch {
	case err != nil:
		return err
	case fi != nil:
		return errf(protocol.CodeExists, "a tree is restored only where nothing exists; nothing was restored")
	}
	chain, err := s.fs.WriteChain(m.Path)
	if err != nil {
		return err
	}
	if d := s.fs.MovedInBy(chain, m.UID); d != nil {
		return s.refuseOwner(m.Path, d, m.UID)
	}
	entries, err := parseTreeArchive(pl.data, s.p.Limits.MaxDeleteEntries)
	if err != nil {
		return err
	}
	if len(entries) != m.Entries {
		return &fsx.Error{Code: protocol.CodeVerifyFailed, Msg: fmt.Sprintf("the tree backup holds %d entries, but its record says %d; nothing was restored", len(entries), m.Entries)}
	}
	_, first, err := s.restoreOwners(m.Path, chain, m.UID, pl.mode, entries, true, func(e *archiveEntry) error {
		if werr := s.fs.CheckWritable(m.Path + "/" + e.name); werr != nil {
			return werr
		}
		mode := s.newInodeMode(e.mode)
		if uint32(mode) != e.mode {
			pl.narrowed++
		}
		pl.modes = append(pl.modes, mode)
		return nil
	})
	switch {
	case err != nil:
		return err
	case first != nil:
		return s.refuseOwner(first.path, &first.dir, first.uid)
	}
	pl.entries = entries
	return nil
}

// ownerRefusal is an entry a restore would refuse under the moved-in rule:
// its path, the first directory of its chain that fails, its recorded owner.
type ownerRefusal struct {
	path string
	dir  fsx.ChainDir
	uid  uint32
}

// restoreOwners applies the restore's moved-in rule (rule R for the
// recorded owners, handoff N-6, N-9) to a backup restored at p: chain is
// p's (from the root to its parent), rootUID and rootMode the file's or the
// tree root's recorded owner and the mode it gets, entries a tree's in
// archive order, whose restored directories, with their recorded owners
// and the modes they get, extend the chain. It returns how many entries
// (the file or the root included) would be refused, and the first; with
// stop it stops there. each, when set, is called for every entry first and
// its error returned at once (the restore's own checks).
func (s *server) restoreOwners(p string, chain []fsx.ChainDir, rootUID uint32, rootMode os.FileMode, entries []archiveEntry, stop bool,
	each func(e *archiveEntry) error) (int, *ownerRefusal, error) {
	n := 0
	var first *ownerRefusal
	refuse := func(target string, d *fsx.ChainDir, uid uint32) bool {
		n++
		if first == nil {
			first = &ownerRefusal{path: target, dir: *d, uid: uid}
		}
		return stop
	}
	if d := s.fs.MovedInBy(chain, rootUID); d != nil && refuse(p, d, rootUID) {
		return n, first, nil
	}
	dirs := map[string]fsx.ChainDir{"": {Path: p, UID: rootUID, Mode: uint32(rootMode)}}
	for i := range entries {
		e := &entries[i]
		if each != nil {
			if err := each(e); err != nil {
				return n, first, err
			}
		}
		target := p + "/" + e.name
		ec := append([]fsx.ChainDir(nil), chain...)
		var anc []string
		for d := path.Dir(e.name); d != "."; d = path.Dir(d) {
			anc = append(anc, d)
		}
		ec = append(ec, dirs[""])
		for j := len(anc) - 1; j >= 0; j-- {
			ec = append(ec, dirs[anc[j]])
		}
		if d := s.fs.MovedInBy(ec, e.uid); d != nil && refuse(target, d, e.uid) {
			return n, first, nil
		}
		if e.dir {
			dirs[e.name] = fsx.ChainDir{Path: target, UID: e.uid, Mode: uint32(s.newInodeMode(e.mode))}
		}
	}
	return n, first, nil
}

// unrestorable is the warning a delete's preview gives when the restore of
// the backup the delete would write (src) would be refused under the
// moved-in rule, with how many entries it concerns and the first; "" when
// the backup restores.
func (s *server) unrestorable(src *fsx.BackupSource) (string, error) {
	chain, err := s.fs.WriteChain(src.Path)
	if err != nil {
		return "", err
	}
	uid, _ := ownerIDs(src.Info)
	var entries []archiveEntry
	if src.Kind == fsx.BackupTree && src.List != nil {
		err = src.List(func(rel string, fi fs.FileInfo) error {
			eu, _ := ownerIDs(fi)
			entries = append(entries, archiveEntry{name: rel, dir: fi.IsDir(), mode: unixMode(fi), uid: eu})
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	n, first, err := s.restoreOwners(src.Path, chain, uid, s.newInodeMode(unixMode(src.Info)), entries, false, nil)
	if err != nil || first == nil {
		return "", err
	}
	what := "1 entry"
	if n != 1 {
		what = strconv.Itoa(n) + " entries"
	}
	return fmt.Sprintf("the tools won't be able to restore %s of this backup: %s would get its recorded owner (uid %d) under the directory %s, which is %s, "+
		"so another account could take a file it could not have made itself; a restore of this backup is refused", what, first.path, first.uid,
		first.dir.Path, s.fs.MovedInWhy(&first.dir, first.uid)), nil
}

// restoreDomain separates restore preview hashes from any other SHA-256
// input.
const restoreDomain = "shell-mcp restore preview v1\x00"

// restoreHash is preview_sha256: the policy's hash, the backup's record,
// what will be set, the current state at the path and whether it will be
// backed up, each length-prefixed.
func restoreHash(policySHA string, pl *restorePlan) string {
	h := sha256.New()
	_, _ = io.WriteString(h, restoreDomain)
	field := func(v string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		_, _ = h.Write(n[:])
		_, _ = io.WriteString(h, v)
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	m := pl.m
	for _, v := range []string{policySHA, m.ID, m.Kind, m.Path, strconv.FormatInt(m.Size, 10), m.SHA256, strconv.Itoa(m.Entries),
		u(uint64(m.UID)), u(uint64(m.GID)), modeString(pl.recorded), modeString(uint32(pl.mode))} {
		field(v)
	}
	if pl.cur == nil {
		field("absent")
	} else {
		mo := metaOf(pl.cur)
		for _, v := range []string{"file", strconv.FormatInt(pl.cur.Size(), 10), modeString(mo.mode), u(uint64(mo.uid)), u(uint64(mo.gid)), pl.curSHA} {
			field(v)
		}
	}
	field(strconv.FormatBool(pl.curBackup.Written))
	return hex.EncodeToString(h.Sum(nil))
}

// fileMeta is an inode's mode bits, owner and group.
type fileMeta struct{ mode, uid, gid uint32 }

func metaOf(fi fs.FileInfo) fileMeta {
	uid, gid := ownerIDs(fi)
	return fileMeta{mode: unixMode(fi), uid: uid, gid: gid}
}

// set is what the plan sets, with the first entries' modes for a tree.
func (pl *restorePlan) set() restoreSet {
	out := restoreSet{UID: pl.m.UID, GID: pl.m.GID, Mode: modeString(uint32(pl.mode)), RecordedMode: modeString(pl.recorded), Narrowed: pl.narrowed,
		First: []restoreEntry{}}
	for i, e := range pl.entries {
		if len(out.First) == previewFirst {
			out.Truncated = true
			break
		}
		typ := "file"
		if e.dir {
			typ = "dir"
		}
		out.First = append(out.First, restoreEntry{Path: pl.m.Path + "/" + e.name, Type: typ, RecordedMode: modeString(e.mode), Mode: modeString(uint32(pl.modes[i]))})
	}
	return out
}

// previewFirst bounds the entries listed in a restore's preview and result.
const previewFirst = 50

// restorePreview is priv_restore_preview (P-2c): the plan, changing
// nothing.
func (s *server) restorePreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a restorePreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	pl, err := s.restorePlan(a.ID)
	if err != nil {
		return nil, nil, err
	}
	m := pl.m
	names := s.ownerOf(m.UID, m.GID)
	out := restorePreviewData{ID: m.ID, Kind: m.Kind, Path: m.Path,
		Backup: restoreBackupInfo{Size: m.Size, SHA256: m.SHA256, Entries: m.Entries, UID: m.UID, GID: m.GID, Owner: names.Owner, Group: names.Group,
			Mode: m.Mode, Created: m.Created, Op: m.Op},
		Current: restoreCurrent{State: "absent"}, Restore: pl.set(), CurrentBackup: pl.curBackup, PolicySHA256: s.p.SHA256, PreviewSHA256: pl.hash}
	if pl.cur != nil {
		mo := metaOf(pl.cur)
		size, uid, gid := pl.cur.Size(), mo.uid, mo.gid
		cn := s.ownerOf(mo.uid, mo.gid)
		out.Current = restoreCurrent{State: "file", Size: &size, Mode: modeString(mo.mode), UID: &uid, GID: &gid, Owner: cn.Owner, Group: cn.Group, SHA256: pl.curSHA}
	}
	return out, nil, nil
}

// restoreBackup is priv_restore_backup: the plan recomputed and bound to the
// preview (P-3), then the restore.
func (s *server) restoreBackup(raw jsontext.Value) (data any, warns []string, failure error) {
	var a restoreArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if !fsx.ValidPreviewSHA256(a.ExpectedPreviewSHA256) {
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 is required: the preview_sha256 priv_restore_preview returned, 64 lowercase hex characters")
	}
	pl, err := s.restorePlan(a.ID)
	if err != nil {
		return nil, nil, err
	}
	if pl.hash != a.ExpectedPreviewSHA256 {
		return nil, nil, errf(protocol.CodeExists, "the backup, what is at its path, or the privileged policy changed since the preview; nothing was restored; preview again")
	}
	// The current version's backup records the preview it belongs to.
	s.boundPreview = a.ExpectedPreviewSHA256
	m := pl.m
	set := pl.set()
	res := restoreData{ID: m.ID, Path: m.Path, Kind: m.Kind, Mode: set.Mode, RecordedMode: set.RecordedMode, Narrowed: set.Narrowed,
		First: set.First, Truncated: set.Truncated}
	uid, gid := m.UID, m.GID
	owner := &fsx.Owner{UID: &uid, GID: &gid}
	if m.Kind == fsx.BackupFile {
		mode := pl.mode
		o := fsx.WriteOptions{Mode: &mode, Create: true, Owner: owner}
		if pl.cur != nil {
			o.ExpectedSHA256 = pl.curSHA
			s.precondition = pl.curSHA
		} else {
			o.ExpectAbsent = true
		}
		r, werr := s.restoreFS.WriteFile(m.Path, pl.data, o)
		if werr != nil {
			return nil, nil, werr
		}
		res.SHA256, res.Verified, res.BackupIDs, res.Mode = r.SHA256, r.Verified, s.ids(), r.Mode
		return res, nil, nil
	}
	n, err := s.restoreTree(pl, owner)
	if err != nil {
		return nil, nil, err
	}
	res.Entries, res.Verified, res.BackupIDs = n, true, s.ids()
	return res, nil, nil
}

// readData reads a backup's data and requires the size and SHA-256 its
// metadata records (Q3): anything else is verify_failed, and nothing is
// restored.
func readData(root *os.Root, m *meta) ([]byte, error) {
	f, err := root.OpenFile(m.dataName(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, storeErr("the backup's data is missing; nothing was restored")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBackupBytes+1))
	if err != nil {
		return nil, storeErr("the backup's data is unreadable; nothing was restored")
	}
	sum := sha256.Sum256(b)
	if int64(len(b)) != m.Size || hex.EncodeToString(sum[:]) != m.SHA256 {
		return nil, &fsx.Error{Code: protocol.CodeVerifyFailed,
			Msg: "the backup's data does not match its record (its size or SHA-256 differs: it was changed or damaged); nothing was restored"}
	}
	return b, nil
}

// restoreTree recreates a tree where nothing exists: its root and every
// directory with an exclusive mkdir, every file create-only, in archive
// order, each with its recorded owner and its mode within modes.max. A stop
// part-way says how many entries were restored.
func (s *server) restoreTree(pl *restorePlan, owner *fsx.Owner) (int, error) {
	m := pl.m
	rootMode := pl.mode
	if _, err := s.restoreFS.MkdirAs(m.Path, &rootMode, false, owner); err != nil {
		var fe *fsx.Error
		if errors.As(err, &fe) && fe.Code == protocol.CodeExists {
			return 0, errf(protocol.CodeExists, "a tree is restored only where nothing exists; nothing was restored")
		}
		return 0, err
	}
	done := 0
	for i, e := range pl.entries {
		target := m.Path + "/" + e.name
		uid, gid := e.uid, e.gid
		o := &fsx.Owner{UID: &uid, GID: &gid}
		mode := pl.modes[i]
		var err error
		if e.dir {
			_, err = s.restoreFS.MkdirAs(target, &mode, false, o)
		} else {
			_, err = s.restoreFS.WriteFile(target, e.data, fsx.WriteOptions{Mode: &mode, Create: true, ExpectAbsent: true, Owner: o})
		}
		if err != nil {
			code, msg := protocol.CodeInternal, "the restore failed"
			var fe *fsx.Error
			var oe *opError
			switch {
			case errors.As(err, &fe):
				code, msg = fe.Code, fe.Msg
			case errors.As(err, &oe):
				code, msg = oe.code, oe.msg
			}
			return done, &fsx.Error{Code: code, Msg: fmt.Sprintf("%s: %s; %d of %d entries were restored and %d were not (its directory %s was created); "+
				"preview again, or delete the partial tree, and restore again", target, msg, done, len(pl.entries), len(pl.entries)-done, m.Path)}
		}
		done++
	}
	if done != m.Entries {
		return done, &fsx.Error{Code: protocol.CodeVerifyFailed, Msg: fmt.Sprintf("%d entries were restored, but the backup's record says %d", done, m.Entries)}
	}
	return done, nil
}

// backupCheckData is priv_backup_check's answer (handoff P-11): whether an
// overwrite of the path now would write a backup, of how many bytes, and
// whether it fits the store's cap, with the store's current use and cap.
type backupCheckData struct {
	Written       bool      `json:"written"`
	Bytes         int64     `json:"bytes"`
	Fits          bool      `json:"fits"`
	StoreBytes    int64     `json:"store_bytes"`
	MaxStoreBytes int64     `json:"max_store_bytes"`
	OwnerRule     ownerRule `json:"owner_rule"`
}

// ownerRule is rule R's verdict for a path (handoff P-14): which owners a
// file there may have, from the same chain the write operations check.
// verdict is any, only (uid, and name when it is on owners.users) or none;
// dir and why name the first directory that is not closed. Only paths,
// uids and modes: the same in every helper instance.
type ownerRule struct {
	Verdict string  `json:"verdict"`
	UID     *uint32 `json:"uid,omitempty"`
	Name    string  `json:"name,omitempty"`
	Dir     string  `json:"dir,omitempty"`
	Why     string  `json:"why,omitempty"`
}

// ownerRuleOf is p's verdict (p's parent must exist).
func (s *server) ownerRuleOf(p string) (ownerRule, error) {
	chain, err := s.fs.WriteChain(p)
	if err != nil {
		return ownerRule{}, err
	}
	v := s.fs.OwnerVerdictOf(chain)
	r := ownerRule{Verdict: "none"}
	switch {
	case v.Any:
		return ownerRule{Verdict: "any"}, nil
	case v.UID != nil:
		r.Verdict, r.UID = "only", v.UID
		r.Name = s.ownerOf(*v.UID, 0).Owner
	}
	// Why it is not closed: its owner (never root's, which is trusted) or
	// its group or world write bits.
	r.Dir, r.Why = v.Dir.Path, s.fs.MovedInWhy(v.Dir, 0)
	return r, nil
}

// backupCheck answers priv_backup_check: the path must be one the write ops
// may change (under a write root, not denied or protected); a regular file
// there would be backed up when backups are on, and the store is counted
// as the backup itself would count it (room). It changes nothing.
func (s *server) backupCheck(raw jsontext.Value) (data any, warns []string, failure error) {
	var a pathArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	out := backupCheckData{Fits: true, MaxStoreBytes: s.p.BackupsMaxStoreBytes}
	fi, err := s.fs.WriteTarget(a.Path)
	if err != nil {
		return nil, nil, err
	}
	if out.OwnerRule, err = s.ownerRuleOf(a.Path); err != nil {
		return nil, nil, err
	}
	if fi == nil || !fi.Mode().IsRegular() || s.p.BackupsKeep == 0 {
		return out, nil, nil
	}
	root, err := s.store.open()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	r, err := s.store.room(root, a.Path, fi.Size(), metaBound(&meta{Path: a.Path, Op: protocol.OpPrivWriteFile, Kind: fsx.BackupFile,
		ID: newID(s.o.Now()), Created: s.o.Now().UTC().Format(time.RFC3339Nano), RequestID: s.req.ID, PreviewSHA256: strings.Repeat("0", 64)}))
	if err != nil {
		return nil, nil, err
	}
	out.Written, out.Bytes, out.Fits, out.StoreBytes = true, fi.Size(), r.fits, r.used
	return out, nil, nil
}

// StoreUsage is the backup store's total size as a backup counts it
// (check-policy reports it beside backups.max_store_bytes).
func StoreUsage(dir string, trust gpolicy.Trust) (int64, error) {
	st := &store{dir: dir, trust: trust}
	root, err := st.open()
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	n, _, err := st.usage(root)
	return n, err
}

// discard removes backups the request wrote when its operation failed
// before committing anything: metadata first, so a backup exists exactly
// while its metadata does. Under the store lock, like a backup.
func (st *store) discard(ids []string) {
	if len(ids) == 0 {
		return
	}
	root, err := st.open()
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	unlock, err := lockStore(root)
	if err != nil {
		return
	}
	defer unlock()
	for _, id := range ids {
		m, err := readMeta(root, id)
		if err != nil {
			continue
		}
		_ = root.Remove(id + metaSuffix)
		_ = root.Remove(m.dataName())
	}
}
