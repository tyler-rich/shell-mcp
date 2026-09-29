//go:build linux

package ops

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	gpolicy "github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
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

var backupIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$`)

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
	now   func() time.Time
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

func ownerIDs(fi fs.FileInfo) (uint32, uint32) {
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

// save writes one backup of src and prunes older versions of its path.
func (st *store) save(src *fsx.BackupSource, op, requestID string) (string, error) {
	root, err := st.open()
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	now := st.now()
	uid, gid := ownerIDs(src.Info)
	m := meta{V: metaVersion, ID: newID(now), Kind: src.Kind, Path: src.Path, UID: uid, GID: gid,
		Mode: fmt.Sprintf("%04o", unixMode(src.Info)), Created: now.UTC().Format(time.RFC3339Nano),
		Seq: time.Now().UnixNano(), Op: op, RequestID: requestID}
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
	cw := &countingWriter{w: io.MultiWriter(f, h), limit: maxBackupBytes}
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
	st.prune(root, src.Path)
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
		uid, gid := ownerIDs(fi)
		hdr := &tar.Header{Name: rel, Mode: int64(unixMode(fi)), Uid: int(uid), Gid: int(gid),
			ModTime: fi.ModTime(), Format: tar.FormatPAX}
		if fi.IsDir() {
			hdr.Typeflag, hdr.Name = tar.TypeDir, rel+"/"
			return tw.WriteHeader(hdr)
		}
		hdr.Typeflag, hdr.Size = tar.TypeReg, fi.Size()
		f, err := open()
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if err := tw.WriteHeader(hdr); err != nil {
			return err
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
	return out, truncated
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

// prune keeps the newest backups.keep versions of p. Failures leave extra
// versions behind; they never fail the operation that made the backup.
func (st *store) prune(root *os.Root, p string) {
	all, _ := st.metas(root)
	kept := 0
	for _, m := range all {
		if m.Path != p {
			continue
		}
		kept++
		if kept > st.keep {
			_ = root.Remove(m.ID + metaSuffix)
			_ = root.Remove(m.dataName())
		}
	}
}

// backup is fsx's backup hook for this request.
func (s *server) backup(src *fsx.BackupSource) error {
	id, err := s.store.save(src, s.req.Op, s.req.ID)
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
	for _, m := range all {
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

type restoreArgs struct {
	ID string `json:"id"`
}

type restoreData struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Kind      string   `json:"kind"`
	SHA256    string   `json:"sha256,omitempty"`
	Entries   int      `json:"entries,omitempty"`
	Verified  bool     `json:"verified"`
	BackupIDs []string `json:"backup_ids"`
}

func (s *server) restoreBackup(raw jsontext.Value) (data any, warns []string, failure error) {
	var a restoreArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if !backupIDRE.MatchString(a.ID) {
		return nil, nil, errf(protocol.CodeBadRequest, "id is not a backup id")
	}
	if s.p.BackupsKeep == 0 {
		return nil, nil, errf(protocol.CodeNotFound, "backups are disabled (backups.keep is 0)")
	}
	root, err := s.store.open()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	m, err := readMeta(root, a.ID)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, errf(protocol.CodeNotFound, "no such backup")
	case err != nil:
		return nil, nil, storeErr("the backup's metadata is unreadable; nothing was restored")
	}
	content, err := readData(root, m)
	if err != nil {
		return nil, nil, err
	}
	mode, err := strconv.ParseUint(m.Mode, 8, 32)
	if err != nil {
		return nil, nil, storeErr("the backup's mode is unreadable; nothing was restored")
	}
	fm := os.FileMode(mode)
	uid, gid := m.UID, m.GID
	owner := &fsx.Owner{UID: &uid, GID: &gid}
	res := restoreData{ID: m.ID, Path: m.Path, Kind: m.Kind}
	if m.Kind == fsx.BackupFile {
		r, err := s.restoreFS.WriteFile(m.Path, content, fsx.WriteOptions{Mode: &fm, Create: true, Owner: owner})
		if err != nil {
			return nil, nil, err
		}
		res.SHA256, res.Verified, res.BackupIDs = r.SHA256, r.Verified, s.ids()
		return res, nil, nil
	}
	n, err := s.restoreTree(m, content, fm, owner)
	if err != nil {
		return nil, nil, err
	}
	res.Entries, res.Verified, res.BackupIDs = n, true, s.ids()
	return res, nil, nil
}

// readData reads a backup's data and requires its recorded SHA-256.
func readData(root *os.Root, m *meta) ([]byte, error) {
	f, err := root.OpenFile(m.dataName(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, storeErr("the backup's data is missing; nothing was restored")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBackupBytes+1))
	if err != nil || len(b) > maxBackupBytes {
		return nil, storeErr("the backup's data is unreadable; nothing was restored")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return nil, storeErr("the backup's data does not match its recorded SHA-256; nothing was restored")
	}
	return b, nil
}

// restoreTree recreates a deleted tree where nothing exists now: the root
// directory, then every entry in archive order (parents first), each with
// its recorded mode and owner, through the confined, verified operations.
func (s *server) restoreTree(m *meta, data []byte, rootMode os.FileMode, owner *fsx.Owner) (int, error) {
	_, err := s.fs.Stat(m.Path)
	var fe *fsx.Error
	switch {
	case err == nil:
		return 0, errf(protocol.CodeExists, "a tree is restored only where nothing exists")
	case !errors.As(err, &fe) || fe.Code != protocol.CodeNotFound:
		return 0, err
	}
	if _, err := s.restoreFS.MkdirAs(m.Path, &rootMode, false, owner); err != nil {
		return 0, err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	n := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, storeErr("the tree backup is unreadable; the restore stopped")
		}
		n++
		if n > s.p.Limits.MaxDeleteEntries {
			return n, errf(protocol.CodeTooLarge, "the tree backup has more than max_delete_entries entries; the restore stopped")
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return n, storeErr("the tree backup holds an unsafe name; the restore stopped")
		}
		target := m.Path + "/" + name
		mode := os.FileMode(uint32(hdr.Mode) & 0o7777) //nolint:gosec // G115: a tar mode written by this helper
		uid, gid := uint32(hdr.Uid), uint32(hdr.Gid) //nolint:gosec // G115: ids written by this helper
		o := &fsx.Owner{UID: &uid, GID: &gid}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if _, err := s.restoreFS.MkdirAs(target, &mode, false, o); err != nil {
				return n, err
			}
		case tar.TypeReg:
			b, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(b)) != hdr.Size {
				return n, storeErr("the tree backup is unreadable; the restore stopped")
			}
			if _, err := s.restoreFS.WriteFile(target, b, fsx.WriteOptions{Mode: &mode, Create: true, Owner: o}); err != nil {
				return n, err
			}
		default:
			return n, storeErr("the tree backup holds an unexpected entry type; the restore stopped")
		}
	}
}
